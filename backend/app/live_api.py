"""Authenticated live telemetry API, deliberately independent of the demo app."""
from __future__ import annotations

import hashlib
import hmac
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials, HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, StrictInt, ValidationError, field_validator
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import Headers, MutableHeaders

from .telemetry.config import LiveConfig, load_config
from .telemetry.dashboard import DASHBOARD_HTML, CONTENT_SECURITY_POLICY
from .telemetry.operator_auth import OperatorVerifier

MAX_BODY_BYTES = 1024 * 1024
_basic = HTTPBasic(auto_error=False)
_bearer = HTTPBearer(auto_error=False)


class RequestBoundaryMiddleware:
    """Cap streamed bodies before JSON parsing, including requests without Content-Length."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def secure_send(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["X-Content-Type-Options"] = "nosniff"
                headers["X-Frame-Options"] = "DENY"
                headers["Referrer-Policy"] = "no-referrer"
                headers["Cache-Control"] = "no-store"
                headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
                headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
            await send(message)

        declared = Headers(scope=scope).get("content-length")
        if declared is not None:
            try:
                size = int(declared)
                if size < 0:
                    raise ValueError
            except ValueError:
                return await JSONResponse({"detail": "Invalid content length"}, 400)(scope, receive, secure_send)
            if size > MAX_BODY_BYTES:
                return await JSONResponse({"detail": "Request body too large"}, 413)(scope, receive, secure_send)

        if scope["method"] in {"POST", "PUT", "PATCH"}:
            chunks = bytearray()
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                chunks.extend(message.get("body", b""))
                if len(chunks) > MAX_BODY_BYTES:
                    return await JSONResponse({"detail": "Request body too large"}, 413)(scope, receive, secure_send)
                if not message.get("more_body", False):
                    break
            consumed = False

            async def bounded_receive():
                nonlocal consumed
                if not consumed:
                    consumed = True
                    return {"type": "http.request", "body": bytes(chunks), "more_body": False}
                return await receive()

            return await self.app(scope, bounded_receive, secure_send)
        return await self.app(scope, receive, secure_send)


def _valid_time(value: str) -> str:
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if moment.tzinfo is None or moment.utcoffset() is None:
            raise ValueError
        moment = moment.astimezone(timezone.utc)
        if moment > datetime.now(timezone.utc) + timedelta(minutes=5):
            raise ValueError
        return moment.isoformat().replace("+00:00", "Z")
    except (ValueError, OverflowError) as exc:
        raise ValueError("Timestamp must be a timezone-aware ISO timestamp, no more than 5 minutes ahead") from exc


class TelemetryRecord(BaseModel):
    model_config = {"extra": "forbid"}
    event_id: str = Field(min_length=1, max_length=512)
    timestamp: str = Field(min_length=1, max_length=64)
    message: str = Field(max_length=16384)
    unit: str | None = Field(default=None, max_length=256)
    priority: StrictInt | Annotated[str, Field(max_length=16)] | None = None
    identifier: str | None = Field(default=None, max_length=256)

    _timestamp = field_validator("timestamp")(_valid_time)


class CollectorReport(BaseModel):
    model_config = {"extra": "forbid"}
    code: str = Field(min_length=1, max_length=64)
    message: str = Field(min_length=1, max_length=1024)


class IPCheckRequest(BaseModel):
    model_config = {"extra": "forbid"}
    ip: str = Field(min_length=1, max_length=128)


class TelemetryBatch(BaseModel):
    model_config = {"extra": "forbid"}
    source_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
    batch_id: str = Field(min_length=1, max_length=128)
    hostname: str | None = Field(default=None, min_length=1, max_length=253)
    collected_at: str | None = Field(default=None, max_length=64)
    records: list[TelemetryRecord] = Field(max_length=500)
    reports: list[CollectorReport] = Field(default_factory=list, max_length=5)
    error: str | None = Field(default=None, max_length=2048)

    @field_validator("collected_at")
    @classmethod
    def collected_time(cls, value):
        return _valid_time(value) if value is not None else None


def create_app(config: LiveConfig | None = None, store: Any | None = None,
               control: Any | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(application: FastAPI):
        from .telemetry.store import TelemetryStore

        application.state.config = config or load_config()
        application.state.operator_verifier = OperatorVerifier()
        from .telemetry.geoip import GeoIPLookup
        application.state.geoip = GeoIPLookup(os.environ.get("RISKOPS_GEOIP_DIRECTORY"))
        from .telemetry.abuseipdb import AbuseIPDBClient
        application.state.abuseipdb = AbuseIPDBClient(os.environ.get("RISKOPS_ABUSEIPDB_KEY_FILE"))
        application.state.store = store or TelemetryStore(
            application.state.config.database_path,
            retention_days=application.state.config.retention_days,
        )
        if not await run_in_threadpool(application.state.store.healthcheck):
            raise RuntimeError("Live telemetry database is unavailable")
        from .telemetry.control import ControlService
        application.state.control = control or ControlService.from_environment(application.state.config.sources)
        if control is None:
            application.state.control.start()
        try:
            yield
        finally:
            if control is None:
                await run_in_threadpool(application.state.control.close)
            if store is None and hasattr(application.state.store, "close"):
                await run_in_threadpool(application.state.store.close)

    application = FastAPI(title="SecAgent RiskOps live telemetry", lifespan=lifespan,
                          docs_url=None, redoc_url=None, openapi_url=None)
    application.add_middleware(RequestBoundaryMiddleware)

    def operator(request: Request, credentials: HTTPBasicCredentials | None = Depends(_basic)) -> None:
        cfg = request.app.state.config
        if credentials is None or len(credentials.password) > 1024:
            raise HTTPException(401, "Authentication required", headers={"WWW-Authenticate": 'Basic realm="RiskOps"'})
        if not request.app.state.operator_verifier.verify(credentials.username, credentials.password,
                                                         cfg.operator_username, cfg.operator_password_pbkdf2):
            raise HTTPException(401, "Authentication required", headers={"WWW-Authenticate": 'Basic realm="RiskOps"'})

    @application.get("/health")
    def health(request: Request):
        try:
            ready = request.app.state.store.healthcheck()
        except Exception:
            ready = False
        return JSONResponse({"status": "ok" if ready else "unavailable"}, status_code=200 if ready else 503)

    @application.get("/", response_class=HTMLResponse, dependencies=[Depends(operator)])
    def dashboard():
        return HTMLResponse(DASHBOARD_HTML)

    @application.get("/api/summary", dependencies=[Depends(operator)])
    def summary(request: Request):
        cfg = request.app.state.config
        reported = {item["source_id"]: item for item in request.app.state.store.list_sources(limit=200, offset=0)}
        now = datetime.now(timezone.utc)
        sources = []
        totals = {"events": 0, "incidents": 0, "ssh_failures": 0, "ssh_successes": 0}
        for source in cfg.sources:
            row = dict(reported.get(source.id, {}))
            row.update({"source_id": source.id, "hostname": source.hostname})
            last_seen = row.get("last_seen")
            connection_status = "never_seen"
            if last_seen:
                age = (now - datetime.fromisoformat(last_seen.replace("Z", "+00:00"))).total_seconds()
                connection_status = "offline" if age > cfg.heartbeat_timeout_seconds else ("error" if row.get("last_error") else "online")
            row["connection_status"] = connection_status
            sources.append(row)
            for total, counter in (("events", "event_count"), ("incidents", "incident_count"),
                                   ("ssh_failures", "ssh_failure_count"), ("ssh_successes", "ssh_success_count")):
                totals[total] += int(row.get(counter, 0))
        # A correlated incident appears under every participating source but is
        # counted once in the global total.
        totals["incidents"] = request.app.state.store.count_incidents()
        return {"generated_at": now.isoformat(), "retention_days": cfg.retention_days,
                "heartbeat_timeout_seconds": cfg.heartbeat_timeout_seconds, "sources": sources, "totals": totals}

    def source_filter(request: Request, source_id: str | None) -> str | None:
        if source_id is not None and source_id not in {source.id for source in request.app.state.config.sources}:
            raise HTTPException(404, "Source not found")
        return source_id

    def search_filters(ip: str | None = Query(None, max_length=64),
                       username: str | None = Query(None, min_length=1, max_length=256),
                       event_type: str | None = Query(None, min_length=1, max_length=64),
                       q: str | None = Query(None, min_length=1, max_length=256),
                       start: str | None = Query(None, max_length=64),
                       end: str | None = Query(None, max_length=64),
                       snapshot: str | None = Query(None, max_length=128)):
        filters = {"ip": ip, "username": username, "event_type": event_type, "q": q,
                   "start": start, "end": end, "snapshot": snapshot}
        from .telemetry.store import TelemetryStore
        try:
            TelemetryStore._event_filter(**filters)
        except (ValueError, OverflowError, TypeError):
            raise HTTPException(422, "查询参数无效，请检查 IP、时间范围和查询快照") from None
        return filters

    @application.get("/api/events", dependencies=[Depends(operator)])
    def events(request: Request, source_id: str | None = Query(None, max_length=64),
               limit: int = Query(100, ge=1, le=200), offset: int = Query(0, ge=0),
               page: int | None = Query(None, ge=1, le=1_000_000_000),
               filters: dict = Depends(search_filters)):
        if page is not None:
            return request.app.state.store.paginate_events(source_id=source_filter(request, source_id), limit=limit, page=page, **filters)
        return request.app.state.store.list_events(source_id=source_filter(request, source_id), limit=limit, offset=offset, **filters)

    @application.get("/api/incidents", dependencies=[Depends(operator)])
    def incidents(request: Request, source_id: str | None = Query(None, max_length=64),
                  limit: int = Query(100, ge=1, le=200), offset: int = Query(0, ge=0),
                  page: int | None = Query(None, ge=1, le=1_000_000_000),
                  include_evidence: bool = Query(True)):
        if page is not None:
            return request.app.state.store.paginate_incidents(source_id=source_filter(request, source_id), limit=limit, page=page, include_evidence=include_evidence)
        return request.app.state.store.list_incidents(source_id=source_filter(request, source_id), limit=limit, offset=offset)

    @application.get("/api/dashboard", dependencies=[Depends(operator)])
    def dashboard_snapshot(request: Request, source_id: str | None = Query(None, max_length=64),
                           event_page: int = Query(1, ge=1, le=1_000_000_000),
                           incident_page: int = Query(1, ge=1, le=1_000_000_000),
                           limit: int = Query(50, ge=1, le=200),
                           filters: dict = Depends(search_filters)):
        # One authenticated HTTP request avoids three expensive password checks
        # when the operator returns after the short verification cache expires.
        selected = source_filter(request, source_id)
        store = request.app.state.store
        return {"summary": summary(request),
                "events": store.paginate_events(source_id=selected, limit=limit, page=event_page, **filters),
                "incidents": store.paginate_incidents(source_id=selected, limit=limit, page=incident_page, include_evidence=False)}

    @application.get("/api/incidents/{incident_id}", dependencies=[Depends(operator)])
    def incident_detail(request: Request, incident_id: str):
        result = request.app.state.store.get_incident(incident_id)
        if result is None:
            raise HTTPException(404, "事件不存在")
        return result

    @application.get("/api/incidents/{incident_id}/evidence", dependencies=[Depends(operator)])
    def incident_evidence(request: Request, incident_id: str,
                          page: int = Query(1, ge=1, le=1_000_000_000),
                          limit: int = Query(50, ge=1, le=200),
                          source_id: str | None = Query(None, max_length=64)):
        result = request.app.state.store.paginate_incident_evidence(
            incident_id, limit=limit, page=page, source_id=source_filter(request, source_id))
        if result is None:
            raise HTTPException(404, "事件不存在")
        return result

    def control_write(request: Request, _: None = Depends(operator)):
        # Basic credentials alone are ambient browser credentials. Requiring a
        # secret custom header prevents CSRF; no cross-origin CORS is enabled.
        supplied = request.headers.get("x-riskops-csrf", "")
        if not hmac.compare_digest(supplied.encode("utf-8"), request.app.state.control.csrf_token.encode("ascii")):
            raise HTTPException(403, "操作校验已过期，请刷新控制区域")
        origin = request.headers.get("origin")
        if request.headers.get("sec-fetch-site") == "cross-site" or (origin and origin != str(request.base_url).rstrip("/")):
            raise HTTPException(403, "不允许跨站操作")
        if request.headers.get("content-type", "").split(";", 1)[0].strip() != "application/json":
            raise HTTPException(415, "Expected application/json")
        if not request.app.state.control.enabled:
            raise HTTPException(503, "手动控制尚未配置")

    @application.get("/api/controls", dependencies=[Depends(operator)])
    def controls(request: Request):
        return request.app.state.control.capabilities()

    @application.post("/api/controls/preview", dependencies=[Depends(control_write)])
    async def preview_control(request: Request):
        try:
            body = await request.json()
            return await run_in_threadpool(request.app.state.control.preview,
                request.app.state.config.operator_username, body,
                operator_ip=request.client.host if request.client else None)
        except (ValueError, TypeError, KeyError) as exc:
            raise HTTPException(422, str(exc) if isinstance(exc, ValueError) else "操作请求无效") from None

    @application.post("/api/controls/execute", dependencies=[Depends(control_write)])
    async def execute_control(request: Request):
        try:
            body = await request.json()
            if not isinstance(body, dict) or set(body) != {"plan_id"} or not isinstance(body["plan_id"], str) or len(body["plan_id"]) > 64:
                raise ValueError("操作请求无效")
            result = await run_in_threadpool(request.app.state.control.execute,
                                            request.app.state.config.operator_username, body["plan_id"])
            return JSONResponse(result, status_code=202)
        except (ValueError, TypeError):
            raise HTTPException(422, "预览无效或已过期，请重新预览") from None

    @application.get("/api/controls/jobs/{job_id}", dependencies=[Depends(operator)])
    def control_job(request: Request, job_id: str):
        if not request.app.state.control.enabled:
            raise HTTPException(503, "手动控制尚未配置")
        result = request.app.state.control.job(job_id)
        if result is None:
            raise HTTPException(404, "操作记录不存在")
        return result

    @application.get("/api/ip-info", dependencies=[Depends(operator)])
    def ip_info(request: Request, ip: str = Query(min_length=1, max_length=128)):
        try:
            result = request.app.state.geoip.lookup(ip)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        return JSONResponse(result, status_code=503 if result["status"] == "unavailable" else 200)

    @application.post("/api/abuseipdb/check", dependencies=[Depends(operator)])
    def abuseipdb_check(request: Request, body: IPCheckRequest):
        # This explicit action may send only the selected IP to AbuseIPDB CHECK.
        # The page never calls it while loading, refreshing, or looking up location.
        try:
            result = request.app.state.abuseipdb.lookup(body.ip)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        status = {"not_configured":503, "rate_limited":429, "unavailable":502}.get(result["status"],200)
        return JSONResponse(result, status_code=status)

    @application.post("/api/telemetry/batches")
    async def ingest(request: Request, credentials: HTTPAuthorizationCredentials | None = Depends(_bearer)):
        if credentials is None or not 24 <= len(credentials.credentials) <= 512:
            raise HTTPException(401, "Invalid source credentials", headers={"WWW-Authenticate": "Bearer"})
        # Resolve the source from its token before parsing any attacker-controlled source id.
        token_hash = hashlib.sha256(credentials.credentials.encode("utf-8")).hexdigest()
        source = None
        for candidate in request.app.state.config.sources:
            if hmac.compare_digest(token_hash, candidate.token_sha256):
                source = candidate
        if source is None:
            raise HTTPException(401, "Invalid source credentials", headers={"WWW-Authenticate": "Bearer"})
        if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
            raise HTTPException(415, "Expected application/json")
        try:
            batch = TelemetryBatch.model_validate_json(await request.body())
        except ValidationError:
            raise HTTPException(422, "Invalid telemetry batch") from None
        if batch.source_id != source.id or (batch.hostname is not None and batch.hostname != source.hostname):
            raise HTTPException(403, "Source identity does not match credentials")
        errors = ([batch.error] if batch.error else []) + [f"{report.code}: {report.message}" for report in batch.reports]
        error = "\n".join(errors)[:2048] or None
        try:
            result = await run_in_threadpool(request.app.state.store.ingest, source.id, source.hostname,
                                            batch.batch_id, [record.model_dump() for record in batch.records], error=error)
        except ValueError:
            raise HTTPException(422, "Invalid telemetry batch") from None
        except Exception:
            # Never acknowledge a batch whose transaction did not commit.
            raise HTTPException(503, "Telemetry storage unavailable; retry this batch") from None
        return {**result, "batch_id": batch.batch_id, "durable": True}

    return application


app = create_app()
