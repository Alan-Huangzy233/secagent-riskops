"""Authenticated HTTP-only ingestion and bounded inspection endpoints."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac

from fastapi import Depends, HTTPException, Query, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool

from .http_store import HttpBatch


def register_routes(application, operator):
    bearer = HTTPBearer(auto_error=False)

    def enabled(request):
        config = request.app.state.config.http_ingest
        if config is None:
            raise HTTPException(404, "HTTP ingestion is not configured")
        return config

    def stream(request, source_id, service_id):
        config = enabled(request)
        if not any(s.id == source_id and service_id in s.services for s in config.sources):
            raise HTTPException(404, "HTTP stream is not configured")

    @application.post("/api/http/batches")
    async def ingest(request: Request, credentials: HTTPAuthorizationCredentials | None = Depends(bearer)):
        config = enabled(request)
        if credentials is None or not 24 <= len(credentials.credentials) <= 512:
            raise HTTPException(401, "Invalid HTTP source credentials", headers={"WWW-Authenticate": "Bearer"})
        digest = hashlib.sha256(credentials.credentials.encode()).hexdigest()
        source = None
        for candidate in config.sources:
            if hmac.compare_digest(digest, candidate.token_sha256):
                source = candidate
        if source is None:
            raise HTTPException(401, "Invalid HTTP source credentials", headers={"WWW-Authenticate": "Bearer"})
        if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
            raise HTTPException(415, "Expected application/json")
        try:
            batch = HttpBatch.model_validate_json(await request.body())
        except ValidationError:
            raise HTTPException(422, "Invalid HTTP batch") from None
        if batch.source_id != source.id or batch.service_id not in source.services:
            raise HTTPException(403, "HTTP stream does not match credentials")
        try:
            return await run_in_threadpool(request.app.state.http_store.ingest, batch)
        except ValueError:
            raise HTTPException(422, "Invalid or conflicting HTTP batch") from None
        except Exception:
            raise HTTPException(503, "HTTP storage unavailable; retry this batch") from None

    @application.get("/api/http/streams", dependencies=[Depends(operator)])
    def streams(request: Request):
        config = enabled(request)
        stored = {(r["source_id"], r["service_id"]): r for r in request.app.state.http_store.streams()}
        items = []
        for source in config.sources:
            for service in source.services:
                row = stored.get((source.id, service))
                item = {"source_id": source.id, "service_id": service, "hostname": source.hostname,
                        "status": "never_seen", "accepted_total": 0, "rejected_total": 0}
                if row:
                    age = (datetime.now(timezone.utc) - datetime.fromisoformat(row["received_at"].replace("Z", "+00:00"))).total_seconds()
                    last = row["last_batch"]
                    lag = (datetime.now(timezone.utc) - datetime.fromisoformat(last["collected_at"].replace("Z", "+00:00"))).total_seconds()
                    item.update({k: v for k, v in row.items() if k != "last_batch_json"})
                    item["status"] = ("stale" if age > request.app.state.config.heartbeat_timeout_seconds
                                      else "delayed" if lag > request.app.state.config.heartbeat_timeout_seconds
                                      else "degraded" if last["reports"] or not last["caught_up"] or last["rejected"]
                                      else "current")
                items.append(item)
        return {"items": items, "retention_days": config.retention_days}

    @application.get("/api/http/events", dependencies=[Depends(operator)])
    @application.get("/api/http/batches", dependencies=[Depends(operator)])
    def page(request: Request, source_id: str = Query(max_length=64), service_id: str = Query(max_length=64),
             after: int = Query(0, ge=0, le=2**63-1), limit: int = Query(100, ge=1, le=200),
             snapshot: int | None = Query(None, ge=0, le=2**63-1)):
        stream(request, source_id, service_id)
        return request.app.state.http_store.page(source_id, service_id, after=after, limit=limit,
                                                 snapshot=snapshot, batches=request.url.path.endswith("/batches"))

    @application.get("/api/http/status", dependencies=[Depends(operator)])
    def analysis_status(request: Request):
        config = request.app.state.config.http_ingest
        if config is None:
            return {"enabled": False}
        return {"enabled": True, **request.app.state.http_store.analysis_status(),
                "sources": [{"id": s.id, "hostname": s.hostname, "services": s.services} for s in config.sources],
                "collection": [{k: row[k] for k in ("source_id", "service_id", "status", "accepted_total", "rejected_total")}
                               for row in streams(request)["items"]]}

    @application.get("/api/http/incidents", dependencies=[Depends(operator)])
    def incidents(request: Request, source_id: str | None = Query(None, max_length=64),
                  service_id: str | None = Query(None, max_length=64),
                  focus: str = Query("all", pattern="^(all|attention|low|retracted)$"),
                  page: int = Query(1, ge=1, le=1000000), limit: int = Query(50, ge=1, le=200)):
        config = enabled(request)
        if source_id and source_id not in {s.id for s in config.sources}:
            raise HTTPException(404, "HTTP source is not configured")
        if service_id and not any(service_id in s.services and (source_id is None or source_id == s.id) for s in config.sources):
            raise HTTPException(404, "HTTP service is not configured")
        return request.app.state.http_store.incidents(source_id=source_id, service_id=service_id,
                                                      focus=focus, page=page, limit=limit)

    @application.get("/api/http/incidents/{identity}", dependencies=[Depends(operator)])
    def incident(request: Request, identity: str, revision: int | None = Query(None, ge=1, le=2**63-1)):
        enabled(request)
        result = request.app.state.http_store.incident(identity, revision)
        if result is None:
            raise HTTPException(404, "HTTP incident revision does not exist")
        return result

    @application.get("/api/http/incidents/{identity}/evidence", dependencies=[Depends(operator)])
    def evidence(request: Request, identity: str, revision: int | None = Query(None, ge=1, le=2**63-1),
                 page: int = Query(1, ge=1, le=1000000), limit: int = Query(50, ge=1, le=200)):
        enabled(request)
        result = request.app.state.http_store.evidence(identity, revision=revision, page=page, limit=limit)
        if result is None:
            raise HTTPException(404, "HTTP incident revision does not exist")
        return result
