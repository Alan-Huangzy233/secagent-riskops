"""Opt-in authenticated network ingestion and operator-only inspection."""
import hashlib
import hmac
import time

from fastapi import Depends, HTTPException, Query, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.concurrency import run_in_threadpool

from .network_protocol import MAX_BATCH_BYTES, decode, validate_batch
from .network_store import NetworkStoreError


def register_routes(application, operator):
    bearer = HTTPBearer(auto_error=False)

    def enabled(request):
        config = request.app.state.config.network_ingest
        if config is None:
            raise HTTPException(404, "Network ingestion is not configured")
        return config

    @application.post("/api/network/batches")
    async def ingest(request: Request, credentials: HTTPAuthorizationCredentials | None = Depends(bearer)):
        config = enabled(request)
        if credentials is None or not 24 <= len(credentials.credentials) <= 512:
            raise HTTPException(401, "Invalid network source credentials", headers={"WWW-Authenticate": "Bearer"})
        digest = hashlib.sha256(credentials.credentials.encode()).hexdigest()
        source = None
        for candidate in config.sources:
            if hmac.compare_digest(digest, candidate.token_sha256):
                source = candidate
        if source is None:
            raise HTTPException(401, "Invalid network source credentials", headers={"WWW-Authenticate": "Bearer"})
        if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
            raise HTTPException(415, "Expected application/json")
        # The shared ASGI middleware also bounds the body before buffering it.
        raw = await request.body()
        if len(raw) > MAX_BATCH_BYTES:
            raise HTTPException(413, "Network batch exceeds its byte limit")
        try:
            batch = decode(raw)
            if type(batch) is not dict:
                raise ValueError
            if batch.get("source_id") != source.id:
                raise HTTPException(403, "Network source does not match credentials")
            profile = source.profile_for(batch.get("profile_revision"))
            validate_batch(batch, profile)
        except ValueError:
            raise HTTPException(422, "Invalid network batch or unenrolled profile") from None
        try:
            return await run_in_threadpool(request.app.state.network_store.ingest, batch, profile)
        except NetworkStoreError as exc:
            status = (409 if exc.code in {"network_batch_conflict", "network_event_conflict",
                                          "network_cursor_conflict"}
                      else 422 if exc.code == "network_collection_time_in_future" else 503)
            raise HTTPException(status, exc.code) from None
        except ValueError:
            raise HTTPException(422, "Invalid network batch") from None
        except Exception:
            raise HTTPException(503, "Network storage unavailable; retain and retry this batch") from None

    @application.get("/api/network/events", dependencies=[Depends(operator)])
    @application.get("/api/network/batches", dependencies=[Depends(operator)])
    def page(request: Request, source_id: str = Query(max_length=64),
             after: int = Query(0, ge=0, le=2**63-1), limit: int = Query(100, ge=1, le=200),
             snapshot: int | None = Query(None, ge=0, le=2**63-1)):
        config = enabled(request)
        if not any(source.id == source_id for source in config.sources):
            raise HTTPException(404, "Network source is not configured")
        try:
            return request.app.state.network_store.page(source_id, after=after, limit=limit,
                snapshot=snapshot, batches=request.url.path.endswith("/batches"))
        except Exception:
            raise HTTPException(503, "Network evidence unavailable") from None

    def source_status(request):
        config = enabled(request)
        rows = {row["source_id"]: row for row in request.app.state.network_store.sources()}
        result = []
        now_us = time.time_ns() // 1000
        for source in config.sources:
            row = rows.get(source.id)
            item = {"source_id": source.id, "hostname": source.hostname, "status": "never_seen"}
            if row:
                last = row["last_report"]
                timeout = request.app.state.config.heartbeat_timeout_seconds * 1_000_000
                status = ("stale" if now_us - row["received_at_us"] > timeout
                          else "delayed" if now_us - last["collected_at_us"] > timeout
                          else "degraded" if last["reports"] or not last["caught_up"]
                          or any(result["code"] is not None for result in last["results"])
                          else "current")
                item.update(row, status=status)
            result.append(item)
        return result

    @application.get("/api/network/sources", dependencies=[Depends(operator)])
    def sources(request: Request):
        enabled(request)
        try:
            return {"items": source_status(request)}
        except Exception:
            raise HTTPException(503, "Network collection status unavailable") from None

    @application.get("/api/network/status", dependencies=[Depends(operator)])
    def status(request: Request):
        if request.app.state.config.network_ingest is None:
            return {"enabled": False}
        try:
            return {"enabled": True, "analysis_enabled": False,
                    **request.app.state.network_store.status(), "sources": source_status(request)}
        except Exception:
            raise HTTPException(503, "Network storage status unavailable") from None
