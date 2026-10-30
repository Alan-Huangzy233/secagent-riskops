"""Operator-only saved observations and an optional local rehearsal workflow.

Reads never initialize storage, run a model or refresh evidence. Explicit workflow
submission writes only the separately configured queue, never source evidence.
"""
from typing import Literal

from fastapi import Depends, HTTPException, Path, Query, Request, Response
from pydantic import BaseModel, Field

from .ai_summary import Aliases
from .joint_ai_preview import JointPreviewError, preview
from .joint_ai_summary import JointSummaryError
from .joint_case_contract import CaseStoreError
from .joint_case_query import open_query
from .joint_config import compile_joint_config


def register_routes(application, operator):
    def specification(request):
        try:
            spec = compile_joint_config(request.app.state.config)
        except (ValueError, CaseStoreError):
            raise HTTPException(503, "joint_configuration_invalid") from None
        if spec is None:
            raise HTTPException(404, "joint_not_configured")
        return spec

    def read(request, method, *args, **kwargs):
        spec = specification(request)
        try:
            query = open_query(spec.database_path, spec.scope, spec.limits,
                               catalog_min_seq=spec.catalog_min_seq)
            result = getattr(query, method)(*args, **kwargs)
        except CaseStoreError as exc:
            status = (409 if exc.code == "joint_refresh_required"
                      else 422 if exc.code == "joint_invalid_request" else 503)
            raise HTTPException(status, exc.code) from None
        except Exception:
            # Paths, source configuration and SQLite details stay server-side.
            raise HTTPException(503, "joint_store_unavailable") from None
        if result is None:
            raise HTTPException(404, "joint_revision_not_found")
        return result

    @application.get("/api/joint/status", dependencies=[Depends(operator)])
    def status(request: Request):
        if request.app.state.config.joint_cases is None:
            return {"enabled": False}
        result = read(request, "status")
        from .joint_refresh_state import read_refresh_status
        result["refresh"] = read_refresh_status(specification(request), result)
        return result

    @application.get("/api/joint/cases", dependencies=[Depends(operator)])
    def cases(request: Request, page: int = Query(1, ge=1, le=1000),
              limit: int = Query(20, ge=1, le=50),
              snapshot: str | None = Query(None, min_length=1, max_length=4096),
              ip: str | None = Query(None, min_length=1, max_length=64),
              asset_id: str | None = Query(None, min_length=1, max_length=128),
              state: Literal["linked", "unmatched", "partial", "retracted", "stale"] | None = None,
              start: str | None = Query(None, min_length=1, max_length=64),
              end: str | None = Query(None, min_length=1, max_length=64)):
        filters = {name: value for name, value in {
            "ip": ip, "asset_id": asset_id, "state": state, "start": start, "end": end,
        }.items() if value is not None}
        return read(request, "list_cases", filters, page=page, limit=limit, snapshot=snapshot)

    @application.get("/api/joint/cases/{identity}", dependencies=[Depends(operator)])
    def case(request: Request, identity: str, revision: int = Query(ge=1, le=2**31-1)):
        return read(request, "case_detail", identity, revision)

    @application.get("/api/joint/cases/{identity}/timeline", dependencies=[Depends(operator)])
    def timeline(request: Request, identity: str, revision: int = Query(ge=1, le=2**31-1),
                 page: int = Query(1, ge=1, le=1000), limit: int = Query(50, ge=1, le=50)):
        return read(request, "timeline", identity, revision, page=page, limit=limit)

    @application.get("/api/joint/cases/{identity}/ai/preview", dependencies=[Depends(operator)])
    def ai_preview(request: Request, response: Response, identity: str,
                   revision: int = Query(ge=1, le=2**31-1)):
        service = getattr(request.app.state, "joint_ai", None)
        if service is not None and service.enabled:
            result = _workflow_result(lambda: service.preview(identity, revision))
            response.headers["Cache-Control"] = "no-store"
            return result
        spec = specification(request)
        # Reuse the already loaded local alias key. Never open jobs or a provider.
        aliases = getattr(getattr(request.app.state, "ai", None), "aliases", None)
        if type(aliases) is not Aliases:
            raise HTTPException(503, "joint_ai_preview_unavailable")
        try:
            result = preview(spec, identity, revision, aliases)
        except JointPreviewError as exc:
            raise HTTPException(409, exc.code) from None
        except JointSummaryError as exc:
            raise HTTPException(422, exc.code) from None
        except CaseStoreError as exc:
            status = (409 if exc.code == "joint_refresh_required"
                      else 422 if exc.code == "joint_invalid_request" else 503)
            raise HTTPException(status, exc.code) from None
        except Exception:
            raise HTTPException(503, "joint_ai_preview_unavailable") from None
        if result is None:
            raise HTTPException(404, "joint_revision_not_found")
        response.headers["Cache-Control"] = "no-store"
        return result


class JointAnalysisRequest(BaseModel):
    model_config = {"extra": "forbid"}
    revision: int = Field(strict=True, ge=1, le=2**31-1)
    preview_key: str = Field(pattern=r"^[a-f0-9]{64}$")


def _workflow_result(action):
    try:
        return action()
    except JointPreviewError:
        raise HTTPException(409, "joint_preview_changed") from None
    except KeyError:
        raise HTTPException(404, "joint_ai_record_not_found") from None
    except (JointSummaryError, CaseStoreError):
        raise HTTPException(409, "joint_ai_request_changed") from None
    except ValueError:
        raise HTTPException(409, "joint_ai_request_changed") from None
    except Exception:
        # Do not reflect paths, rejected data, provider text or SQLite details.
        raise HTTPException(503, "joint_ai_unavailable") from None


def register_workflow_routes(application, operator, operator_write):
    def service(request):
        value = getattr(request.app.state, "joint_ai", None)
        if value is None or not value.enabled:
            raise HTTPException(503, "joint_ai_disabled")
        return value

    @application.get("/api/joint/ai/status", dependencies=[Depends(operator)])
    def ai_status(request: Request):
        return {**request.app.state.joint_ai.status(),
                "csrf_token": getattr(request.app.state.control, "csrf_token", "")}

    @application.post("/api/joint/cases/{identity}/ai",
                      dependencies=[Depends(operator_write)], status_code=202)
    def ai_enqueue(request: Request, body: JointAnalysisRequest,
                   identity: str = Path(pattern=r"^JOINT-[a-f0-9]{32}$")):
        worker = service(request)
        return _workflow_result(lambda: worker.enqueue(
            identity, body.revision, body.preview_key, request.app.state.config.operator_username))

    @application.get("/api/joint/cases/{identity}/ai/history", dependencies=[Depends(operator)])
    def ai_history(request: Request, identity: str = Path(pattern=r"^JOINT-[a-f0-9]{32}$")):
        worker = service(request)
        return {"case_id": identity, "items": _workflow_result(lambda: worker.history(identity))}

    @application.get("/api/joint/ai/jobs/{job_id}", dependencies=[Depends(operator)])
    def ai_job(request: Request, job_id: str = Path(pattern=r"^[a-f0-9]{32}$")):
        worker = service(request)
        return _workflow_result(lambda: worker.job(job_id))
