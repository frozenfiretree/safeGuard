import hashlib
import mimetypes
import secrets
from pathlib import Path
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, StreamingResponse

from config_app import (
    API_PREFIX,
    APP_VERSION,
    OCR_SERVICE_TIMEOUT_SECONDS,
    OCR_SERVICE_URL,
    UPGRADE_STORE_DIR,
    get_admin_basic_password,
    get_admin_basic_user,
    get_admin_token,
)
from models import (
    AdminConfigUpdateRequest,
    AgentConfigResponse,
    AgentHeartbeatRequest,
    AgentRegisterRequest,
    BatchEventItem,
    DetectionRuleCreateRequest,
    DetectionRuleUpdateRequest,
    EventsBatchRequest,
    ScanCompleteRequest,
    UploadCompleteResponse,
    UploadInitRequest,
    UploadInitResponse,
    UploadStatusResponse,
    UpgradeReportRequest,
)
from detection.rules import (
    create_detection_rule,
    delete_detection_rule,
    get_detection_rule,
    list_detection_rules,
    update_detection_rule,
)
from services import (
    authenticate_agent,
    get_admin_global_config,
    get_agent_config,
    get_file_detail,
    heartbeat,
    ingest_events_batch,
    init_upload_session,
    list_admin_events,
    list_admin_agents,
    list_admin_assets,
    list_admin_files,
    list_admin_upload_sessions,
    list_admin_upgrade_reports,
    list_task_failures,
    mark_scan_complete,
    register_agent,
    refresh_admin_assets,
    report_upgrade,
    retry_task_failure,
    update_global_config,
    upload_chunk,
    get_upload_status,
    complete_upload_session,
)
from tasks import submit_discovery_task
from tracked_files import (
    get_sensitive_file_history,
    get_sensitive_version_detail,
    get_version_artifact_path,
    list_sensitive_files,
)


router = APIRouter(prefix=API_PREFIX, tags=["server-v2"])
rules_alias_router = APIRouter(prefix="/api", tags=["rules"])


def _extract_token(authorization: Optional[str], x_agent_token: Optional[str]) -> str:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization.split(" ", 1)[1].strip()
    return (x_agent_token or "").strip()


def _decode_basic(authorization: Optional[str]) -> tuple[str, str]:
    if not authorization or not authorization.lower().startswith("basic "):
        return "", ""
    import base64

    try:
        raw = base64.b64decode(authorization.split(" ", 1)[1].strip()).decode("utf-8")
        user, password = raw.split(":", 1)
        return user, password
    except Exception:
        return "", ""


def require_admin_auth(
    authorization: Optional[str] = Header(default=None),
    x_admin_token: Optional[str] = Header(default=None),
):
    configured_token = get_admin_token()
    configured_user = get_admin_basic_user()
    configured_password = get_admin_basic_password()
    presented_token = ""
    if authorization and authorization.lower().startswith("bearer "):
        presented_token = authorization.split(" ", 1)[1].strip()
    elif x_admin_token:
        presented_token = x_admin_token.strip()

    if configured_token and presented_token and secrets.compare_digest(configured_token, presented_token):
        return True

    user, password = _decode_basic(authorization)
    if configured_password and user and password:
        if secrets.compare_digest(user, configured_user) and secrets.compare_digest(password, configured_password):
            return True

    raise HTTPException(status_code=401, detail="admin authorization required")


@router.get("/health")
def health():
    return {"status": "ok", "version": APP_VERSION}


@router.post("/agents/register")
def register_agent_endpoint(req: AgentRegisterRequest):
    return register_agent(req.model_dump())


@router.get("/agents/{agent_id}/config", response_model=AgentConfigResponse)
def get_config_endpoint(
    agent_id: str,
    config_version: Optional[int] = None,
    authorization: Optional[str] = Header(default=None),
    x_agent_token: Optional[str] = Header(default=None),
):
    token = _extract_token(authorization, x_agent_token)
    authenticate_agent(agent_id, token)
    data = get_agent_config(agent_id, config_version)
    if data is None:
        return Response(status_code=304)
    return data


@router.post("/agents/{agent_id}/heartbeat")
def heartbeat_endpoint(
    agent_id: str,
    req: AgentHeartbeatRequest,
    authorization: Optional[str] = Header(default=None),
    x_agent_token: Optional[str] = Header(default=None),
):
    token = _extract_token(authorization, x_agent_token)
    authenticate_agent(agent_id, token)
    try:
        return heartbeat(agent_id, req.model_dump())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/uploads/init", response_model=UploadInitResponse)
def upload_init_endpoint(
    req: UploadInitRequest,
    authorization: Optional[str] = Header(default=None),
    x_agent_token: Optional[str] = Header(default=None),
):
    token = _extract_token(authorization, x_agent_token)
    authenticate_agent(req.agent_id, token)
    return init_upload_session(req.model_dump())


@router.put("/uploads/{session_id}/chunks/{index}")
async def upload_chunk_endpoint(
    session_id: str,
    index: int,
    request: Request,
    content_md5: Optional[str] = Header(default=None),
):
    body = await request.body()
    try:
        return upload_chunk(session_id, index, body, content_md5)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/uploads/{session_id}", response_model=UploadStatusResponse)
def upload_status_endpoint(session_id: str):
    try:
        return get_upload_status(session_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/uploads/{session_id}/complete", response_model=UploadCompleteResponse, status_code=202)
def upload_complete_endpoint(session_id: str):
    try:
        data = complete_upload_session(session_id)
    except RuntimeError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    task_id = submit_discovery_task(data["file_hash"])
    data["task_id"] = task_id
    return data


@router.post("/events/batch", status_code=202)
def events_batch_endpoint(
    req: EventsBatchRequest,
    authorization: Optional[str] = Header(default=None),
    x_agent_token: Optional[str] = Header(default=None),
):
    if not req.events:
        return {"accepted": 0, "duplicates": 0}
    token = _extract_token(authorization, x_agent_token)
    authenticate_agent(req.events[0].agent_id, token)
    return ingest_events_batch([item.model_dump() for item in req.events])


@router.post("/agents/{agent_id}/scan-complete")
def scan_complete_endpoint(
    agent_id: str,
    req: ScanCompleteRequest,
    authorization: Optional[str] = Header(default=None),
    x_agent_token: Optional[str] = Header(default=None),
):
    token = _extract_token(authorization, x_agent_token)
    authenticate_agent(agent_id, token)
    return mark_scan_complete(agent_id, req.model_dump())


@router.get("/upgrades/{version}/download")
def upgrade_download_endpoint(version: str, request: Request):
    candidates = [
        UPGRADE_STORE_DIR / version / "SafeGuardAgent.exe",
        UPGRADE_STORE_DIR / version / "SensAgent.exe",
    ]
    file_path = next((path for path in candidates if path.exists()), None)
    if not file_path:
        raise HTTPException(status_code=404, detail="upgrade package not found")
    file_size = file_path.stat().st_size
    range_header = request.headers.get("range") or request.headers.get("Range")
    media_type = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
    if not range_header:
        return FileResponse(str(file_path), filename=file_path.name, media_type=media_type)

    try:
        units, raw_range = range_header.split("=", 1)
        if units.strip().lower() != "bytes":
            raise ValueError("unsupported range unit")
        start_text, end_text = raw_range.split("-", 1)
        start = int(start_text) if start_text else 0
        end = int(end_text) if end_text else file_size - 1
        if start < 0 or end < start or end >= file_size:
            raise ValueError("invalid range")
    except Exception:
        raise HTTPException(status_code=416, detail="invalid range header")

    def iter_range():
        with open(file_path, "rb") as handle:
            handle.seek(start)
            remaining = end - start + 1
            while remaining > 0:
                chunk = handle.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                yield chunk

    headers = {
        "Content-Range": f"bytes {start}-{end}/{file_size}",
        "Accept-Ranges": "bytes",
        "Content-Length": str(end - start + 1),
        "Content-Disposition": f'attachment; filename="{file_path.name}"',
    }
    return StreamingResponse(iter_range(), status_code=206, headers=headers, media_type=media_type)


@router.post("/agents/{agent_id}/upgrade-report")
def upgrade_report_endpoint(
    agent_id: str,
    req: UpgradeReportRequest,
    authorization: Optional[str] = Header(default=None),
    x_agent_token: Optional[str] = Header(default=None),
):
    token = _extract_token(authorization, x_agent_token)
    authenticate_agent(agent_id, token)
    return report_upgrade(agent_id, req.model_dump())


@router.get("/admin/agents")
def admin_agents_endpoint(_=Depends(require_admin_auth)):
    return {"items": list_admin_agents()}


@router.get("/admin/assets")
def admin_assets_endpoint(_=Depends(require_admin_auth)):
    return list_admin_assets()


@router.post("/admin/assets/refresh")
def admin_assets_refresh_endpoint(_=Depends(require_admin_auth)):
    return refresh_admin_assets()


@router.get("/admin/files")
def admin_files_endpoint(sensitive: bool = False, agent_id: Optional[str] = None, _=Depends(require_admin_auth)):
    return {"items": list_admin_files(sensitive, agent_id)}


@router.get("/admin/events")
def admin_events_endpoint(limit: int = 100, agent_id: Optional[str] = None, _=Depends(require_admin_auth)):
    return {"items": list_admin_events(limit=limit, agent_id=agent_id)}


@router.get("/admin/upload-sessions")
def admin_upload_sessions_endpoint(limit: int = 100, _=Depends(require_admin_auth)):
    return {"items": list_admin_upload_sessions(limit=limit)}


@router.get("/admin/upgrades")
def admin_upgrades_endpoint(limit: int = 100, _=Depends(require_admin_auth)):
    return {"items": list_admin_upgrade_reports(limit=limit)}


@router.get("/admin/ocr/health")
def admin_ocr_health_endpoint(_=Depends(require_admin_auth)):
    try:
        with httpx.Client(timeout=OCR_SERVICE_TIMEOUT_SECONDS) as client:
            response = client.get(f"{OCR_SERVICE_URL}/health")
            response.raise_for_status()
            data = response.json()
        healthy = data.get("status") == "ok" and data.get("ready") is not False and not data.get("init_error")
        return {
            "status": "ok" if healthy else "error",
            "service_url": OCR_SERVICE_URL,
            "health": data,
            "error": data.get("init_error") if not healthy else None,
        }
    except Exception as exc:
        return {"status": "error", "service_url": OCR_SERVICE_URL, "error": str(exc)}


@router.get("/admin/files/{file_hash}")
def admin_file_detail_endpoint(file_hash: str, _=Depends(require_admin_auth)):
    try:
        return get_file_detail(file_hash)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/admin/task-failures")
def admin_task_failures_endpoint(_=Depends(require_admin_auth)):
    return {"items": list_task_failures()}


@router.post("/admin/task-failures/{failure_id}/retry")
def admin_task_failure_retry_endpoint(failure_id: int, _=Depends(require_admin_auth)):
    try:
        retry_payload = retry_task_failure(failure_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    task_id = None
    if retry_payload["task_name"] == "tasks.discovery_task":
        file_hash = retry_payload["payload"].get("file_hash")
        if file_hash:
            task_id = submit_discovery_task(file_hash)
    return {"status": "ok", "task_id": task_id}


@router.put("/admin/configs")
def admin_update_configs_endpoint(req: AdminConfigUpdateRequest, _=Depends(require_admin_auth)):
    return update_global_config(req.model_dump())


@router.get("/admin/configs")
def admin_get_configs_endpoint(_=Depends(require_admin_auth)):
    return get_admin_global_config()


@router.get("/rules")
def rules_list_endpoint(rule_type: Optional[str] = None, enabled: Optional[bool] = None, keyword: Optional[str] = None):
    return {"items": list_detection_rules(rule_type=rule_type, enabled=enabled, keyword=keyword)}


@router.get("/rules/{rule_id}")
def rule_detail_endpoint(rule_id: str):
    try:
        return get_detection_rule(rule_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/rules")
def rule_create_endpoint(req: DetectionRuleCreateRequest):
    try:
        return create_detection_rule(req.model_dump())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/rules/{rule_id}")
def rule_update_endpoint(rule_id: str, req: DetectionRuleUpdateRequest):
    payload = req.model_dump(exclude_unset=True)
    try:
        return update_detection_rule(rule_id, payload)
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/rules/{rule_id}")
def rule_delete_endpoint(rule_id: str):
    try:
        return delete_detection_rule(rule_id)
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))


@rules_alias_router.get("/rules")
def rules_list_alias_endpoint(rule_type: Optional[str] = None, enabled: Optional[bool] = None, keyword: Optional[str] = None):
    return rules_list_endpoint(rule_type=rule_type, enabled=enabled, keyword=keyword)


@rules_alias_router.get("/rules/{rule_id}")
def rule_detail_alias_endpoint(rule_id: str):
    return rule_detail_endpoint(rule_id)


@rules_alias_router.post("/rules")
def rule_create_alias_endpoint(req: DetectionRuleCreateRequest):
    return rule_create_endpoint(req)


@rules_alias_router.put("/rules/{rule_id}")
def rule_update_alias_endpoint(rule_id: str, req: DetectionRuleUpdateRequest):
    return rule_update_endpoint(rule_id, req)


@rules_alias_router.delete("/rules/{rule_id}")
def rule_delete_alias_endpoint(rule_id: str):
    return rule_delete_endpoint(rule_id)


@router.get("/sensitive-files")
def sensitive_files_endpoint(
    agent_id: Optional[str] = None,
    changed_only: bool = False,
    is_deleted: Optional[bool] = None,
    keyword: Optional[str] = None,
    file_type: Optional[str] = None,
    page: int = 1,
    page_size: int = 50,
):
    return list_sensitive_files(
        agent_id=agent_id,
        changed_only=changed_only,
        is_deleted=is_deleted,
        keyword=keyword,
        file_type=file_type,
        page=page,
        page_size=page_size,
    )


@router.get("/sensitive-files/{tracked_file_id}/versions")
def sensitive_file_versions_endpoint(tracked_file_id: str):
    try:
        return get_sensitive_file_history(tracked_file_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/sensitive-files/{tracked_file_id}/versions/{version_id}")
def sensitive_file_version_detail_endpoint(tracked_file_id: str, version_id: str):
    try:
        return get_sensitive_version_detail(tracked_file_id, version_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


def _artifact_response(tracked_file_id: str, version_id: str, artifact: str):
    try:
        path = get_version_artifact_path(tracked_file_id, version_id, artifact)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    media_type = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
    return FileResponse(str(path), filename=path.name, media_type=media_type)


@router.get("/sensitive-files/{tracked_file_id}/versions/{version_id}/download")
def sensitive_file_version_download_endpoint(tracked_file_id: str, version_id: str):
    return _artifact_response(tracked_file_id, version_id, "source")


@router.get("/sensitive-files/{tracked_file_id}/versions/{version_id}/download-highlight")
def sensitive_file_version_highlight_download_endpoint(tracked_file_id: str, version_id: str):
    return _artifact_response(tracked_file_id, version_id, "highlight")


@router.get("/sensitive-files/{tracked_file_id}/versions/{version_id}/download-diff")
def sensitive_file_version_diff_download_endpoint(tracked_file_id: str, version_id: str):
    return _artifact_response(tracked_file_id, version_id, "diff")
