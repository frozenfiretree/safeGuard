import hashlib
import json
import platform
import re
import secrets
import socket
import subprocess
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional

import httpx

from config_app import (
    APP_VERSION,
    DATA_DIR,
    FILE_STORE_DIR,
    HEARTBEAT_OFFLINE_SECONDS,
    HEARTBEAT_THROTTLE_SECONDS,
    TIMESTAMP_SKEW_SECONDS,
    TOKEN_REFRESH_THRESHOLD_SECONDS,
    TOKEN_TTL_SECONDS,
    UPLOAD_SESSION_TTL_SECONDS,
    OCR_SERVICE_TIMEOUT_SECONDS,
    OCR_SERVICE_URL,
    UploadSessionStatus,
    AgentStatus,
    FileDetectionStatus,
    NON_SENSITIVE_TTL_SECONDS,
    UPGRADE_STORE_DIR,
    setup_app_logger,
)
from detection.pipeline import detect_file
from models import (
    AdminConfigUpdateRequest,
    Agent,
    AgentConfig,
    FileChangeEvent,
    FileRecord,
    FileVersion,
    ParseResult,
    RuleHit,
    TaskFailure,
    UploadSession,
)
from path_utils import remote_path_name
from storage import db_session, init_db, object_storage, redis_cache
from tracked_files import archive_sensitive_file, ingest_tracked_event
from asset_discovery import discover_assets, get_local_network_context, infer_candidate_networks


logger = setup_app_logger("services")


def _now() -> float:
    return time.time()


def _is_parse_failure_result(result: dict) -> bool:
    return str(result.get("parse_status") or "").lower() == "failed"


def _parse_failure_message(result: dict) -> str:
    return str(result.get("parse_error") or result.get("error") or result.get("explanation_summary") or "File parsing failed")


def _persist_parse_failure_result(file_hash: str, result: dict) -> str:
    message = _parse_failure_message(result)
    with db_session() as session:
        file_row = session.get(FileRecord, file_hash)
        if not file_row:
            raise ValueError("file missing after detection")

        parse_row = session.get(ParseResult, file_hash)
        parse_status = str(result.get("parse_status") or "failed")
        if not parse_row:
            parse_row = ParseResult(file_hash=file_hash, parse_status=parse_status, result_data=result)
            session.add(parse_row)
        else:
            parse_row.parse_status = parse_status
            parse_row.result_data = result
            parse_row.updated_at = _now()

        session.query(RuleHit).filter(RuleHit.file_hash == file_hash).delete()
        file_row.detection_status = FileDetectionStatus.PARSE_FAILED.value
        file_row.is_sensitive = False
        file_row.risk_level = result.get("risk_level") or "REVIEW"
        file_row.explanation_summary = message
        file_row.updated_at = _now()

    record_task_failure(
        "tasks.discovery_task",
        {
            "file_hash": file_hash,
            "stage": "parse",
            "parse_status": str(result.get("parse_status") or "failed"),
            "file_name": result.get("file_name"),
        },
        message,
    )
    logger.warning("discovery parse failed: file_hash=%s error=%s", file_hash, message)
    return message


def check_ocr_service_health() -> dict:
    started = time.time()
    base = {
        "status": "error",
        "service": "ocr",
        "service_url": OCR_SERVICE_URL,
        "service_alive": False,
        "latency_ms": None,
        "ready": False,
        "models_ok": False,
        "ocr_initialized": False,
        "warmup_completed": False,
        "runtime_device": None,
        "missing_items": [],
        "health": None,
        "error": None,
    }
    try:
        with httpx.Client(timeout=OCR_SERVICE_TIMEOUT_SECONDS) as client:
            response = client.get(f"{OCR_SERVICE_URL}/status")
            if response.status_code == 404:
                response = client.get(f"{OCR_SERVICE_URL}/health")
            response.raise_for_status()
            data = response.json()
        latency_ms = int((time.time() - started) * 1000)
        init_error = data.get("init_error") or data.get("error")
        ready = bool(data.get("ready", data.get("status") == "ok") and data.get("models_ok", True) and not init_error)
        return {
            **base,
            "status": "ok" if ready else "error",
            "service_alive": True,
            "latency_ms": latency_ms,
            "ready": ready,
            "models_ok": bool(data.get("models_ok", ready)),
            "ocr_initialized": bool(data.get("ocr_initialized") or data.get("model_loaded")),
            "warmup_completed": bool(data.get("warmup_completed")),
            "warmup_in_progress": bool(data.get("warmup_in_progress")),
            "runtime_device": data.get("runtime_device"),
            "gpu_requested": data.get("gpu_requested"),
            "gpu_enabled": data.get("gpu_enabled"),
            "missing_items": data.get("missing_items") or data.get("model_integrity", {}).get("missing_items") or [],
            "model_home": data.get("model_home") or data.get("model_integrity", {}).get("model_home"),
            "health": data,
            "error": init_error if not ready else None,
        }
    except Exception as exc:
        latency_ms = int((time.time() - started) * 1000)
        return {**base, "latency_ms": latency_ms, "error": str(exc)}


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _new_token() -> tuple[str, str, float]:
    token = secrets.token_urlsafe(32)
    return token, _hash_token(token), _now() + TOKEN_TTL_SECONDS


def _restricted_agent_dirs() -> List[str]:
    return ["C:\\test", "%USERPROFILE%\\Downloads", "%USERPROFILE%\\Documents"]


def _has_legacy_broad_watch(value: object) -> bool:
    text = str(value or "").replace("/", "\\").rstrip("\\").lower()
    return text in {"c:\\users", "\\home"} or "devicesearchcache" in text or "\\appdata\\" in text


_WINDOWS_PATH_ENV_RE = re.compile(r"%[A-Za-z_][A-Za-z0-9_]*%")
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:([\\/]|$)")
_WINDOWS_INVALID_COMPONENT_CHARS = set('<>:"|?*')


def _looks_like_windows_path(value: str) -> bool:
    raw = str(value or "").strip().strip('"').strip("'")
    return bool(_WINDOWS_DRIVE_RE.match(raw) or raw.startswith("\\\\") or raw.startswith("//") or raw.startswith("%"))


def _validate_config_path(path_value: object, field_name: str) -> str:
    raw = str(path_value or "").strip().strip('"').strip("'")
    if not raw:
        raise ValueError(f"{field_name} contains empty path")
    if any(ord(ch) < 32 for ch in raw):
        raise ValueError(f"{field_name} contains control characters: {raw!r}")
    if "\x00" in raw:
        raise ValueError(f"{field_name} contains null byte")

    placeholder_safe = _WINDOWS_PATH_ENV_RE.sub("ENVVAR", raw)
    if _looks_like_windows_path(raw):
        if not (_WINDOWS_DRIVE_RE.match(placeholder_safe) or placeholder_safe.startswith("\\\\") or placeholder_safe.startswith("//") or placeholder_safe.startswith("ENVVAR")):
            raise ValueError(f"{field_name} must be an absolute Windows path: {raw}")
        tail = placeholder_safe[2:] if _WINDOWS_DRIVE_RE.match(placeholder_safe) else placeholder_safe
        for part in re.split(r"[\\/]+", tail):
            if not part or part in {".", ".."}:
                continue
            if any(ch in _WINDOWS_INVALID_COMPONENT_CHARS for ch in part):
                raise ValueError(f"{field_name} contains invalid Windows path characters: {raw}")
    else:
        if not raw.startswith(("/", "~", "$")):
            raise ValueError(f"{field_name} must be an absolute path: {raw}")
        if any(ch in raw for ch in "\x00"):
            raise ValueError(f"{field_name} contains invalid path characters: {raw}")
    return raw


def _clean_config_path_list(values: object, field_name: str) -> List[str]:
    cleaned: List[str] = []
    seen = set()
    for item in values or []:
        path = _validate_config_path(item, field_name)
        key = path.replace("/", "\\").rstrip("\\").lower()
        if key in seen:
            continue
        seen.add(key)
        cleaned.append(path)
    return cleaned


def _validate_include_extensions(values: object) -> List[str]:
    cleaned: List[str] = []
    seen = set()
    for item in values or []:
        ext = str(item or "").strip().lower()
        if not ext:
            continue
        if not ext.startswith("."):
            ext = f".{ext}"
        if not re.fullmatch(r"\.[a-z0-9]{1,16}", ext):
            raise ValueError(f"include_extensions contains invalid extension: {item}")
        if ext in seen:
            continue
        seen.add(ext)
        cleaned.append(ext)
    if not cleaned:
        raise ValueError("include_extensions cannot be empty")
    return cleaned


def _default_config_payload(version: int, watch_dirs: Optional[List[str]] = None) -> dict:
    scan_dirs = _restricted_agent_dirs()
    exclude_paths = [
        "C:\\Windows\\",
        "C:\\Program Files\\",
        "C:\\Program Files (x86)\\",
        "C:\\ProgramData\\",
        "%USERPROFILE%\\AppData\\",
        "/proc",
        "/sys",
        "/dev",
        "/run",
        "/var/lib/docker",
        "/tmp",
    ]
    return {
        "config_version": version,
        "scan_dirs": scan_dirs,
        "include_extensions": [".doc", ".docx", ".xlsx", ".pdf", ".ppt", ".pptx", ".csv", ".txt", ".png", ".jpg", ".jpeg", ".bmp"],
        "exclude_paths": exclude_paths,
        "max_file_size_mb": 100,
        "heartbeat_interval_sec": 60,
        "watch_dirs": sorted(set(watch_dirs or _restricted_agent_dirs())),
        "upgrade": None,
    }


def _sanitize_agent_config_payload(payload: Optional[dict], version: int) -> tuple[dict, bool]:
    current = dict(payload or {})
    changed = False
    scan_dirs = list(current.get("scan_dirs") or [])
    watch_dirs = list(current.get("watch_dirs") or [])
    if not scan_dirs or any(_has_legacy_broad_watch(item) for item in scan_dirs):
        current["scan_dirs"] = _restricted_agent_dirs()
        changed = True
    if not watch_dirs or any(_has_legacy_broad_watch(item) for item in watch_dirs):
        current["watch_dirs"] = _restricted_agent_dirs()
        changed = True
    for field_name in ("scan_dirs", "watch_dirs", "exclude_paths"):
        if field_name in current:
            cleaned = _clean_config_path_list(current.get(field_name) or [], field_name)
            if cleaned != current.get(field_name):
                current[field_name] = cleaned
                changed = True
    current.setdefault("include_extensions", [".doc", ".docx", ".xlsx", ".pdf", ".ppt", ".pptx", ".csv", ".txt", ".png", ".jpg", ".jpeg", ".bmp"])
    include_extensions = _validate_include_extensions(current.get("include_extensions") or [])
    if ".doc" not in include_extensions:
        include_extensions.append(".doc")
        current["include_extensions"] = include_extensions
        changed = True
    if ".ppt" not in include_extensions:
        include_extensions.append(".ppt")
        current["include_extensions"] = include_extensions
        changed = True
    if include_extensions != current.get("include_extensions"):
        current["include_extensions"] = include_extensions
        changed = True
    current.setdefault("exclude_paths", _default_config_payload(version).get("exclude_paths", []))
    current["max_file_size_mb"] = max(1, min(1024, int(current.get("max_file_size_mb") or 100)))
    current["heartbeat_interval_sec"] = max(5, min(3600, int(current.get("heartbeat_interval_sec") or 60)))
    if int(current.get("config_version") or 0) != int(version):
        current["config_version"] = version
        changed = True
    return current, changed


def _merge_config_payload(base: dict, override: Optional[dict]) -> dict:
    merged = dict(base or {})
    for key, value in (override or {}).items():
        if value is None:
            continue
        if isinstance(value, list):
            merged[key] = list(value)
        elif isinstance(value, dict) and isinstance(merged.get(key), dict):
            nested = dict(merged.get(key) or {})
            nested.update(value)
            merged[key] = nested
        else:
            merged[key] = value
    return merged


def _sanitize_upgrade_payload(upgrade: Optional[dict]) -> Optional[dict]:
    if not isinstance(upgrade, dict):
        return None
    version = str(upgrade.get("version") or "").strip()
    if not version:
        return None
    candidates = [
        UPGRADE_STORE_DIR / version / "SafeGuardAgent.exe",
        UPGRADE_STORE_DIR / version / "SensAgent.exe",
    ]
    if any(path.exists() for path in candidates):
        return upgrade
    return None


SUSPICIOUS_LLM_SOURCE_TOKENS = [
    "\\downloads\\",
    "\\desktop\\",
    "\\documents\\",
    "\\wechat files\\",
    "\\temp\\",
    "/downloads/",
    "/desktop/",
    "/documents/",
    "/tmp/",
]


def _is_suspicious_llm_source_path(path: str) -> bool:
    lowered = str(path or "").replace("/", "\\").lower()
    lowered_slash = str(path or "").replace("\\", "/").lower()
    return any(token in lowered or token in lowered_slash for token in SUSPICIOUS_LLM_SOURCE_TOKENS)


def _select_llm_source_path(session, file_hash: str, fallback: str) -> str:
    rows = session.query(FileVersion).filter(
        FileVersion.file_hash == file_hash,
        FileVersion.is_current.is_(True),
    ).all()
    paths = [str(row.file_path or "") for row in rows if row.file_path]
    suspicious = [path for path in paths if _is_suspicious_llm_source_path(path)]
    if suspicious:
        return sorted(suspicious, key=lambda item: (len(item), item.lower()))[0]
    return paths[0] if paths else fallback


def _should_rediscover_for_suspicious_source(session, file_hash: str) -> bool:
    file_row = session.get(FileRecord, file_hash)
    parse_row = session.get(ParseResult, file_hash)
    if not file_row or not parse_row:
        return False
    if file_row.detection_status not in {FileDetectionStatus.NON_SENSITIVE.value, FileDetectionStatus.SENSITIVE.value}:
        return False
    data = parse_row.result_data or {}
    if data.get("llm_gate_reason") != "source_not_suspicious":
        return False
    selected_path = _select_llm_source_path(session, file_hash, data.get("file_path") or file_row.file_name or "")
    return _is_suspicious_llm_source_path(selected_path)


def save_agent_upgrade_package(filename: str, content: bytes, version: Optional[str] = None) -> dict:
    safe_name = Path(str(filename or "")).name
    if not safe_name.lower().endswith(".exe"):
        raise ValueError("only .exe upgrade packages are allowed")
    if not content:
        raise ValueError("upgrade package is empty")
    raw_version = str(version or "").strip()
    if not raw_version:
        raw_version = Path(safe_name).stem
    raw_version = re.sub(r"(?i)^SafeGuardAgent[-_ ]*", "", raw_version).strip()
    raw_version = re.sub(r"[^0-9A-Za-z._-]+", "-", raw_version).strip(".-_")
    if not raw_version:
        raw_version = str(int(_now()))
    checksum = hashlib.sha256(content).hexdigest().lower()
    package_dir = UPGRADE_STORE_DIR / raw_version
    package_dir.mkdir(parents=True, exist_ok=True)
    package_path = package_dir / "SafeGuardAgent.exe"
    package_path.write_bytes(content)
    return {
        "status": "ok",
        "version": raw_version,
        "checksum": checksum,
        "file_name": package_path.name,
        "size": len(content),
        "path": str(package_path),
    }


def ensure_global_config() -> AgentConfig:
    with db_session() as session:
        row = session.query(AgentConfig).filter(AgentConfig.scope == "global", AgentConfig.agent_id.is_(None)).order_by(AgentConfig.version.desc()).first()
        if row:
            sanitized, changed = _sanitize_agent_config_payload(row.config_data, row.version)
            if changed:
                row.version = int(row.version) + 1
                sanitized["config_version"] = row.version
                row.config_data = sanitized
                row.updated_at = _now()
                session.add(row)
                session.flush()
            return row
        row = AgentConfig(scope="global", agent_id=None, version=1, config_data=_default_config_payload(1))
        session.add(row)
        session.flush()
        return row


def register_agent(payload: dict) -> dict:
    ensure_global_config()
    token, token_hash, token_expires = _new_token()
    with db_session() as session:
        agent = session.query(Agent).filter(Agent.device_fingerprint == payload["device_fingerprint"]).first()
        if not agent:
            agent = Agent(
                agent_id=str(uuid.uuid4()),
                device_fingerprint=payload["device_fingerprint"],
                hostname=payload.get("hostname"),
                ip=payload.get("ip"),
                os_version=payload.get("os_version"),
                mac_address=payload.get("mac_address"),
                agent_version=payload.get("agent_version"),
                status=AgentStatus.REGISTERED.value,
                token_hash=token_hash,
                token_expires_at=token_expires,
            )
            session.add(agent)
        else:
            agent.hostname = payload.get("hostname")
            agent.ip = payload.get("ip")
            agent.os_version = payload.get("os_version")
            agent.mac_address = payload.get("mac_address")
            agent.agent_version = payload.get("agent_version")
            agent.status = AgentStatus.ONLINE.value
            agent.token_hash = token_hash
            agent.token_expires_at = token_expires
            agent.updated_at = _now()
        session.flush()
        config = ensure_global_config()
        return {
            "agent_id": agent.agent_id,
            "token": token,
            "token_expires": token_expires,
            "config_version": config.version,
        }


def register_agent_legacy(payload: dict, preferred_agent_id: Optional[str] = None) -> dict:
    ensure_global_config()
    token, token_hash, token_expires = _new_token()
    with db_session() as session:
        agent = session.query(Agent).filter(Agent.device_fingerprint == payload["device_fingerprint"]).first()
        if not agent and preferred_agent_id:
            agent = session.get(Agent, preferred_agent_id)
        if not agent:
            agent = Agent(
                agent_id=preferred_agent_id or str(uuid.uuid4()),
                device_fingerprint=payload["device_fingerprint"],
            )
            session.add(agent)
        agent.hostname = payload.get("hostname")
        agent.ip = payload.get("ip")
        agent.os_version = payload.get("os_version")
        agent.mac_address = payload.get("mac_address")
        agent.agent_version = payload.get("agent_version")
        agent.status = AgentStatus.ONLINE.value
        agent.token_hash = token_hash
        agent.token_expires_at = token_expires
        agent.updated_at = _now()
        session.flush()
        config = ensure_global_config()
        return {
            "agent_id": agent.agent_id,
            "token": token,
            "token_expires": token_expires,
            "config_version": config.version,
        }


def authenticate_agent(agent_id: str, token: str) -> Agent:
    with db_session() as session:
        agent = session.get(Agent, agent_id)
        if not agent:
            raise ValueError("agent not found")
        if not token or agent.token_hash != _hash_token(token):
            raise ValueError("invalid token")
        if agent.token_expires_at and float(agent.token_expires_at) < _now():
            raise ValueError("token expired")
        session.expunge(agent)
        return agent


def get_agent_config(agent_id: str, client_version: Optional[int]) -> Optional[dict]:
    ensure_global_config()
    with db_session() as session:
        agent = session.get(Agent, agent_id)
        if not agent:
            raise ValueError("agent not found")
        global_config = session.query(AgentConfig).filter(
            AgentConfig.scope == "global",
            AgentConfig.agent_id.is_(None),
        ).order_by(AgentConfig.version.desc()).first()
        if not global_config:
            global_config = ensure_global_config()
        agent_config = session.query(AgentConfig).filter(
            AgentConfig.agent_id == agent_id,
        ).order_by(AgentConfig.version.desc()).first()
        effective = _merge_config_payload(global_config.config_data or {}, agent_config.config_data if agent_config else None)
        effective["upgrade"] = _sanitize_upgrade_payload(effective.get("upgrade"))
        effective["config_version"] = int(agent_config.version if agent_config else global_config.version)
        if client_version is not None and int(client_version) == int(effective["config_version"]):
            return None
        return effective


def heartbeat_legacy(agent_id: str, payload: Optional[dict] = None) -> dict:
    payload = payload or {}
    return heartbeat(
        agent_id,
        {
            "timestamp": float(payload.get("timestamp") or _now()),
            "agent_version": payload.get("agent_version") or "",
            "config_version": int(payload.get("config_version") or 0),
            "scan_status": payload.get("scan_status") or "RUNNING",
            "pending_task_count": int(payload.get("pending_task_count") or 0),
        },
    )


def heartbeat(agent_id: str, payload: dict) -> dict:
    now = _now()
    if abs(now - float(payload["timestamp"])) > TIMESTAMP_SKEW_SECONDS:
        raise ValueError("timestamp skew too large")

    throttle_key = f"heartbeat:{agent_id}:last"
    if not redis_cache.setnx(throttle_key, str(now), HEARTBEAT_THROTTLE_SECONDS):
        return {"config_changed": False, "upgrade": None, "token_refreshed": None}

    with db_session() as session:
        agent = session.get(Agent, agent_id)
        if not agent:
            raise ValueError("agent not found")
        agent.status = AgentStatus.ONLINE.value
        agent.last_heartbeat = now
        agent.agent_version = payload.get("agent_version")
        agent.updated_at = now
        agent.scan_progress = {
            "scan_status": payload.get("scan_status"),
            "pending_task_count": payload.get("pending_task_count", 0),
            "reported_config_version": payload.get("config_version"),
        }

        global_config = session.query(AgentConfig).filter(AgentConfig.scope == "global", AgentConfig.agent_id.is_(None)).order_by(AgentConfig.version.desc()).first()
        agent_config = session.query(AgentConfig).filter(AgentConfig.agent_id == agent_id).order_by(AgentConfig.version.desc()).first()
        effective_config = _merge_config_payload(global_config.config_data if global_config else {}, agent_config.config_data if agent_config else None)
        effective_version = int(agent_config.version if agent_config else (global_config.version if global_config else 1))
        config_changed = bool(int(payload.get("config_version") or 0) != effective_version)
        agent.config_version = effective_version

        remaining_ttl = float(agent.token_expires_at or 0) - now
        token_refreshed = None
        if remaining_ttl < TOKEN_REFRESH_THRESHOLD_SECONDS:
            token, token_hash, token_expires = _new_token()
            agent.token_hash = token_hash
            agent.token_expires_at = token_expires
            token_refreshed = token
        else:
            agent.token_expires_at = now + TOKEN_TTL_SECONDS

        return {
            "config_changed": config_changed,
            "upgrade": _sanitize_upgrade_payload(effective_config.get("upgrade")),
            "token_refreshed": token_refreshed,
        }


def init_upload_session(payload: dict) -> dict:
    archive_after_commit = None
    with db_session() as session:
        file_row = session.get(FileRecord, payload["file_hash"])
        if file_row and file_row.detection_status != FileDetectionStatus.PARSE_FAILED.value:
            current = session.query(FileVersion).filter(
                FileVersion.agent_id == payload["agent_id"],
                FileVersion.file_path == payload["file_path"],
                FileVersion.file_hash == payload["file_hash"],
            ).first()
            if not current:
                session.add(FileVersion(
                    agent_id=payload["agent_id"],
                    file_path=payload["file_path"],
                    file_hash=payload["file_hash"],
                    is_current=True,
                ))
            if file_row.is_sensitive:
                archive_after_commit = (payload["file_hash"], payload["agent_id"], payload["file_path"])
            result = {"status": "dedup", "file_id": payload["file_hash"], "uploaded_chunks": []}
        else:
            existing = session.query(UploadSession).filter(
                UploadSession.file_hash == payload["file_hash"],
                UploadSession.status.in_([UploadSessionStatus.CREATED.value, UploadSessionStatus.UPLOADING.value]),
                UploadSession.expires_at > _now(),
            ).first()
            if existing:
                result = {
                    "status": "existing",
                    "session_id": existing.session_id,
                    "uploaded_chunks": list(existing.uploaded_chunks or []),
                }
            else:
                session_id = str(uuid.uuid4())
                row = UploadSession(
                    session_id=session_id,
                    agent_id=payload["agent_id"],
                    file_hash=payload["file_hash"],
                    file_name=payload["file_name"],
                    file_type=payload.get("file_type"),
                    file_path=payload["file_path"],
                    file_size=int(payload["file_size"]),
                    total_chunks=int(payload["total_chunks"]),
                    uploaded_chunks=[],
                    status=UploadSessionStatus.CREATED.value,
                    expires_at=_now() + UPLOAD_SESSION_TTL_SECONDS,
                )
                session.add(row)
                result = {"status": "created", "session_id": session_id, "uploaded_chunks": []}

    if archive_after_commit:
        file_hash, agent_id, file_path = archive_after_commit
        try:
            archive_sensitive_file(file_hash, agent_id=agent_id, file_path=file_path)
        except Exception as exc:
            logger.warning("dedup sensitive archive failed: file_hash=%s agent_id=%s path=%s error=%s", file_hash, agent_id, file_path, exc)
    return result


def upload_chunk(session_id: str, index: int, body: bytes, content_md5: Optional[str] = None, chunk_sha256: Optional[str] = None) -> dict:
    with db_session() as session:
        row = session.get(UploadSession, session_id)
        if not row:
            raise ValueError("upload session not found")
        if row.status not in {UploadSessionStatus.CREATED.value, UploadSessionStatus.UPLOADING.value}:
            raise ValueError(f"upload session status invalid: {row.status}")
        if row.expires_at <= _now():
            row.status = UploadSessionStatus.EXPIRED.value
            raise ValueError("upload session expired")
        if index < 0 or index >= int(row.total_chunks):
            raise ValueError("chunk index out of range")

        if content_md5:
            md5hex = hashlib.md5(body).hexdigest()
            if md5hex.lower() != content_md5.lower():
                raise ValueError("chunk md5 mismatch")
        if chunk_sha256:
            sha256hex = hashlib.sha256(body).hexdigest()
            if sha256hex.lower() != chunk_sha256.lower():
                raise ValueError("chunk sha256 mismatch")

        object_storage.put_bytes(f"uploads/{session_id}/chunk_{index}", body)
        redis_cache.sadd(f"upload:{session_id}:chunks", index)
        redis_cache.expire(f"upload:{session_id}:chunks", UPLOAD_SESSION_TTL_SECONDS)

        uploaded = sorted(set((row.uploaded_chunks or []) + [index]))
        row.uploaded_chunks = uploaded
        row.status = UploadSessionStatus.UPLOADING.value
        row.updated_at = _now()
        return {"status": "ok", "session_id": session_id, "uploaded_chunks": uploaded}


def get_upload_status(session_id: str) -> dict:
    with db_session() as session:
        row = session.get(UploadSession, session_id)
        if not row:
            raise ValueError("upload session not found")
        uploaded = sorted(redis_cache.smembers(f"upload:{session_id}:chunks") or set(row.uploaded_chunks or []))
        return {
            "session_id": session_id,
            "status": row.status,
            "uploaded_chunks": uploaded,
            "total_chunks": row.total_chunks,
        }


def get_upload_session_agent_id(session_id: str) -> str:
    with db_session() as session:
        row = session.get(UploadSession, session_id)
        if not row:
            raise ValueError("upload session not found")
        return row.agent_id


def complete_upload_session(session_id: str, priority: str = "MEDIUM") -> dict:
    cleanup_chunks = 0
    temp_path = None
    temp_object = f"uploads/{session_id}/merged"
    with db_session() as session:
        row = session.get(UploadSession, session_id)
        if not row:
            raise ValueError("upload session not found")
        if row.status == UploadSessionStatus.COMPLETED.value:
            return {"status": "ok", "session_id": session_id, "file_hash": row.file_hash}

        uploaded = sorted(redis_cache.smembers(f"upload:{session_id}:chunks") or set(row.uploaded_chunks or []))
        missing = [idx for idx in range(int(row.total_chunks)) if idx not in uploaded]
        if missing:
            raise RuntimeError(f"missing chunks: {missing}")

        upload_info = {
            "agent_id": row.agent_id,
            "file_hash": row.file_hash,
            "file_name": row.file_name,
            "file_type": row.file_type,
            "file_path": row.file_path,
            "file_size": row.file_size,
            "total_chunks": int(row.total_chunks),
        }
        row.status = UploadSessionStatus.COMPLETING.value
        row.updated_at = _now()

    try:
        object_storage.compose_chunks(session_id, upload_info["total_chunks"], temp_object)
        temp_path = object_storage.download_to_temp(temp_object)
        actual_hash = hashlib.sha256(temp_path.read_bytes()).hexdigest()
        if actual_hash.lower() != upload_info["file_hash"].lower():
            with db_session() as session:
                row = session.get(UploadSession, session_id)
                if row:
                    row.status = UploadSessionStatus.FAILED.value
                    row.updated_at = _now()
            raise RuntimeError(f"file hash mismatch: expected={upload_info['file_hash']}, actual={actual_hash}")

        final_store_path = object_storage.upload_final_file(upload_info["file_hash"], temp_object)

        with db_session() as session:
            row = session.get(UploadSession, session_id)
            if not row:
                raise ValueError("upload session not found")

            existing = session.get(FileRecord, upload_info["file_hash"])
            if not existing:
                existing = FileRecord(
                    file_hash=upload_info["file_hash"],
                    file_name=upload_info["file_name"],
                    file_type=upload_info["file_type"],
                    file_size=upload_info["file_size"],
                    store_path=final_store_path,
                    detection_status=FileDetectionStatus.RECEIVED.value,
                )
                session.add(existing)
            else:
                existing.file_name = upload_info["file_name"]
                existing.file_type = upload_info["file_type"]
                existing.file_size = upload_info["file_size"]
                existing.store_path = final_store_path
                existing.detection_status = FileDetectionStatus.RECEIVED.value
                existing.updated_at = _now()

            session.query(FileVersion).filter(
                FileVersion.agent_id == upload_info["agent_id"],
                FileVersion.file_path == upload_info["file_path"],
                FileVersion.is_current.is_(True),
            ).update({"is_current": False})
            session.add(
                FileVersion(
                    agent_id=upload_info["agent_id"],
                    file_path=upload_info["file_path"],
                    file_hash=upload_info["file_hash"],
                    is_current=True,
                )
            )

            row.status = UploadSessionStatus.COMPLETED.value
            row.updated_at = _now()
        redis_cache.delete(f"upload:{session_id}:chunks")
        cleanup_chunks = upload_info["total_chunks"]
    except Exception:
        with db_session() as session:
            row = session.get(UploadSession, session_id)
            if row and row.status == UploadSessionStatus.COMPLETING.value:
                row.status = UploadSessionStatus.FAILED.value
                row.updated_at = _now()
        raise
    finally:
        try:
            if temp_path:
                temp_path.unlink(missing_ok=True)
        except Exception:
            pass
        for idx in range(cleanup_chunks):
            object_storage.delete(f"uploads/{session_id}/chunk_{idx}")
        object_storage.delete(temp_object)

    return {"status": "accepted", "session_id": session_id, "file_hash": upload_info["file_hash"], "priority": priority}


def run_discovery_pipeline(file_hash: str) -> dict:
    with db_session() as session:
        file_row = session.get(FileRecord, file_hash)
        if not file_row:
            raise ValueError("file not found")
        llm_source_path = _select_llm_source_path(session, file_hash, file_row.file_name or file_hash)
        allow_rediscover = _should_rediscover_for_suspicious_source(session, file_hash)
        if file_row.detection_status in {
            FileDetectionStatus.SENSITIVE.value,
            FileDetectionStatus.NON_SENSITIVE.value,
            FileDetectionStatus.PARSE_FAILED.value,
        } and not allow_rediscover:
            if file_row.detection_status == FileDetectionStatus.SENSITIVE.value:
                try:
                    archive_sensitive_file(file_hash)
                except Exception as exc:
                    logger.warning("sensitive archive backfill failed: file_hash=%s error=%s", file_hash, exc)
            return {"status": "skipped", "file_hash": file_hash, "detection_status": file_row.detection_status}

        file_row.detection_status = FileDetectionStatus.PARSING.value
        file_row.updated_at = _now()
        session.flush()
        store_path = file_row.store_path
        file_name = file_row.file_name
        file_type = file_row.file_type
        file_size = file_row.file_size

    temp_path = object_storage.download_to_temp(store_path, file_type or Path(file_name or "").suffix)
    try:
        result = detect_file(
            temp_path,
            agent_id="server",
            scan_id=file_hash,
            file_meta={
                "path": llm_source_path or file_name,
                "size": file_size,
                "extension": file_type or Path(file_name or "").suffix.lower(),
                "sha256": file_hash,
            },
        )
    except Exception as e:
        with db_session() as session:
            file_row = session.get(FileRecord, file_hash)
            if file_row:
                file_row.detection_status = FileDetectionStatus.PARSE_FAILED.value
                file_row.explanation_summary = str(e)
                file_row.updated_at = _now()
        raise
    finally:
        try:
            temp_path.unlink(missing_ok=True)
        except Exception:
            pass

    if _is_parse_failure_result(result):
        message = _persist_parse_failure_result(file_hash, result)
        refresh_watch_dirs()
        return {"status": "parse_failed", "file_hash": file_hash, "risk_level": result.get("risk_level") or "REVIEW", "error": message}

    with db_session() as session:
        file_row = session.get(FileRecord, file_hash)
        if not file_row:
            raise ValueError("file missing after detection")
        file_row.detection_status = FileDetectionStatus.RULE_CHECKING.value
        file_row.updated_at = _now()
        session.flush()

        parse_row = session.get(ParseResult, file_hash)
        if not parse_row:
            parse_row = ParseResult(file_hash=file_hash, parse_status=str(result.get("parse_status")), result_data=result)
            session.add(parse_row)
        else:
            parse_row.parse_status = str(result.get("parse_status"))
            parse_row.result_data = result
            parse_row.updated_at = _now()

        session.query(RuleHit).filter(RuleHit.file_hash == file_hash).delete()
        for item in (result.get("rule_findings") or []) + (result.get("ocr_findings") or []) + (result.get("llm_findings") or []):
            session.add(
                RuleHit(
                    file_hash=file_hash,
                    rule_id=str(item.get("rule_id") or item.get("rule_name") or "unknown"),
                    source=str(item.get("source") or "text"),
                    match_positions=item,
                )
            )

        findings = (result.get("rule_findings") or []) + (result.get("ocr_findings") or []) + (result.get("llm_findings") or [])
        if findings:
            file_row.detection_status = FileDetectionStatus.SENSITIVE.value
            file_row.is_sensitive = True
        else:
            file_row.detection_status = FileDetectionStatus.NON_SENSITIVE.value
            file_row.is_sensitive = False
        file_row.risk_level = result.get("risk_level")
        file_row.explanation_summary = result.get("explanation_summary")
        file_row.updated_at = _now()

    if findings:
        archive_sensitive_file(file_hash)

    refresh_watch_dirs()
    return {"status": "ok", "file_hash": file_hash, "risk_level": result.get("risk_level")}


def get_detection_result_payload(file_hash: str) -> Optional[dict]:
    with db_session() as session:
        file_row = session.get(FileRecord, file_hash)
        parse_row = session.get(ParseResult, file_hash)
        if not file_row or not parse_row:
            return None
        return {
            "agent_id": (parse_row.result_data or {}).get("agent_id"),
            "scan_id": (parse_row.result_data or {}).get("scan_id"),
            "file_path": (parse_row.result_data or {}).get("file_path"),
            "file_hash": file_row.file_hash,
            "file_name": file_row.file_name,
            "file_type": file_row.file_type,
            "file_size": file_row.file_size,
            "parse_status": parse_row.parse_status,
            "parse_error": (parse_row.result_data or {}).get("parse_error") or (parse_row.result_data or {}).get("error") or "",
            "needs_ocr": bool((parse_row.result_data or {}).get("needs_ocr")),
            "ocr_available": bool((parse_row.result_data or {}).get("ocr_available", True)),
            "ocr_error": (parse_row.result_data or {}).get("ocr_error"),
            "risk_level": file_row.risk_level,
            "explanation_summary": file_row.explanation_summary,
            "rule_findings": (parse_row.result_data or {}).get("rule_findings") or [],
            "ocr_findings": (parse_row.result_data or {}).get("ocr_findings") or [],
            "llm_findings": (parse_row.result_data or {}).get("llm_findings") or [],
            "llm_summary": (parse_row.result_data or {}).get("llm_summary") or "",
            "llm_used": bool((parse_row.result_data or {}).get("llm_used")),
            "llm_error": (parse_row.result_data or {}).get("llm_error") or "",
            "llm_gate_reason": (parse_row.result_data or {}).get("llm_gate_reason") or "",
            "final_decision": (parse_row.result_data or {}).get("final_decision") or {},
            "final_confidence": (parse_row.result_data or {}).get("final_confidence"),
            "suspicious_blocks": (parse_row.result_data or {}).get("suspicious_blocks") or [],
            "parsed_block_count": (parse_row.result_data or {}).get("parsed_block_count") or 0,
            "image_block_count": (parse_row.result_data or {}).get("image_block_count") or 0,
            "generated_at": (parse_row.result_data or {}).get("generated_at"),
        }


def list_detection_results_compat(agent_id: Optional[str], scan_id: Optional[str], limit: int = 100) -> list[dict]:
    with db_session() as session:
        rows = session.query(ParseResult).order_by(ParseResult.updated_at.desc()).all()
        items = []
        for row in rows:
            data = dict(row.result_data or {})
            if agent_id and str(data.get("agent_id") or "") != str(agent_id):
                continue
            if scan_id and str(data.get("scan_id") or "") != str(scan_id):
                continue
            file_payload = get_detection_result_payload(row.file_hash)
            if file_payload:
                items.append(file_payload)
            if len(items) >= limit:
                break
        return items


def legacy_inventory_decisions(agent_id: str, scan_id: str, files: List[dict]) -> dict:
    need_uploads = []
    reused_results = []
    inventory_items = []
    with db_session() as session:
        for item in files:
            file_hash = str(item.get("sha256") or "").lower()
            item_obj = dict(item)
            item_obj["file_id"] = hashlib.sha256(f"{agent_id}|{item_obj.get('path','')}|{file_hash}".encode("utf-8", errors="ignore")).hexdigest()[:24]
            inventory_items.append(item_obj)

            file_row = session.get(FileRecord, file_hash) if file_hash else None
            parse_row = session.get(ParseResult, file_hash) if file_hash else None
            if file_row and parse_row and file_row.detection_status != FileDetectionStatus.PARSE_FAILED.value:
                reused = get_detection_result_payload(file_hash) or {}
                reused_results.append(
                    {
                        "path": item_obj.get("path"),
                        "sha256": file_hash,
                        "parse_status": reused.get("parse_status"),
                        "needs_ocr": reused.get("needs_ocr"),
                        "risk_level": reused.get("risk_level"),
                        "explanation_summary": reused.get("explanation_summary"),
                    }
                )
            else:
                need_uploads.append(item_obj)

    return {
        "scan_id": scan_id,
        "inventory_items": inventory_items,
        "need_uploads": need_uploads,
        "reused_results": reused_results,
    }


def legacy_sync_upload(agent_id: str, scan_id: str, file_meta: dict, content: bytes) -> dict:
    init_resp = init_upload_session(
        {
            "file_hash": file_meta["sha256"],
            "file_size": int(file_meta["size"]),
            "total_chunks": 1,
            "file_name": remote_path_name(file_meta.get("path"), file_meta["sha256"]),
            "file_type": file_meta.get("extension"),
            "agent_id": agent_id,
            "file_path": file_meta["path"],
        }
    )
    if init_resp["status"] == "dedup":
        try:
            from tasks import submit_discovery_task

            submit_discovery_task(file_meta["sha256"])
        except Exception as exc:
            logger.warning("legacy dedup discovery submit failed: file_hash=%s error=%s", file_meta["sha256"], exc)
        reused = get_detection_result_payload(file_meta["sha256"]) or {}
        return {"status": "ok", "reused": True, "result": reused}

    session_id = init_resp["session_id"]
    upload_chunk(session_id, 0, content, hashlib.md5(content).hexdigest())
    complete_upload_session(session_id)
    run_discovery_pipeline(file_meta["sha256"])
    result = get_detection_result_payload(file_meta["sha256"]) or {}
    return {"status": "ok", "reused": False, "result": result}


def refresh_watch_dirs() -> dict:
    with db_session() as session:
        config = session.query(AgentConfig).filter(AgentConfig.scope == "global", AgentConfig.agent_id.is_(None)).order_by(AgentConfig.version.desc()).first()
        if not config:
            config = AgentConfig(scope="global", agent_id=None, version=1, config_data=_default_config_payload(1))
            session.add(config)
            return {"config_version": config.version, "watch_dirs": config.config_data.get("watch_dirs") or []}

        sanitized, changed = _sanitize_agent_config_payload(config.config_data, config.version)
        if changed:
            config.version = int(config.version) + 1
            sanitized["config_version"] = config.version
            config.config_data = sanitized
            config.updated_at = _now()
            session.add(config)
            session.flush()
        return {"config_version": config.version, "watch_dirs": config.config_data.get("watch_dirs") or []}


def ingest_events_batch(events: List[dict]) -> dict:
    inserted = 0
    duplicates = 0
    accepted_items = []
    with db_session() as session:
        for item in events:
            if session.get(FileChangeEvent, item["event_id"]):
                duplicates += 1
                continue
            session.add(
                FileChangeEvent(
                    event_id=item["event_id"],
                    agent_id=item["agent_id"],
                    event_type=item["event_type"],
                    file_path=item.get("file_path"),
                    old_path=item.get("old_path"),
                    new_path=item.get("new_path"),
                    old_hash=item.get("old_hash"),
                    new_hash=item.get("new_hash"),
                    file_size=item.get("file_size"),
                    timestamp=float(item["timestamp"]),
                    usb_context=item.get("usb_context") or {},
                    event_details=item.get("event_details") or {},
                )
            )
            inserted += 1
            accepted_items.append(dict(item))
    for item in accepted_items:
        try:
            ingest_tracked_event(item)
        except Exception:
            pass
    return {"accepted": inserted, "duplicates": duplicates}


def mark_scan_complete(agent_id: str, payload: dict) -> dict:
    with db_session() as session:
        agent = session.get(Agent, agent_id)
        if not agent:
            raise ValueError("agent not found")
        progress = dict(agent.scan_progress or {})
        progress.update(payload)
        progress["scan_status"] = "COMPLETED"
        agent.scan_progress = progress
        agent.updated_at = _now()
    return {"status": "ok", "agent_id": agent_id}


def report_upgrade(agent_id: str, payload: dict) -> dict:
    with db_session() as session:
        agent = session.get(Agent, agent_id)
        if not agent:
            raise ValueError("agent not found")
        progress = agent.scan_progress or {}
        progress["upgrade_report"] = payload
        if payload.get("new_version"):
            progress["upgrade_target"] = payload.get("new_version")
        agent.scan_progress = progress
        agent.updated_at = _now()
    return {"status": "ok", "agent_id": agent_id, "reported": True}


def cleanup_expired_upload_sessions() -> dict:
    now = _now()
    cleaned = 0
    with db_session() as session:
        rows = session.query(UploadSession).filter(
            UploadSession.status.in_([UploadSessionStatus.CREATED.value, UploadSessionStatus.UPLOADING.value, UploadSessionStatus.COMPLETING.value]),
            UploadSession.expires_at <= now,
        ).all()
        for row in rows:
            row.status = UploadSessionStatus.EXPIRED.value
            row.updated_at = now
            redis_cache.delete(f"upload:{row.session_id}:chunks")
            for idx in range(int(row.total_chunks or 0)):
                object_storage.delete(f"uploads/{row.session_id}/chunk_{idx}")
            object_storage.delete(f"uploads/{row.session_id}/merged")
            cleaned += 1
    return {"expired_sessions": cleaned}


def mark_offline_agents() -> dict:
    now = _now()
    updated = 0
    with db_session() as session:
        rows = session.query(Agent).filter(
            Agent.last_heartbeat.is_not(None),
            Agent.status == AgentStatus.ONLINE.value,
        ).all()
        for row in rows:
            if now - float(row.last_heartbeat or 0) > HEARTBEAT_OFFLINE_SECONDS:
                row.status = AgentStatus.OFFLINE.value
                row.updated_at = now
                updated += 1
    return {"offline_agents": updated}


def cleanup_non_sensitive_records() -> dict:
    cutoff = _now() - NON_SENSITIVE_TTL_SECONDS
    removed = 0
    with db_session() as session:
        rows = session.query(FileRecord).filter(
            FileRecord.is_sensitive.is_(False),
            FileRecord.updated_at < cutoff,
            FileRecord.detection_status.in_([FileDetectionStatus.NON_SENSITIVE.value, FileDetectionStatus.RULE_MISS_PENDING.value]),
        ).all()
        for row in rows:
            session.query(RuleHit).filter(RuleHit.file_hash == row.file_hash).delete()
            session.query(ParseResult).filter(ParseResult.file_hash == row.file_hash).delete()
            if row.store_path:
                object_storage.delete(row.store_path)
            session.delete(row)
            removed += 1
    return {"removed_files": removed}


def list_admin_agents() -> list[dict]:
    now = _now()
    with db_session() as session:
        agents = session.query(Agent).all()
        results = []
        for item in agents:
            status = item.status
            if item.last_heartbeat and now - float(item.last_heartbeat) > HEARTBEAT_OFFLINE_SECONDS:
                status = AgentStatus.OFFLINE.value
            results.append(
                {
                    "agent_id": item.agent_id,
                    "hostname": item.hostname,
                    "ip": item.ip,
                    "device_fingerprint": item.device_fingerprint,
                    "mac_address": item.mac_address,
                    "agent_version": item.agent_version,
                    "status": status,
                    "config_version": item.config_version,
                    "last_heartbeat": item.last_heartbeat,
                    "token_expires_at": item.token_expires_at,
                    "scan_progress": item.scan_progress or {},
                    "created_at": item.created_at,
                    "updated_at": item.updated_at,
                }
            )
        return results


def _serialize_admin_file_item(session, item: FileRecord) -> dict:
    current_versions = session.query(FileVersion).filter(
        FileVersion.file_hash == item.file_hash,
        FileVersion.is_current.is_(True),
    ).all()
    current_agents = sorted({row.agent_id for row in current_versions if row.agent_id})
    current_paths = sorted({row.file_path for row in current_versions if row.file_path})
    return {
        "file_hash": item.file_hash,
        "file_name": item.file_name,
        "file_type": item.file_type,
        "file_size": item.file_size,
        "detection_status": item.detection_status,
        "is_sensitive": item.is_sensitive,
        "risk_level": item.risk_level,
        "explanation_summary": item.explanation_summary,
        "agents": current_agents,
        "current_paths": current_paths,
        "updated_at": item.updated_at,
    }


def list_admin_files(sensitive_only: bool, agent_id: Optional[str] = None) -> list[dict]:
    with db_session() as session:
        query = session.query(FileRecord)
        if sensitive_only:
            query = query.filter(FileRecord.is_sensitive.is_(True))
        rows = query.order_by(FileRecord.updated_at.desc()).all()
        items = [_serialize_admin_file_item(session, item) for item in rows]
        if agent_id:
            normalized = str(agent_id)
            items = [item for item in items if normalized in (item.get("agents") or [])]
        return items


def _extract_text_previews(result_data: dict | None) -> List[str]:
    previews = []
    for item in (result_data or {}).get("per_block_locations") or []:
        text = str((item or {}).get("preview") or "").strip()
        if text:
            previews.append(text)
    return previews


def _summarize_event_change(session, row: FileChangeEvent) -> dict:
    summary = dict(row.event_details or {})
    event_type = str(row.event_type or "").lower()
    if event_type not in {"file_modified", "file_overwritten"}:
        return summary
    if not row.old_hash or not row.new_hash or row.old_hash == row.new_hash:
        return summary
    old_parse = session.get(ParseResult, row.old_hash)
    new_parse = session.get(ParseResult, row.new_hash)
    old_texts = _extract_text_previews(old_parse.result_data if old_parse else {})
    new_texts = _extract_text_previews(new_parse.result_data if new_parse else {})
    old_set = set(old_texts)
    new_set = set(new_texts)
    added = [item for item in new_texts if item not in old_set][:3]
    removed = [item for item in old_texts if item not in new_set][:3]
    if added or removed:
        summary["change_summary"] = {
            "added": added,
            "removed": removed,
            "more_added": max(0, len([item for item in new_texts if item not in old_set]) - len(added)),
            "more_removed": max(0, len([item for item in old_texts if item not in new_set]) - len(removed)),
        }
    return summary


def list_admin_events(limit: int = 100, agent_id: Optional[str] = None) -> list[dict]:
    with db_session() as session:
        query = session.query(FileChangeEvent)
        if agent_id:
            query = query.filter(FileChangeEvent.agent_id == agent_id)
        rows = query.order_by(FileChangeEvent.timestamp.desc()).limit(limit).all()
        return [
            {
                "event_id": row.event_id,
                "agent_id": row.agent_id,
                "event_type": row.event_type,
                "file_path": row.file_path,
                "old_path": row.old_path,
                "new_path": row.new_path,
                "old_hash": row.old_hash,
                "new_hash": row.new_hash,
                "file_size": row.file_size,
                "timestamp": row.timestamp,
                "usb_context": row.usb_context or {},
                "event_details": _summarize_event_change(session, row),
                "created_at": row.created_at,
            }
            for row in rows
        ]


def list_admin_upload_sessions(limit: int = 100) -> list[dict]:
    with db_session() as session:
        rows = session.query(UploadSession).order_by(UploadSession.updated_at.desc()).limit(limit).all()
        return [
            {
                "session_id": row.session_id,
                "agent_id": row.agent_id,
                "file_hash": row.file_hash,
                "file_name": row.file_name,
                "file_type": row.file_type,
                "file_path": row.file_path,
                "file_size": row.file_size,
                "total_chunks": row.total_chunks,
                "uploaded_chunks": row.uploaded_chunks or [],
                "status": row.status,
                "expires_at": row.expires_at,
                "created_at": row.created_at,
                "updated_at": row.updated_at,
            }
            for row in rows
        ]


def list_admin_upgrade_reports(limit: int = 100) -> list[dict]:
    with db_session() as session:
        rows = session.query(Agent).order_by(Agent.updated_at.desc()).all()
        items = []
        for row in rows:
            upgrade_report = (row.scan_progress or {}).get("upgrade_report")
            upgrade_target = (row.scan_progress or {}).get("upgrade_target")
            if not upgrade_report and not upgrade_target:
                continue
            items.append(
                {
                    "agent_id": row.agent_id,
                    "hostname": row.hostname,
                    "ip": row.ip,
                    "agent_version": row.agent_version,
                    "upgrade_target": upgrade_target,
                    "upgrade_report": upgrade_report,
                    "updated_at": row.updated_at,
                }
            )
            if len(items) >= limit:
                break
        return items


def get_admin_global_config() -> dict:
    with db_session() as session:
        global_config = session.query(AgentConfig).filter(
            AgentConfig.scope == "global",
            AgentConfig.agent_id.is_(None),
        ).order_by(AgentConfig.version.desc()).first()
        agent_overrides = session.query(AgentConfig).filter(AgentConfig.agent_id.is_not(None)).order_by(AgentConfig.updated_at.desc()).all()
        payload = dict(global_config.config_data or {}) if global_config else {}
        return {
            "config_version": int(global_config.version if global_config else 0),
            "config": payload,
            "agent_overrides": [
                {
                    "agent_id": row.agent_id,
                    "version": row.version,
                    "config": row.config_data or {},
                    "updated_at": row.updated_at,
                }
                for row in agent_overrides
            ],
        }


def get_file_detail(file_hash: str) -> dict:
    with db_session() as session:
        file_row = session.get(FileRecord, file_hash)
        if not file_row:
            raise ValueError("file not found")
        parse_row = session.get(ParseResult, file_hash)
        hits = session.query(RuleHit).filter(RuleHit.file_hash == file_hash).all()
        current_versions = session.query(FileVersion).filter(
            FileVersion.file_hash == file_hash,
            FileVersion.is_current.is_(True),
        ).all()
        return {
            "file_hash": file_row.file_hash,
            "file_name": file_row.file_name,
            "file_type": file_row.file_type,
            "file_size": file_row.file_size,
            "detection_status": file_row.detection_status,
            "is_sensitive": file_row.is_sensitive,
            "risk_level": file_row.risk_level,
            "explanation_summary": file_row.explanation_summary,
            "agents": sorted(
                {
                    item.agent_id
                    for item in current_versions
                    if item.agent_id
                }
            ),
            "current_paths": sorted(
                {
                    item.file_path
                    for item in current_versions
                    if item.file_path
                }
            ),
            "parse_result": parse_row.result_data if parse_row else None,
            "rule_hits": [item.match_positions for item in hits],
            "ocr_findings": list((parse_row.result_data or {}).get("ocr_findings") or []) if parse_row else [],
            "llm_findings": list((parse_row.result_data or {}).get("llm_findings") or []) if parse_row else [],
            "llm_summary": ((parse_row.result_data or {}).get("llm_summary") or "") if parse_row else "",
            "final_decision": ((parse_row.result_data or {}).get("final_decision") or {}) if parse_row else {},
            "confidence": ((parse_row.result_data or {}).get("confidence")) if parse_row else None,
            "per_block_locations": list((parse_row.result_data or {}).get("per_block_locations") or []) if parse_row else [],
        }


def record_task_failure(task_name: str, task_payload: dict, error_message: str):
    with db_session() as session:
        session.add(TaskFailure(task_name=task_name, task_payload=task_payload, error_message=error_message[:4000]))


def list_task_failures() -> list[dict]:
    with db_session() as session:
        rows = session.query(TaskFailure).order_by(TaskFailure.created_at.desc()).all()
        return [
            {
                "id": row.id,
                "task_name": row.task_name,
                "task_payload": row.task_payload,
                "error_message": row.error_message,
                "created_at": row.created_at,
            }
            for row in rows
        ]


def retry_task_failure(failure_id: int) -> dict:
    with db_session() as session:
        row = session.get(TaskFailure, failure_id)
        if not row:
            raise ValueError("task failure not found")
        payload = row.task_payload or {}
        return {"task_name": row.task_name, "payload": payload}


def update_global_config(payload: dict) -> dict:
    with db_session() as session:
        config = session.query(AgentConfig).filter(AgentConfig.scope == "global", AgentConfig.agent_id.is_(None)).order_by(AgentConfig.version.desc()).first()
        if not config:
            config = AgentConfig(scope="global", agent_id=None, version=1, config_data=_default_config_payload(1))
            session.add(config)
            session.flush()

        merged = dict(config.config_data or {})
        for key, value in payload.items():
            merged[key] = value
        config.version = int(config.version) + 1
        merged["config_version"] = config.version
        sanitized, _ = _sanitize_agent_config_payload(merged, config.version)
        config.config_data = sanitized
        config.updated_at = _now()
        session.add(config)
        session.flush()
        return {"config_version": config.version, "config": sanitized}


def _read_json(path: Path, default=None):
    if default is None:
        default = {}
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return default


def _asset_cache_path() -> Path:
    asset_dir = DATA_DIR / "assets"
    asset_dir.mkdir(parents=True, exist_ok=True)
    return asset_dir / "discovered_hosts.json"


def _asset_discovery_cache_path() -> Path:
    asset_dir = DATA_DIR / "assets"
    asset_dir.mkdir(parents=True, exist_ok=True)
    return asset_dir / "asset_discovery_latest.json"


def _normalize_mac(value: Optional[str]) -> str:
    raw = str(value or "").strip().lower().replace("-", ":")
    if not raw or raw == "ff:ff:ff:ff:ff:ff":
        return ""
    parts = [part.zfill(2) for part in raw.split(":") if part]
    return ":".join(parts[:6]) if parts else ""


def _sort_ip_key(ip: str) -> tuple:
    try:
        return tuple(int(part) for part in ip.split("."))
    except Exception:
        return (999, 999, 999, 999)


def _detect_local_hosts() -> list[dict]:
    now = _now()
    hostname = socket.gethostname()
    fqdn = socket.getfqdn() or hostname
    local_mac = _normalize_mac(":".join(re.findall("..", f"{uuid.getnode():012x}")))
    hosts: dict[str, dict] = {}

    for candidate in {hostname, fqdn}:
        try:
            _, _, addresses = socket.gethostbyname_ex(candidate)
        except Exception:
            continue
        for ip in addresses:
            if ip.startswith("127.") or ":" in ip:
                continue
            hosts[ip] = {
                "ip": ip,
                "mac": local_mac or None,
                "hostname": hostname,
                "hostname_source": "local-system",
                "os_type": platform.system() or "unknown",
                "os_source": "local-system",
                "os_confidence": 100,
                "open_ports": [],
                "is_alive": True,
                "discovery_tool": "local-system",
                "arp_verified": bool(local_mac),
                "host_discovery_verified": True,
                "icmp_verified": True,
                "tcp_verified": False,
                "suspicious": False,
                "last_seen_at": now,
            }
    return list(hosts.values())


def _parse_arp_cache() -> list[dict]:
    if platform.system().lower() == "linux":
        return _parse_linux_ip_neigh()
    return _parse_windows_arp_cache()


def _parse_linux_ip_neigh() -> list[dict]:
    now = _now()
    try:
        completed = subprocess.run(
            ["ip", "neigh", "show"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=8,
            check=False,
        )
    except Exception:
        return []
    items: dict[str, dict] = {}
    for raw_line in (completed.stdout or "").replace("\r", "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = re.match(r"^([0-9.]+)\s+dev\s+(\S+).*?\s+lladdr\s+([0-9a-f:-]{11,})\s+(\S+)", line, flags=re.IGNORECASE)
        if not match:
            continue
        ip = match.group(1)
        interface_name = match.group(2)
        mac = _normalize_mac(match.group(3))
        state = match.group(4)
        if not mac:
            continue
        hostname = "unknown"
        hostname_source = "unknown"
        try:
            resolved, _, _ = socket.gethostbyaddr(ip)
            hostname = resolved
            hostname_source = "ptr"
        except Exception:
            pass
        items[ip] = {
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "hostname_source": hostname_source,
            "os_type": "unknown",
            "os_source": "unknown",
            "os_confidence": 0,
            "open_ports": [],
            "is_alive": state.upper() not in {"FAILED", "INCOMPLETE"},
            "discovery_tool": "linux-ip-neigh",
            "arp_verified": True,
            "host_discovery_verified": False,
            "icmp_verified": False,
            "tcp_verified": False,
            "suspicious": False,
            "last_seen_at": now,
            "interface_ip": interface_name,
        }
    return list(items.values())


def _parse_windows_arp_cache() -> list[dict]:
    now = _now()
    try:
        completed = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=8,
            check=False,
        )
    except Exception:
        return []
    text = (completed.stdout or "").replace("\r", "")
    items: dict[str, dict] = {}
    current_interface = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match_iface = re.match(r"^Interface:\s+([0-9.]+)", line, flags=re.IGNORECASE)
        if match_iface:
            current_interface = match_iface.group(1)
            continue
        match_arp = re.match(r"^([0-9.]+)\s+([0-9a-f:-]{11,})\s+(\w+)$", line, flags=re.IGNORECASE)
        if not match_arp:
            continue
        ip = match_arp.group(1)
        mac = _normalize_mac(match_arp.group(2))
        if not mac:
            continue
        hostname = "unknown"
        hostname_source = "unknown"
        try:
            resolved, _, _ = socket.gethostbyaddr(ip)
            hostname = resolved
            hostname_source = "ptr"
        except Exception:
            pass
        items[ip] = {
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "hostname_source": hostname_source,
            "os_type": "unknown",
            "os_source": "unknown",
            "os_confidence": 0,
            "open_ports": [],
            "is_alive": True,
            "discovery_tool": "windows-arp-cache",
            "arp_verified": True,
            "host_discovery_verified": False,
            "icmp_verified": False,
            "tcp_verified": False,
            "suspicious": False,
            "last_seen_at": now,
            "interface_ip": current_interface or None,
        }
    return list(items.values())


def _merge_asset_records(existing: list[dict], fresh: list[dict]) -> list[dict]:
    merged: dict[str, dict] = {}
    for row in existing + fresh:
        ip = str((row or {}).get("ip") or "").strip()
        if not ip:
            continue
        previous = merged.get(ip, {})
        current = dict(previous)
        current.update({k: v for k, v in (row or {}).items() if v not in (None, "", [], {})})
        current.setdefault("hostname", "unknown")
        current.setdefault("hostname_source", "unknown")
        current.setdefault("os_type", "unknown")
        current.setdefault("os_source", "unknown")
        current.setdefault("os_confidence", 0)
        current.setdefault("open_ports", [])
        current.setdefault("is_alive", True)
        current.setdefault("discovery_tool", "cached")
        current.setdefault("arp_verified", False)
        current.setdefault("host_discovery_verified", False)
        current.setdefault("icmp_verified", False)
        current.setdefault("tcp_verified", False)
        current.setdefault("suspicious", False)
        current.setdefault("last_seen_at", _now())
        if previous.get("discovery_tool") and row.get("discovery_tool") and previous.get("discovery_tool") != row.get("discovery_tool"):
            current["discovery_tool"] = f"{previous.get('discovery_tool')},{row.get('discovery_tool')}"
        merged[ip] = current
    return [merged[ip] for ip in sorted(merged.keys(), key=_sort_ip_key)]


def list_admin_assets() -> dict:
    cache_path = _asset_cache_path()
    data = _read_json(cache_path, default=[])
    items = data if isinstance(data, list) else data.get("items", [])
    updated_at = cache_path.stat().st_mtime if cache_path.exists() else None
    return {"items": items, "updated_at": updated_at}


def refresh_admin_assets() -> dict:
    cache_path = _asset_cache_path()
    existing = _read_json(cache_path, default=[])
    if isinstance(existing, dict):
        existing = existing.get("items", [])
    result = discover_assets(include_port_scan=False, include_os_detect=True, timeout=20)
    fresh = result.get("assets") or []
    merged = _merge_asset_records(existing or [], fresh)
    cache_path.write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")
    discovery_cache = _asset_discovery_cache_path()
    result["assets"] = merged
    result["count"] = len(merged)
    result["updated_at"] = _now()
    discovery_cache.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return {
        "items": merged,
        "updated_at": result["updated_at"],
        "sources": {"asset_discovery": len(fresh)},
        "warnings": result.get("warnings") or [],
        "errors": result.get("errors") or [],
        "platform": result.get("platform"),
        "candidate_networks": result.get("candidate_networks") or [],
        "local_interfaces": result.get("local_interfaces") or [],
    }


def list_discovered_assets() -> dict:
    cache_path = _asset_discovery_cache_path()
    if not cache_path.exists():
        return {"status": "ok", "count": 0, "assets": [], "message": "asset discovery has not been run yet"}
    data = _read_json(cache_path, default={})
    if isinstance(data, list):
        return {"status": "ok", "count": len(data), "assets": data}
    assets = data.get("assets") or data.get("items") or []
    data["assets"] = assets
    data["count"] = len(assets)
    data.setdefault("status", "ok")
    return data


def run_asset_discovery(payload: Optional[dict] = None) -> dict:
    payload = payload or {}
    result = discover_assets(
        targets=payload.get("targets"),
        mode=str(payload.get("mode") or "auto"),
        include_port_scan=bool(payload.get("include_port_scan", True)),
        include_os_detect=bool(payload.get("include_os_detect", True)),
        timeout=int(payload.get("timeout") or 60),
        ports=payload.get("ports"),
    )
    result["updated_at"] = _now()
    _asset_discovery_cache_path().write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    _asset_cache_path().write_text(json.dumps(result.get("assets") or [], ensure_ascii=False, indent=2), encoding="utf-8")
    return result


def get_asset_network_context() -> dict:
    context = get_local_network_context()
    candidates = infer_candidate_networks(context)
    return {
        "platform": context.get("platform"),
        "local_interfaces": context.get("local_interfaces") or [],
        "route_table": context.get("route_table") or [],
        "extra_networks": context.get("extra_networks") or [],
        "candidate_networks": candidates,
        "warnings": context.get("warnings") or [],
        "errors": context.get("errors") or [],
    }


def _iter_jsonl(path: Path):
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except Exception:
            continue


def migrate_legacy_state(logger=None) -> dict:
    init_db()
    summary = {
        "agents": 0,
        "files": 0,
        "parse_results": 0,
        "rule_hits": 0,
        "versions": 0,
        "events": 0,
        "config_updated": 0,
    }

    state_agents_dir = DATA_DIR / "state" / "agents"
    for path in state_agents_dir.glob("*.json"):
        data = _read_json(path, {})
        info = data.get("info") or {}
        agent_id = path.stem
        register_agent_legacy(
            {
                "device_fingerprint": info.get("agent_id") or agent_id,
                "hostname": info.get("hostname"),
                "ip": info.get("ip"),
                "os_version": info.get("os_version"),
                "agent_version": info.get("agent_version") or info.get("python_version"),
                "mac_address": info.get("mac"),
            },
            preferred_agent_id=agent_id,
        )
        summary["agents"] += 1

    detection_root = DATA_DIR / "detection_results"
    by_hash_dir = detection_root / "by_hash"
    for path in by_hash_dir.glob("*.json"):
        result = _read_json(path, {})
        file_hash = result.get("file_hash")
        if not file_hash:
            continue
        with db_session() as session:
            file_row = session.get(FileRecord, file_hash)
            if not file_row:
                file_row = FileRecord(file_hash=file_hash)
                session.add(file_row)
            file_row.file_name = result.get("file_name")
            file_row.file_type = result.get("file_extension")
            file_row.file_size = int(result.get("file_size") or 0)
            file_row.detection_status = (
                FileDetectionStatus.PARSE_FAILED.value
                if str(result.get("parse_status")) not in {"ok", "OK"}
                else (FileDetectionStatus.SENSITIVE.value if (result.get("rule_findings") or result.get("ocr_findings")) else FileDetectionStatus.RULE_MISS_PENDING.value)
            )
            file_row.is_sensitive = bool((result.get("rule_findings") or []) or (result.get("ocr_findings") or []))
            file_row.risk_level = result.get("risk_level")
            file_row.explanation_summary = result.get("explanation_summary")
            parse_row = session.get(ParseResult, file_hash)
            if not parse_row:
                parse_row = ParseResult(file_hash=file_hash, parse_status=str(result.get("parse_status")), result_data=result)
                session.add(parse_row)
                summary["parse_results"] += 1
            else:
                parse_row.parse_status = str(result.get("parse_status"))
                parse_row.result_data = result
                parse_row.updated_at = _now()
            session.query(RuleHit).filter(RuleHit.file_hash == file_hash).delete()
            hit_count = 0
            for item in (result.get("rule_findings") or []) + (result.get("ocr_findings") or []):
                session.add(
                    RuleHit(
                        file_hash=file_hash,
                        rule_id=str(item.get("rule_id") or item.get("rule_name") or "unknown"),
                        source=str(item.get("source") or "text"),
                        match_positions=item,
                    )
                )
                hit_count += 1
            summary["rule_hits"] += hit_count
            summary["files"] += 1

    for agent_dir in detection_root.iterdir() if detection_root.exists() else []:
        if not agent_dir.is_dir() or agent_dir.name == "by_hash":
            continue
        for scan_dir in agent_dir.iterdir():
            if not scan_dir.is_dir():
                continue
            for path in scan_dir.glob("*.json"):
                result = _read_json(path, {})
                file_hash = result.get("file_hash")
                file_path = result.get("file_path")
                if not file_hash or not file_path:
                    continue
                with db_session() as session:
                    session.query(FileVersion).filter(
                        FileVersion.agent_id == agent_dir.name,
                        FileVersion.file_path == file_path,
                        FileVersion.is_current.is_(True),
                    ).update({"is_current": False})
                    exists = session.query(FileVersion).filter(
                        FileVersion.agent_id == agent_dir.name,
                        FileVersion.file_path == file_path,
                        FileVersion.file_hash == file_hash,
                    ).first()
                    if not exists:
                        session.add(FileVersion(agent_id=agent_dir.name, file_path=file_path, file_hash=file_hash, is_current=True))
                        summary["versions"] += 1

    generic_events_root = DATA_DIR / "events" / "generic"
    for agent_dir in generic_events_root.iterdir() if generic_events_root.exists() else []:
        path = agent_dir / "events.jsonl"
        for item in _iter_jsonl(path):
            event_name = item.get("event_name")
            payload = item.get("payload") or {}
            if event_name not in {"file_changed", "usb_changed"}:
                continue
            event_id = payload.get("event_id") or hashlib.sha256(json.dumps(item, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()[:32]
            try:
                ingest_events_batch(
                    [
                        {
                            "event_id": event_id,
                            "agent_id": item.get("agent_id") or agent_dir.name,
                            "event_type": event_name,
                            "file_path": payload.get("path") or payload.get("file_path"),
                            "old_path": payload.get("old_path"),
                            "new_path": payload.get("new_path"),
                            "old_hash": payload.get("old_hash"),
                            "new_hash": payload.get("new_hash"),
                            "file_size": payload.get("file_size"),
                            "timestamp": float(payload.get("timestamp") or item.get("timestamp") or _now()),
                            "usb_context": payload.get("usb_context") or {},
                            "event_details": payload.get("event_details") or {},
                        }
                    ]
                )
                summary["events"] += 1
            except Exception:
                pass

    guard_config_root = DATA_DIR / "state" / "guard_configs"
    watch_dirs = set()
    for path in guard_config_root.glob("*.json") if guard_config_root.exists() else []:
        config = _read_json(path, {})
        for item in config.get("monitor_roots") or []:
            if item:
                watch_dirs.add(item)
    if watch_dirs:
        update_global_config({"watch_dirs": sorted(watch_dirs)})
        summary["config_updated"] = 1

    if logger:
        logger.info("legacy state migrated: %s", summary)
    return summary
