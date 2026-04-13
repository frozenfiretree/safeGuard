import hashlib
import json
import logging
import os
import platform
import re
import socket
import sys
import uuid
from urllib.parse import urlparse
import winreg
from dataclasses import dataclass, field
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Iterable, List


AGENT_VERSION = "2.0.0"
SERVICE_NAME = "SafeGuardAgent"
SERVICE_DISPLAY_NAME = "SafeGuard Agent"
SERVICE_DESCRIPTION = "Collects file metadata and uploads files for server-side detection."

PROGRAM_DATA_DIR = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "SafeGuardAgent"
DEFAULT_SERVER_BASE = "http://192.168.175.1:8000"
INSTALL_CONFIG_PATH = Path(
    os.environ.get("SAFEGUARD_AGENT_SETTINGS_FILE", str(PROGRAM_DATA_DIR / "install_config.json"))
)


def load_install_settings() -> dict:
    try:
        if INSTALL_CONFIG_PATH.exists():
            data = json.loads(INSTALL_CONFIG_PATH.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


INSTALL_SETTINGS = load_install_settings()
SERVER_BASE = os.environ.get(
    "SAFEGUARD_SERVER_BASE",
    str(INSTALL_SETTINGS.get("server_base") or DEFAULT_SERVER_BASE),
).rstrip("/")
API_V1_BASE = f"{SERVER_BASE}/api/v1"
_parsed_server = urlparse(SERVER_BASE if "://" in SERVER_BASE else f"http://{SERVER_BASE}")
GRPC_UPLOAD_TARGET = os.environ.get(
    "SAFEGUARD_GRPC_UPLOAD_TARGET",
    f"{_parsed_server.hostname or '127.0.0.1'}:50051",
).strip()

REGISTER_URL = f"{API_V1_BASE}/agents/register"
AGENT_CONFIG_URL_TEMPLATE = f"{API_V1_BASE}/agents/{{agent_id}}/config"
HEARTBEAT_URL_TEMPLATE = f"{API_V1_BASE}/agents/{{agent_id}}/heartbeat"
UPLOAD_INIT_URL = f"{API_V1_BASE}/uploads/init"
UPLOAD_STATUS_URL_TEMPLATE = f"{API_V1_BASE}/uploads/{{session_id}}"
UPLOAD_CHUNK_URL_TEMPLATE = f"{API_V1_BASE}/uploads/{{session_id}}/chunks/{{index}}"
UPLOAD_COMPLETE_URL_TEMPLATE = f"{API_V1_BASE}/uploads/{{session_id}}/complete"
EVENT_BATCH_URL = f"{API_V1_BASE}/events/batch"
SCAN_COMPLETE_URL_TEMPLATE = f"{API_V1_BASE}/agents/{{agent_id}}/scan-complete"
UPGRADE_REPORT_URL_TEMPLATE = f"{API_V1_BASE}/agents/{{agent_id}}/upgrade-report"
UPGRADE_DOWNLOAD_URL_TEMPLATE = f"{API_V1_BASE}/upgrades/{{version}}/download"
ARTIFACT_URL_TEMPLATE = f"{SERVER_BASE}/api/artifacts/{{artifact_id}}"

WORK_DIR = Path(
    os.environ.get("SAFEGUARD_AGENT_WORKDIR", str(INSTALL_SETTINGS.get("work_dir") or PROGRAM_DATA_DIR))
)
LOG_DIR = WORK_DIR / "logs"
DB_PATH = WORK_DIR / "agent.db"
LOG_FILE = LOG_DIR / "agent.log"

DEFAULT_INCLUDE_EXTENSIONS = {
    ".txt", ".csv", ".doc", ".docx", ".pdf", ".xlsx", ".ppt", ".pptx",
    ".png", ".jpg", ".jpeg", ".bmp",
}
DEFAULT_EXCLUDE_PATHS = [
    r"C:\Windows",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\ProgramData\Microsoft",
    str(WORK_DIR),
]
TEMP_FILE_PATTERNS = [
    re.compile(r"^~\$.+", re.IGNORECASE),
    re.compile(r"^~lock\..+", re.IGNORECASE),
    re.compile(r".+\.tmp$", re.IGNORECASE),
    re.compile(r".+\.temp$", re.IGNORECASE),
]


@dataclass
class AgentRuntimeConfig:
    config_version: str = ""
    include_extensions: List[str] = field(default_factory=lambda: sorted(DEFAULT_INCLUDE_EXTENSIONS))
    exclude_paths: List[str] = field(default_factory=lambda: [normalize_path(x) for x in DEFAULT_EXCLUDE_PATHS])
    max_file_size_mb: int = 100
    scan_roots: List[str] = field(default_factory=list)
    watch_dirs: List[str] = field(default_factory=list)
    heartbeat_interval: int = 60
    config_pull_interval: int = 300
    debounce_seconds: float = 2.0
    write_stable_seconds: float = 1.0
    move_pair_window_seconds: float = 2.0
    upload_workers: int = 2
    queue_batch_size: int = 20
    chunk_size_bytes: int = 4 * 1024 * 1024
    event_batch_size: int = 50
    max_retries: int = 5
    usb_poll_interval: int = 30
    request_timeout: int = 20
    bootstrap_scan_enabled: bool = False
    upgrade: dict | None = None


def ensure_dirs():
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def setup_logging(name: str = "agent") -> logging.Logger:
    ensure_dirs()
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    if logger.handlers:
        return logger

    formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s")
    file_handler = RotatingFileHandler(LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
    file_handler.setFormatter(formatter)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger


def now_iso() -> str:
    from datetime import datetime

    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def normalize_path(value: str) -> str:
    return os.path.normcase(os.path.abspath(value))


def _user_profile_is_system(profile: Path) -> bool:
    return "systemprofile" in str(profile).lower()


def _user_special_dirs(folder_name: str) -> List[str]:
    candidates: List[Path] = []
    user_profile = Path(os.environ.get("USERPROFILE", Path.home()))
    if not _user_profile_is_system(user_profile):
        candidates.append(user_profile / folder_name)

    users_root = Path(r"C:\Users")
    if users_root.exists():
        for child in users_root.iterdir():
            if not child.is_dir():
                continue
            lowered = child.name.lower()
            if lowered in {"all users", "appdata", "default", "default user", "public", "wsiaccount"}:
                continue
            candidates.append(child / folder_name)

    results: List[str] = []
    seen = set()
    for path in candidates:
        normalized = normalize_path(str(path))
        if normalized in seen:
            continue
        seen.add(normalized)
        results.append(str(path))
    return results


def expand_config_paths(value: object) -> List[str]:
    raw = str(value or "").strip().strip('"')
    if not raw:
        return []
    expanded = os.path.expanduser(os.path.expandvars(raw))
    raw_upper = raw.upper()
    if "%USERPROFILE%" in raw_upper and "systemprofile" in expanded.lower():
        suffix = raw_upper.split("%USERPROFILE%", 1)[1].lstrip("\\/")
        suffix_lower = suffix.lower()
        if suffix_lower in {"downloads", "documents"}:
            return _user_special_dirs("Downloads" if suffix_lower == "downloads" else "Documents")
    return [expanded]


def get_mac_address() -> str:
    mac = uuid.getnode()
    return ":".join(("%012X" % mac)[i:i + 2] for i in range(0, 12, 2))


def get_primary_ip() -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "unknown"


def read_machine_guid() -> str:
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography")
        value, _ = winreg.QueryValueEx(key, "MachineGuid")
        winreg.CloseKey(key)
        return str(value)
    except Exception:
        return ""


def build_device_fingerprint() -> str:
    raw = "|".join([
        read_machine_guid(),
        get_mac_address(),
        platform.node(),
    ])
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()


def default_scan_roots() -> List[str]:
    roots = [r"C:\test"]
    roots.extend(_user_special_dirs("Downloads"))
    roots.extend(_user_special_dirs("Documents"))
    deduped = []
    seen = set()
    for item in roots:
        normalized = normalize_path(item)
        if normalized in seen:
            continue
        seen.add(normalized)
        deduped.append(item)
    return deduped


def is_temp_filename(name: str) -> bool:
    return any(pattern.match(name or "") for pattern in TEMP_FILE_PATTERNS)


def should_exclude_path(path: str, exclude_paths: Iterable[str]) -> bool:
    normalized = normalize_path(path)
    return any(normalized.startswith(normalize_path(item)) for item in exclude_paths if item)


def build_agent_identity(existing_agent_id: str | None = None) -> dict:
    return {
        "agent_id": existing_agent_id or build_device_fingerprint(),
        "hostname": socket.gethostname(),
        "mac": get_mac_address(),
        "ip": get_primary_ip(),
        "open_port": [],
        "os_type": platform.system(),
        "os_version": platform.version(),
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "agent_version": AGENT_VERSION,
        "device_fingerprint": build_device_fingerprint(),
    }


def parse_runtime_config(config_data: dict | None) -> AgentRuntimeConfig:
    config_data = config_data or {}
    scan_cfg = config_data.get("scan", {}) or {}
    guard_cfg = config_data.get("guard", {}) or {}

    include_extensions = (
        config_data.get("include_extensions")
        or scan_cfg.get("supported_extensions")
        or sorted(DEFAULT_INCLUDE_EXTENSIONS)
    )
    watch_dirs = list(config_data.get("watch_dirs") or guard_cfg.get("monitor_roots") or [])

    for item in guard_cfg.get("explicit_files") or []:
        try:
            parent = str(Path(item).resolve().parent)
        except Exception:
            parent = str(Path(item).parent)
        if parent and parent not in watch_dirs:
            watch_dirs.append(parent)

    scan_roots = []
    for item in config_data.get("scan_dirs") or []:
        scan_roots.extend(expand_config_paths(item))
    target_dir = scan_cfg.get("target_dir")
    for item in expand_config_paths(target_dir):
        if item not in scan_roots:
            scan_roots.append(item)
    expanded_watch_dirs = []
    for item in watch_dirs:
        for expanded in expand_config_paths(item):
            expanded_watch_dirs.append(expanded)
            if expanded not in scan_roots:
                scan_roots.append(expanded)
    watch_dirs = expanded_watch_dirs
    if not scan_roots:
        scan_roots = default_scan_roots()

    return AgentRuntimeConfig(
        config_version=str(config_data.get("config_version") or config_data.get("version") or ""),
        include_extensions=sorted({str(x).lower() for x in include_extensions if str(x).strip()}),
        exclude_paths=[
            normalize_path(x)
            for item in (config_data.get("exclude_paths") or DEFAULT_EXCLUDE_PATHS)
            for x in expand_config_paths(item)
            if str(x).strip()
        ],
        max_file_size_mb=int(config_data.get("max_file_size_mb") or scan_cfg.get("max_file_size_mb") or 100),
        scan_roots=scan_roots,
        watch_dirs=watch_dirs,
        heartbeat_interval=int(config_data.get("heartbeat_interval_sec") or 60),
        config_pull_interval=int(config_data.get("config_pull_interval_sec") or 300),
        debounce_seconds=float(config_data.get("debounce_seconds") or 2.0),
        write_stable_seconds=float(config_data.get("write_stable_seconds") or 1.0),
        move_pair_window_seconds=float(config_data.get("move_pair_window_seconds") or 2.0),
        queue_batch_size=int(config_data.get("queue_batch_size") or 20),
        event_batch_size=int(config_data.get("event_batch_size") or 50),
        chunk_size_bytes=int(config_data.get("chunk_size_bytes") or 4 * 1024 * 1024),
        upload_workers=int(config_data.get("upload_workers") or 2),
        usb_poll_interval=int(config_data.get("usb_poll_interval_sec") or 30),
        request_timeout=int(config_data.get("request_timeout_sec") or 20),
        max_retries=int(config_data.get("max_retries") or 5),
        bootstrap_scan_enabled=bool(scan_cfg.get("bootstrap_scan_enabled", False)),
        upgrade=config_data.get("upgrade"),
    )
