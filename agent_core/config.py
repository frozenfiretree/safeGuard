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
from typing import Any, Iterable, List, Sequence


AGENT_VERSION = "2.0.0"
SERVICE_NAME = "SafeGuardAgent"
SERVICE_DISPLAY_NAME = "SafeGuard Agent"
SERVICE_DESCRIPTION = "Collects file metadata and uploads files for server-side detection."

PROGRAM_DATA_DIR = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "SafeGuardAgent"
DEFAULT_SERVER_BASE = "http://192.168.175.1:8000"


@dataclass
class AgentBaseConfig:
    server_base: str
    grpc_upload_target: str
    work_dir: Path
    install_config_path: Path
    packaged_defaults_path: Path
    field_sources: dict[str, str] = field(default_factory=dict)
    conflicts: list[dict[str, Any]] = field(default_factory=list)

    def as_safe_dict(self) -> dict:
        return {
            "server_base": self.server_base,
            "grpc_upload_target": self.grpc_upload_target,
            "work_dir": str(self.work_dir),
            "install_config_path": str(self.install_config_path),
            "packaged_defaults_path": str(self.packaged_defaults_path),
            "field_sources": dict(self.field_sources),
            "conflicts": list(self.conflicts),
        }


def _service_exe_path() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve()
    return Path(__file__).resolve().parents[1] / "agent.py"


def _packaged_defaults_path() -> Path:
    return _service_exe_path().with_name("agent-install.json")


def _read_json_settings(path: Path) -> dict:
    try:
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def _cli_options(argv: Sequence[str] | None = None) -> dict[str, str]:
    argv = list(sys.argv[1:] if argv is None else argv)
    result: dict[str, str] = {}
    flag_map = {
        "--server-base": "server_base",
        "--work-dir": "work_dir",
        "--grpc-upload-target": "grpc_upload_target",
        "--settings-file": "install_config_path",
    }
    index = 0
    while index < len(argv):
        item = argv[index]
        if item in flag_map and index + 1 < len(argv):
            result[flag_map[item]] = argv[index + 1]
            index += 2
            continue
        index += 1
    return result


def _pick_setting(
    field: str,
    candidates: list[tuple[str, Any]],
    default: Any,
) -> tuple[Any, str, list[dict[str, Any]]]:
    present = [(source, value) for source, value in candidates if value not in (None, "")]
    if not present:
        return default, "default", []
    chosen_source, chosen_value = present[0]
    conflicts = []
    for source, value in present[1:]:
        if str(value) != str(chosen_value):
            conflicts.append(
                {
                    "field": field,
                    "effective_source": chosen_source,
                    "ignored_source": source,
                    "effective_value": str(chosen_value),
                    "ignored_value": str(value),
                }
            )
    return chosen_value, chosen_source, conflicts


def _default_grpc_target(server_base: str) -> str:
    parsed_server = urlparse(server_base if "://" in server_base else f"http://{server_base}")
    return f"{parsed_server.hostname or '127.0.0.1'}:50051"


def resolve_agent_base_config(argv: Sequence[str] | None = None) -> AgentBaseConfig:
    cli = _cli_options(argv)
    default_install_path = PROGRAM_DATA_DIR / "install_config.json"
    install_config_path = Path(
        cli.get("install_config_path")
        or os.environ.get("SAFEGUARD_AGENT_SETTINGS_FILE")
        or default_install_path
    )
    install_settings = _read_json_settings(install_config_path)
    packaged_defaults_path = _packaged_defaults_path()
    packaged_settings = _read_json_settings(packaged_defaults_path)

    field_sources: dict[str, str] = {
        "install_config_path": "cli" if cli.get("install_config_path") else ("env" if os.environ.get("SAFEGUARD_AGENT_SETTINGS_FILE") else "default"),
        "packaged_defaults_path": "default",
    }
    conflicts: list[dict[str, Any]] = []

    server_base, source, found_conflicts = _pick_setting(
        "server_base",
        [
            ("cli", cli.get("server_base")),
            ("env", os.environ.get("SAFEGUARD_SERVER_BASE")),
            ("install_config", install_settings.get("server_base")),
            ("packaged_defaults", packaged_settings.get("server_base")),
        ],
        DEFAULT_SERVER_BASE,
    )
    server_base = str(server_base).rstrip("/")
    field_sources["server_base"] = source
    conflicts.extend(found_conflicts)

    work_dir, source, found_conflicts = _pick_setting(
        "work_dir",
        [
            ("cli", cli.get("work_dir")),
            ("env", os.environ.get("SAFEGUARD_AGENT_WORKDIR")),
            ("install_config", install_settings.get("work_dir")),
            ("packaged_defaults", packaged_settings.get("work_dir")),
        ],
        str(PROGRAM_DATA_DIR),
    )
    work_dir = Path(str(work_dir))
    field_sources["work_dir"] = source
    conflicts.extend(found_conflicts)

    grpc_upload_target, source, found_conflicts = _pick_setting(
        "grpc_upload_target",
        [
            ("cli", cli.get("grpc_upload_target")),
            ("env", os.environ.get("SAFEGUARD_GRPC_UPLOAD_TARGET")),
            ("install_config", install_settings.get("grpc_upload_target")),
            ("packaged_defaults", packaged_settings.get("grpc_upload_target")),
        ],
        _default_grpc_target(server_base),
    )
    grpc_upload_target = str(grpc_upload_target).strip()
    field_sources["grpc_upload_target"] = source
    conflicts.extend(found_conflicts)

    return AgentBaseConfig(
        server_base=server_base,
        grpc_upload_target=grpc_upload_target,
        work_dir=work_dir,
        install_config_path=install_config_path,
        packaged_defaults_path=packaged_defaults_path,
        field_sources=field_sources,
        conflicts=conflicts,
    )


EFFECTIVE_AGENT_CONFIG = resolve_agent_base_config()
INSTALL_CONFIG_PATH = EFFECTIVE_AGENT_CONFIG.install_config_path
INSTALL_SETTINGS = _read_json_settings(INSTALL_CONFIG_PATH)
SERVER_BASE = EFFECTIVE_AGENT_CONFIG.server_base
API_V1_BASE = f"{SERVER_BASE}/api/v1"
GRPC_UPLOAD_TARGET = EFFECTIVE_AGENT_CONFIG.grpc_upload_target

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

WORK_DIR = EFFECTIVE_AGENT_CONFIG.work_dir
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
    chunk_size_bytes: int = 3 * 1024 * 1024
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


def agent_config_diagnostics() -> dict:
    return EFFECTIVE_AGENT_CONFIG.as_safe_dict()


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
        chunk_size_bytes=int(config_data.get("chunk_size_bytes") or 3 * 1024 * 1024),
        upload_workers=int(config_data.get("upload_workers") or 2),
        usb_poll_interval=int(config_data.get("usb_poll_interval_sec") or 30),
        request_timeout=int(config_data.get("request_timeout_sec") or 20),
        max_retries=int(config_data.get("max_retries") or 5),
        bootstrap_scan_enabled=bool(scan_cfg.get("bootstrap_scan_enabled", False)),
        upgrade=config_data.get("upgrade"),
    )
