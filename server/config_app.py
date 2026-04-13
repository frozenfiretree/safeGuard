import logging
import os
from enum import Enum
from logging.handlers import RotatingFileHandler
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
LOG_DIR = BASE_DIR / "logs"
OBJECT_STORE_DIR = DATA_DIR / "object_store"
CHUNK_STORE_DIR = OBJECT_STORE_DIR / "uploads"
FILE_STORE_DIR = OBJECT_STORE_DIR / "files"
UPGRADE_STORE_DIR = OBJECT_STORE_DIR / "upgrades"
TMP_DIR = DATA_DIR / "tmp_uploads_v1"
DB_PATH = DATA_DIR / "server_v2.db"

DATABASE_URL = os.environ.get("SAFEGUARD_DATABASE_URL", f"sqlite:///{DB_PATH.as_posix()}")
CELERY_BROKER_URL = os.environ.get("SAFEGUARD_CELERY_BROKER_URL", "memory://")
CELERY_RESULT_BACKEND = os.environ.get("SAFEGUARD_CELERY_RESULT_BACKEND", "cache+memory://")
REDIS_URL = os.environ.get("SAFEGUARD_REDIS_URL", "")
MINIO_ENDPOINT = os.environ.get("SAFEGUARD_MINIO_ENDPOINT", "")
MINIO_ACCESS_KEY = os.environ.get("SAFEGUARD_MINIO_ACCESS_KEY", "")
MINIO_SECRET_KEY = os.environ.get("SAFEGUARD_MINIO_SECRET_KEY", "")
MINIO_SECURE = os.environ.get("SAFEGUARD_MINIO_SECURE", "false").lower() == "true"
MINIO_BUCKET = os.environ.get("SAFEGUARD_MINIO_BUCKET", "safeguard")
OCR_SERVICE_URL = os.environ.get("SAFEGUARD_OCR_SERVICE_URL", "http://127.0.0.1:8010").rstrip("/")
OCR_SERVICE_TIMEOUT_SECONDS = int(os.environ.get("SAFEGUARD_OCR_SERVICE_TIMEOUT_SECONDS", "60"))
GRPC_UPLOAD_HOST = os.environ.get("SAFEGUARD_GRPC_UPLOAD_HOST", "0.0.0.0").strip() or "0.0.0.0"
GRPC_UPLOAD_PORT = int(os.environ.get("SAFEGUARD_GRPC_UPLOAD_PORT", "50051"))
REQUIRE_PRODUCTION_DEPS = os.environ.get("SAFEGUARD_REQUIRE_PRODUCTION_DEPS", "false").lower() in {"1", "true", "yes", "on"}

API_PREFIX = "/api/v1"
APP_VERSION = "2.0.0"
UPLOAD_CHUNK_SIZE = 5 * 1024 * 1024
UPLOAD_SESSION_TTL_SECONDS = 24 * 3600
TOKEN_TTL_SECONDS = 7 * 24 * 3600
TOKEN_REFRESH_THRESHOLD_SECONDS = 24 * 3600
HEARTBEAT_THROTTLE_SECONDS = 5
HEARTBEAT_OFFLINE_SECONDS = 300
TIMESTAMP_SKEW_SECONDS = 300
NON_SENSITIVE_TTL_SECONDS = 7 * 24 * 3600
UPLOAD_CLEANUP_INTERVAL_SECONDS = 600
OFFLINE_SWEEP_INTERVAL_SECONDS = 120
NON_SENSITIVE_CLEANUP_INTERVAL_SECONDS = 3600


class AgentStatus(str, Enum):
    REGISTERED = "REGISTERED"
    ONLINE = "ONLINE"
    OFFLINE = "OFFLINE"
    UNINSTALLED = "UNINSTALLED"


class UploadSessionStatus(str, Enum):
    CREATED = "CREATED"
    UPLOADING = "UPLOADING"
    COMPLETING = "COMPLETING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"


class FileDetectionStatus(str, Enum):
    RECEIVED = "RECEIVED"
    PARSING = "PARSING"
    PARSED = "PARSED"
    PARSE_FAILED = "PARSE_FAILED"
    RULE_CHECKING = "RULE_CHECKING"
    SENSITIVE = "SENSITIVE"
    NON_SENSITIVE = "NON_SENSITIVE"
    RULE_MISS_PENDING = "RULE_MISS_PENDING"


class EventType(str, Enum):
    FILE_CHANGED = "file_changed"
    USB_CHANGED = "usb_changed"


def ensure_app_dirs():
    for path in [DATA_DIR, LOG_DIR, OBJECT_STORE_DIR, CHUNK_STORE_DIR, FILE_STORE_DIR, UPGRADE_STORE_DIR, TMP_DIR]:
        path.mkdir(parents=True, exist_ok=True)


def setup_app_logger(name: str = "server_v2") -> logging.Logger:
    ensure_app_dirs()
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    if logger.handlers:
        return logger

    formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s")
    file_handler = RotatingFileHandler(LOG_DIR / "server_v2.log", maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8")
    file_handler.setFormatter(formatter)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger


def validate_production_settings():
    if not REQUIRE_PRODUCTION_DEPS:
        return
    problems = []
    if not DATABASE_URL.lower().startswith("postgresql"):
        problems.append("SAFEGUARD_DATABASE_URL must use PostgreSQL")
    if not CELERY_BROKER_URL.lower().startswith(("redis://", "rediss://")):
        problems.append("SAFEGUARD_CELERY_BROKER_URL must use Redis")
    if not CELERY_RESULT_BACKEND.lower().startswith(("redis://", "rediss://")):
        problems.append("SAFEGUARD_CELERY_RESULT_BACKEND must use Redis")
    if not REDIS_URL.lower().startswith(("redis://", "rediss://")):
        problems.append("SAFEGUARD_REDIS_URL must use Redis")
    if not MINIO_ENDPOINT:
        problems.append("SAFEGUARD_MINIO_ENDPOINT is required")
    if problems:
        raise RuntimeError("Production config validation failed: " + "; ".join(problems))


def get_admin_token() -> str:
    return os.environ.get("SAFEGUARD_ADMIN_TOKEN", "").strip()


def get_admin_basic_user() -> str:
    return os.environ.get("SAFEGUARD_ADMIN_USER", "admin").strip() or "admin"


def get_admin_basic_password() -> str:
    return os.environ.get("SAFEGUARD_ADMIN_PASSWORD", "").strip()
