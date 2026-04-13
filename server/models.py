import time
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field
from sqlalchemy import JSON, Boolean, Float, Integer, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from config_app import DATABASE_URL


class Base(DeclarativeBase):
    pass


engine = create_engine(DATABASE_URL, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)


class Agent(Base):
    __tablename__ = "agents"

    agent_id: Mapped[str] = mapped_column(Text, primary_key=True)
    device_fingerprint: Mapped[str] = mapped_column(Text, unique=True, index=True)
    hostname: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ip: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    os_version: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    mac_address: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    agent_version: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    token_hash: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    token_expires_at: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    status: Mapped[str] = mapped_column(Text, default="REGISTERED")
    config_version: Mapped[int] = mapped_column(Integer, default=1)
    last_heartbeat: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    scan_progress: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[float] = mapped_column(Float, default=lambda: time.time())
    updated_at: Mapped[float] = mapped_column(Float, default=lambda: time.time())


class FileRecord(Base):
    __tablename__ = "files"

    file_hash: Mapped[str] = mapped_column(Text, primary_key=True)
    file_name: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    file_type: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    file_size: Mapped[int] = mapped_column(Integer, default=0)
    store_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    detection_status: Mapped[str] = mapped_column(Text, default="RECEIVED")
    is_sensitive: Mapped[bool] = mapped_column(Boolean, default=False)
    risk_level: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    explanation_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[float] = mapped_column(Float, default=lambda: time.time())
    updated_at: Mapped[float] = mapped_column(Float, default=lambda: time.time())


class FileVersion(Base):
    __tablename__ = "file_versions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_id: Mapped[str] = mapped_column(Text, index=True)
    file_path: Mapped[str] = mapped_column(Text, index=True)
    file_hash: Mapped[str] = mapped_column(Text, index=True)
    is_current: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[float] = mapped_column(Float, default=lambda: time.time())


class UploadSession(Base):
    __tablename__ = "upload_sessions"

    session_id: Mapped[str] = mapped_column(Text, primary_key=True)
    agent_id: Mapped[str] = mapped_column(Text, index=True)
    file_hash: Mapped[str] = mapped_column(Text, index=True)
    file_name: Mapped[str] = mapped_column(Text)
    file_type: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    file_path: Mapped[str] = mapped_column(Text)
    file_size: Mapped[int] = mapped_column(Integer)
    total_chunks: Mapped[int] = mapped_column(Integer)
    uploaded_chunks: Mapped[List[int]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(Text, default="CREATED")
    expires_at: Mapped[float] = mapped_column(Float)
    created_at: Mapped[float] = mapped_column(Float, default=lambda: time.time())
    updated_at: Mapped[float] = mapped_column(Float, default=lambda: time.time())


class FileChangeEvent(Base):
    __tablename__ = "file_change_events"

    event_id: Mapped[str] = mapped_column(Text, primary_key=True)
    agent_id: Mapped[str] = mapped_column(Text, index=True)
    event_type: Mapped[str] = mapped_column(Text)
    file_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    old_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    new_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    old_hash: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    new_hash: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    file_size: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    timestamp: Mapped[float] = mapped_column(Float, index=True)
    usb_context: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    event_details: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[float] = mapped_column(Float, default=lambda: time.time())


class TrackedFile(Base):
    __tablename__ = "tracked_files"

    tracked_file_id: Mapped[str] = mapped_column(Text, primary_key=True)
    agent_id: Mapped[str] = mapped_column(Text, index=True)
    file_key: Mapped[str] = mapped_column(Text, index=True)
    current_path: Mapped[str] = mapped_column(Text, index=True)
    current_name: Mapped[str] = mapped_column(Text)
    original_path: Mapped[str] = mapped_column(Text)
    original_name: Mapped[str] = mapped_column(Text)
    file_type: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    sensitive_level: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    first_seen_at: Mapped[float] = mapped_column(Float, index=True)
    last_seen_at: Mapped[float] = mapped_column(Float, index=True)
    deleted_at: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    latest_version_no: Mapped[int] = mapped_column(Integer, default=0)
    latest_version_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    rename_count: Mapped[int] = mapped_column(Integer, default=0)
    modify_count: Mapped[int] = mapped_column(Integer, default=0)


class TrackedFileVersion(Base):
    __tablename__ = "tracked_file_versions"

    version_id: Mapped[str] = mapped_column(Text, primary_key=True)
    tracked_file_id: Mapped[str] = mapped_column(Text, index=True)
    version_no: Mapped[int] = mapped_column(Integer, index=True)
    snapshot_time: Mapped[float] = mapped_column(Float, index=True)
    event_type: Mapped[str] = mapped_column(Text, index=True)
    path_at_that_time: Mapped[str] = mapped_column(Text)
    name_at_that_time: Mapped[str] = mapped_column(Text)
    stored_file_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    content_hash: Mapped[Optional[str]] = mapped_column(Text, nullable=True, index=True)
    prev_version_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    change_summary: Mapped[str] = mapped_column(Text, default="")
    change_detail_json: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    highlight_artifact_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    diff_artifact_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    sensitive_hits: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=list)
    is_snapshot_retained: Mapped[bool] = mapped_column(Boolean, default=True)
    artifact_type: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[float] = mapped_column(Float, default=lambda: time.time())


class TrackedFileEvent(Base):
    __tablename__ = "tracked_file_events"

    event_id: Mapped[str] = mapped_column(Text, primary_key=True)
    tracked_file_id: Mapped[str] = mapped_column(Text, index=True)
    event_time: Mapped[float] = mapped_column(Float, index=True)
    event_type: Mapped[str] = mapped_column(Text, index=True)
    old_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    new_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    old_name: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    new_name: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    description: Mapped[str] = mapped_column(Text, default="")
    raw_event_json: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    version_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[float] = mapped_column(Float, default=lambda: time.time())


class TaskFailure(Base):
    __tablename__ = "task_failures"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_name: Mapped[str] = mapped_column(Text)
    task_payload: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    error_message: Mapped[str] = mapped_column(Text)
    created_at: Mapped[float] = mapped_column(Float, default=lambda: time.time())


class AgentConfig(Base):
    __tablename__ = "agent_configs"

    config_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scope: Mapped[str] = mapped_column(Text, default="global")
    agent_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True, index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    config_data: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[float] = mapped_column(Float, default=lambda: time.time())
    updated_at: Mapped[float] = mapped_column(Float, default=lambda: time.time())


class ParseResult(Base):
    __tablename__ = "parse_results"

    file_hash: Mapped[str] = mapped_column(Text, primary_key=True)
    parse_status: Mapped[str] = mapped_column(Text)
    result_data: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[float] = mapped_column(Float, default=lambda: time.time())
    updated_at: Mapped[float] = mapped_column(Float, default=lambda: time.time())


class RuleHit(Base):
    __tablename__ = "rule_hits"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    file_hash: Mapped[str] = mapped_column(Text, index=True)
    rule_id: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(Text)
    match_positions: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[float] = mapped_column(Float, default=lambda: time.time())


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    rule_id: Mapped[str] = mapped_column(Text, primary_key=True)
    rule_name: Mapped[str] = mapped_column(Text, index=True)
    rule_type: Mapped[str] = mapped_column(Text, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    priority: Mapped[int] = mapped_column(Integer, default=100, index=True)
    config: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[float] = mapped_column(Float, default=lambda: time.time())
    updated_at: Mapped[float] = mapped_column(Float, default=lambda: time.time())


class AgentRegisterRequest(BaseModel):
    device_fingerprint: str
    hostname: Optional[str] = None
    ip: Optional[str] = None
    os_version: Optional[str] = None
    agent_version: Optional[str] = None
    mac_address: Optional[str] = None


class AgentRegisterResponse(BaseModel):
    agent_id: str
    token: str
    token_expires: float
    config_version: int


class AgentHeartbeatRequest(BaseModel):
    timestamp: float
    agent_version: str
    config_version: int
    scan_status: str
    pending_task_count: int = 0


class UploadInitRequest(BaseModel):
    file_hash: str
    file_size: int
    total_chunks: int
    file_name: str
    file_type: Optional[str] = None
    agent_id: str
    file_path: str


class UploadInitResponse(BaseModel):
    status: str
    session_id: Optional[str] = None
    file_id: Optional[str] = None
    uploaded_chunks: List[int] = Field(default_factory=list)


class UploadStatusResponse(BaseModel):
    session_id: str
    status: str
    uploaded_chunks: List[int] = Field(default_factory=list)
    total_chunks: int


class UploadCompleteResponse(BaseModel):
    status: str
    session_id: str
    file_hash: str
    task_id: Optional[str] = None


class AgentConfigResponse(BaseModel):
    config_version: int
    scan_dirs: List[str] = Field(default_factory=list)
    include_extensions: List[str] = Field(default_factory=list)
    exclude_paths: List[str] = Field(default_factory=list)
    max_file_size_mb: int = 100
    heartbeat_interval_sec: int = 60
    watch_dirs: List[str] = Field(default_factory=list)
    upgrade: Optional[Dict[str, Any]] = None


class BatchEventItem(BaseModel):
    event_id: str
    event_type: str
    file_path: Optional[str] = None
    old_path: Optional[str] = None
    new_path: Optional[str] = None
    old_hash: Optional[str] = None
    new_hash: Optional[str] = None
    file_size: Optional[int] = None
    timestamp: float
    agent_id: str
    usb_context: Dict[str, Any] = Field(default_factory=dict)
    event_details: Dict[str, Any] = Field(default_factory=dict)


class EventsBatchRequest(BaseModel):
    events: List[BatchEventItem] = Field(default_factory=list)


class ScanCompleteRequest(BaseModel):
    total_files: int = 0
    scanned: int = 0
    uploaded: int = 0
    skipped: int = 0
    errors: int = 0
    duration_sec: float = 0


class UpgradeReportRequest(BaseModel):
    old_version: Optional[str] = None
    new_version: str
    success: bool
    error_message: Optional[str] = None


class AdminConfigUpdateRequest(BaseModel):
    scan_dirs: Optional[List[str]] = None
    include_extensions: Optional[List[str]] = None
    exclude_paths: Optional[List[str]] = None
    max_file_size_mb: Optional[int] = None
    heartbeat_interval_sec: Optional[int] = None
    watch_dirs: Optional[List[str]] = None
    upgrade: Optional[Dict[str, Any]] = None


class DetectionRuleCreateRequest(BaseModel):
    rule_name: str
    rule_type: str
    enabled: bool = True
    description: Optional[str] = None
    priority: int = 100
    config: Dict[str, Any] = Field(default_factory=dict)


class DetectionRuleUpdateRequest(BaseModel):
    rule_name: Optional[str] = None
    rule_type: Optional[str] = None
    enabled: Optional[bool] = None
    description: Optional[str] = None
    priority: Optional[int] = None
    config: Optional[Dict[str, Any]] = None
