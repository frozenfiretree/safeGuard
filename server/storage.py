import hashlib
import shutil
import time
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import inspect, text

from config_app import (
    CHUNK_STORE_DIR,
    FILE_STORE_DIR,
    MINIO_ACCESS_KEY,
    MINIO_BUCKET,
    MINIO_ENDPOINT,
    MINIO_SECRET_KEY,
    MINIO_SECURE,
    REDIS_URL,
    REQUIRE_PRODUCTION_DEPS,
    TMP_DIR,
)
from models import Base, SessionLocal, engine

try:
    from minio import Minio
except Exception:
    Minio = None

try:
    import redis
except Exception:
    redis = None


class RedisCache:
    def __init__(self):
        self.client = None
        self.memory: dict[str, tuple[object, float | None]] = {}
        if redis and REDIS_URL:
            try:
                self.client = redis.from_url(REDIS_URL, decode_responses=True)
                self.client.ping()
            except Exception:
                self.client = None
        if REQUIRE_PRODUCTION_DEPS and not self.client:
            raise RuntimeError("生产模式要求 Redis 可用，请检查 SAFEGUARD_REDIS_URL")

    def _cleanup_memory(self):
        now = time.time()
        expired = [key for key, (_, expires_at) in self.memory.items() if expires_at and expires_at < now]
        for key in expired:
            self.memory.pop(key, None)

    def get(self, key: str):
        if self.client:
            return self.client.get(key)
        self._cleanup_memory()
        item = self.memory.get(key)
        return item[0] if item else None

    def setex(self, key: str, ttl: int, value: str):
        if self.client:
            self.client.setex(key, ttl, value)
            return
        self.memory[key] = (value, time.time() + ttl)

    def sadd(self, key: str, value: int):
        if self.client:
            self.client.sadd(key, value)
            return
        members, expires_at = self.memory.get(key, (set(), None))
        if not isinstance(members, set):
            members = set()
        members.add(int(value))
        self.memory[key] = (members, expires_at)

    def smembers(self, key: str):
        if self.client:
            values = self.client.smembers(key)
            return {int(x) for x in values}
        self._cleanup_memory()
        members, _ = self.memory.get(key, (set(), None))
        return {int(x) for x in members}

    def expire(self, key: str, ttl: int):
        if self.client:
            self.client.expire(key, ttl)
            return
        value, _ = self.memory.get(key, (set(), None))
        self.memory[key] = (value, time.time() + ttl)

    def setnx(self, key: str, value: str, ttl: int) -> bool:
        if self.client:
            if self.client.setnx(key, value):
                self.client.expire(key, ttl)
                return True
            return False
        self._cleanup_memory()
        if key in self.memory:
            return False
        self.memory[key] = (value, time.time() + ttl)
        return True

    def delete(self, key: str):
        if self.client:
            self.client.delete(key)
            return
        self.memory.pop(key, None)


class ObjectStorage:
    def __init__(self):
        self.client = None
        if Minio and MINIO_ENDPOINT:
            try:
                self.client = Minio(
                    MINIO_ENDPOINT,
                    access_key=MINIO_ACCESS_KEY,
                    secret_key=MINIO_SECRET_KEY,
                    secure=MINIO_SECURE,
                )
                if not self.client.bucket_exists(MINIO_BUCKET):
                    self.client.make_bucket(MINIO_BUCKET)
            except Exception:
                self.client = None
        if REQUIRE_PRODUCTION_DEPS and not self.client:
            raise RuntimeError("生产模式要求 MinIO 可用，请检查 SAFEGUARD_MINIO_* 配置")
        for path in [CHUNK_STORE_DIR, FILE_STORE_DIR, TMP_DIR]:
            path.mkdir(parents=True, exist_ok=True)

    def _local_path(self, object_name: str) -> Path:
        return TMP_DIR / object_name.replace("/", "_")

    def put_bytes(self, object_name: str, data: bytes):
        if self.client:
            from io import BytesIO
            self.client.put_object(MINIO_BUCKET, object_name, BytesIO(data), len(data))
            return
        path = self._local_path(object_name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def get_bytes(self, object_name: str) -> bytes:
        if self.client:
            resp = self.client.get_object(MINIO_BUCKET, object_name)
            try:
                return resp.read()
            finally:
                resp.close()
                resp.release_conn()
        return self._local_path(object_name).read_bytes()

    def exists(self, object_name: str) -> bool:
        if self.client:
            try:
                self.client.stat_object(MINIO_BUCKET, object_name)
                return True
            except Exception:
                return False
        return self._local_path(object_name).exists()

    def delete(self, object_name: str):
        if self.client:
            try:
                self.client.remove_object(MINIO_BUCKET, object_name)
            except Exception:
                pass
            return
        path = self._local_path(object_name)
        if path.exists():
            path.unlink()

    def compose_chunks(self, session_id: str, total_chunks: int, object_name: str):
        if self.client:
            from minio.commonconfig import ComposeSource
            sources = [ComposeSource(MINIO_BUCKET, f"uploads/{session_id}/chunk_{idx}") for idx in range(total_chunks)]
            self.client.compose_object(MINIO_BUCKET, object_name, sources)
            return
        target = self._local_path(object_name)
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "wb") as out:
            for idx in range(total_chunks):
                out.write(self.get_bytes(f"uploads/{session_id}/chunk_{idx}"))

    def upload_final_file(self, file_hash: str, src_object_name: str) -> str:
        object_name = f"files/{file_hash[:2]}/{file_hash}"
        if self.client:
            data = self.get_bytes(src_object_name)
            self.put_bytes(object_name, data)
        else:
            src = self._local_path(src_object_name)
            dst = self._local_path(object_name)
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst)
        return object_name

    def download_to_temp(self, object_name: str, suffix: str = "") -> Path:
        suffix = suffix or ""
        if suffix and not suffix.startswith("."):
            suffix = f".{suffix}"
        dst = TMP_DIR / f"download_{hashlib.sha1(object_name.encode()).hexdigest()}{suffix}"
        dst.write_bytes(self.get_bytes(object_name))
        return dst


redis_cache = RedisCache()
object_storage = ObjectStorage()


def init_db():
    Base.metadata.create_all(bind=engine)
    _ensure_schema_columns()


def _ensure_schema_columns():
    inspector = inspect(engine)
    if "file_change_events" not in inspector.get_table_names():
        return
    existing = {col["name"] for col in inspector.get_columns("file_change_events")}
    ddl = []
    if "old_path" not in existing:
        ddl.append("ALTER TABLE file_change_events ADD COLUMN old_path TEXT")
    if "new_path" not in existing:
        ddl.append("ALTER TABLE file_change_events ADD COLUMN new_path TEXT")
    if "event_details" not in existing:
        ddl.append("ALTER TABLE file_change_events ADD COLUMN event_details JSON")
    if not ddl:
        return
    with engine.begin() as conn:
        for stmt in ddl:
            conn.execute(text(stmt))


@contextmanager
def db_session():
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
