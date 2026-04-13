import json
import shutil
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import DB_PATH, WORK_DIR, now_iso


class AgentStore:
    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_db(self):
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS file_baseline (
                    file_path TEXT PRIMARY KEY,
                    file_hash TEXT NOT NULL,
                    file_size INTEGER,
                    mtime REAL,
                    uploaded INTEGER DEFAULT 0,
                    last_seen TEXT
                );

                CREATE TABLE IF NOT EXISTS task_queue (
                    task_id TEXT PRIMARY KEY,
                    task_type TEXT NOT NULL,
                    status TEXT DEFAULT 'PENDING',
                    payload TEXT NOT NULL,
                    retry_count INTEGER DEFAULT 0,
                    max_retries INTEGER DEFAULT 5,
                    last_error TEXT,
                    created_at TEXT,
                    updated_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_queue_status_type ON task_queue(status, task_type);

                CREATE TABLE IF NOT EXISTS agent_state (
                    key TEXT PRIMARY KEY,
                    value TEXT
                );
                """
            )

    def recover_if_needed(self):
        try:
            with self._connect() as conn:
                conn.execute("SELECT 1")
        except sqlite3.DatabaseError:
            backup = self.db_path.with_suffix(".corrupt")
            try:
                if self.db_path.exists():
                    shutil.move(str(self.db_path), str(backup))
            finally:
                self._init_db()
                self.set_json_state("recovery_required", True)
                self.set_json_state("last_scan_path", None)

    def set_state(self, key: str, value: str):
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO agent_state(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    def get_state(self, key: str, default: Optional[str] = None) -> Optional[str]:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT value FROM agent_state WHERE key=?", (key,)).fetchone()
            return row["value"] if row else default

    def set_json_state(self, key: str, value: Any):
        self.set_state(key, json.dumps(value, ensure_ascii=False))

    def get_json_state(self, key: str, default: Any = None) -> Any:
        raw = self.get_state(key)
        if raw is None:
            return default
        try:
            return json.loads(raw)
        except Exception:
            return default

    def upsert_baseline(
        self,
        *,
        file_path: str,
        file_hash: str,
        file_size: int,
        mtime: float,
        uploaded: int = 0,
    ):
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO file_baseline(file_path, file_hash, file_size, mtime, uploaded, last_seen)
                VALUES(?, ?, ?, ?, ?, ?)
                ON CONFLICT(file_path) DO UPDATE SET
                    file_hash=excluded.file_hash,
                    file_size=excluded.file_size,
                    mtime=excluded.mtime,
                    uploaded=excluded.uploaded,
                    last_seen=excluded.last_seen
                """,
                (file_path, file_hash, file_size, mtime, uploaded, now_iso()),
            )

    def delete_baseline(self, file_path: str):
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM file_baseline WHERE file_path=?", (file_path,))

    def get_baseline(self, file_path: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM file_baseline WHERE file_path=?", (file_path,)).fetchone()
            return dict(row) if row else None

    def find_paths_by_hash(self, file_hash: str, exclude_path: Optional[str] = None) -> List[Dict[str, Any]]:
        if not file_hash:
            return []
        sql = "SELECT * FROM file_baseline WHERE file_hash=?"
        params: List[Any] = [file_hash]
        if exclude_path:
            sql += " AND file_path<>?"
            params.append(exclude_path)
        sql += " ORDER BY last_seen DESC"
        with self._lock, self._connect() as conn:
            rows = conn.execute(sql, tuple(params)).fetchall()
            return [dict(row) for row in rows]

    def mark_uploaded(self, file_path: str, file_hash: str):
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE file_baseline SET uploaded=1, file_hash=?, last_seen=? WHERE file_path=?",
                (file_hash, now_iso(), file_path),
            )

    def enqueue_task(
        self,
        *,
        task_id: str,
        task_type: str,
        payload: Dict[str, Any],
        max_retries: int = 5,
    ) -> bool:
        now = now_iso()
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                """
                INSERT OR IGNORE INTO task_queue(task_id, task_type, status, payload, retry_count, max_retries, created_at, updated_at)
                VALUES(?, ?, 'PENDING', ?, 0, ?, ?, ?)
                """,
                (task_id, task_type, json.dumps(payload, ensure_ascii=False), max_retries, now, now),
            )
            return cur.rowcount > 0

    def fetch_pending_tasks(self, limit: int, task_type: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM task_queue WHERE status='PENDING'"
        params: List[Any] = []
        if task_type:
            sql += " AND task_type=?"
            params.append(task_type)
        sql += " ORDER BY created_at ASC LIMIT ?"
        params.append(limit)
        with self._lock, self._connect() as conn:
            rows = conn.execute(sql, tuple(params)).fetchall()
            return [dict(row) for row in rows]

    def claim_task(self, task_id: str) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "UPDATE task_queue SET status='IN_PROGRESS', updated_at=? WHERE task_id=? AND status='PENDING'",
                (now_iso(), task_id),
            )
            return cur.rowcount > 0

    def complete_task(self, task_id: str):
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE task_queue SET status='DONE', updated_at=?, last_error=NULL WHERE task_id=?",
                (now_iso(), task_id),
            )

    def retry_task(self, task_id: str, error: str):
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT retry_count, max_retries FROM task_queue WHERE task_id=?",
                (task_id,),
            ).fetchone()
            if not row:
                return
            retry_count = int(row["retry_count"] or 0) + 1
            max_retries = int(row["max_retries"] or 5)
            next_status = "FAILED" if retry_count >= max_retries else "PENDING"
            conn.execute(
                "UPDATE task_queue SET status=?, retry_count=?, updated_at=?, last_error=? WHERE task_id=?",
                (next_status, retry_count, now_iso(), error[:2000], task_id),
            )

    def pending_task_count(self) -> int:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT COUNT(1) AS c FROM task_queue WHERE status='PENDING'").fetchone()
            return int(row["c"] or 0)

    def cleanup_tasks(self):
        with self._lock, self._connect() as conn:
            conn.execute(
                "DELETE FROM task_queue WHERE status='DONE' AND updated_at < ?",
                (self._task_cutoff(days=3),),
            )
            conn.execute(
                "DELETE FROM task_queue WHERE status='FAILED' AND updated_at < ?",
                (self._task_cutoff(days=7),),
            )

    def fetch_claimed_tasks(self, task_ids: List[str]) -> List[Dict[str, Any]]:
        if not task_ids:
            return []
        placeholders = ",".join("?" for _ in task_ids)
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM task_queue WHERE task_id IN ({placeholders}) ORDER BY created_at ASC",
                tuple(task_ids),
            ).fetchall()
            return [dict(row) for row in rows]

    def reset_in_progress_tasks(self):
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE task_queue SET status='PENDING', updated_at=? WHERE status='IN_PROGRESS'",
                (now_iso(),),
            )

    def set_current_state(self, state: str):
        self.set_state("current_state", state)

    def get_current_state(self) -> str:
        return self.get_state("current_state", "STARTING") or "STARTING"

    def set_scan_checkpoint(self, path: Optional[str]):
        self.set_json_state("last_scan_path", path)

    def get_scan_checkpoint(self) -> Optional[str]:
        return self.get_json_state("last_scan_path", None)

    def set_scan_completed(self, done: bool):
        self.set_json_state("scan_completed", bool(done))

    def is_scan_completed(self) -> bool:
        return bool(self.get_json_state("scan_completed", False))

    def _task_cutoff(self, days: int) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - days * 86400))
