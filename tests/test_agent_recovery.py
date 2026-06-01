import sqlite3
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _queue_rows(db_path: Path):
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM task_queue ORDER BY created_at ASC").fetchall()
        return [dict(row) for row in rows]


class AgentUploadRecoveryTests(unittest.TestCase):
    def test_initial_scan_requeues_same_hash_when_baseline_not_uploaded(self):
        from agent_core.config import AgentRuntimeConfig, normalize_path, sha256_of_file
        from agent_core.scanner import AgentScanner, FileSnapshot
        from agent_core.store import AgentStore

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            root = Path(tmp)
            db_path = root / "agent.db"
            scan_root = root / "scan"
            scan_root.mkdir()
            sample = scan_root / "secret.txt"
            sample.write_text("pending upload", encoding="utf-8")
            file_hash = sha256_of_file(sample)
            normalized = normalize_path(str(sample))

            store = AgentStore(db_path)
            store.upsert_baseline(
                file_path=normalized,
                file_hash=file_hash,
                file_size=sample.stat().st_size,
                mtime=sample.stat().st_mtime,
                uploaded=0,
            )
            runtime_config = AgentRuntimeConfig(
                scan_roots=[str(scan_root)],
                watch_dirs=[],
                include_extensions=[".txt"],
                exclude_paths=[],
                max_retries=3,
            )
            scanner = AgentScanner(store, mock.Mock(), runtime_config)

            with mock.patch.object(scanner, "_wait_for_stable_snapshot", side_effect=lambda path: FileSnapshot.from_path(path)):
                stats = scanner.initial_scan(threading.Event())

            rows = _queue_rows(db_path)
            self.assertEqual(stats["uploaded"], 1)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["task_type"], "UPLOAD")
            self.assertEqual(rows[0]["status"], "PENDING")

    def test_initial_scan_skips_same_hash_when_baseline_already_uploaded(self):
        from agent_core.config import AgentRuntimeConfig, normalize_path, sha256_of_file
        from agent_core.scanner import AgentScanner, FileSnapshot
        from agent_core.store import AgentStore

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            root = Path(tmp)
            db_path = root / "agent.db"
            scan_root = root / "scan"
            scan_root.mkdir()
            sample = scan_root / "secret.txt"
            sample.write_text("already uploaded", encoding="utf-8")
            file_hash = sha256_of_file(sample)

            store = AgentStore(db_path)
            store.upsert_baseline(
                file_path=normalize_path(str(sample)),
                file_hash=file_hash,
                file_size=sample.stat().st_size,
                mtime=sample.stat().st_mtime,
                uploaded=1,
            )
            runtime_config = AgentRuntimeConfig(
                scan_roots=[str(scan_root)],
                watch_dirs=[],
                include_extensions=[".txt"],
                exclude_paths=[],
            )
            scanner = AgentScanner(store, mock.Mock(), runtime_config)

            with mock.patch.object(scanner, "_wait_for_stable_snapshot", side_effect=lambda path: FileSnapshot.from_path(path)):
                stats = scanner.initial_scan(threading.Event())

            self.assertEqual(stats["uploaded"], 0)
            self.assertEqual(_queue_rows(db_path), [])

    def test_failed_upload_task_can_be_revived(self):
        from agent_core.store import AgentStore

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            db_path = Path(tmp) / "agent.db"
            store = AgentStore(db_path)
            payload = {
                "path": str(Path(tmp) / "secret.txt"),
                "normalized_path": str(Path(tmp) / "secret.txt"),
                "sha256": "abc123",
            }
            self.assertTrue(store.enqueue_task(task_id="upload-1", task_type="UPLOAD", payload=payload, max_retries=1))
            self.assertTrue(store.claim_task("upload-1"))
            store.retry_task("upload-1", "network unavailable")
            self.assertEqual(_queue_rows(db_path)[0]["status"], "FAILED")

            revived = store.revive_failed_upload_tasks()
            row = _queue_rows(db_path)[0]
            self.assertEqual(revived, 1)
            self.assertEqual(row["status"], "PENDING")
            self.assertEqual(row["retry_count"], 0)
            self.assertEqual(row["last_error"], "network unavailable")

    def test_enqueue_existing_failed_upload_resets_retry_counter(self):
        from agent_core.store import AgentStore

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            db_path = Path(tmp) / "agent.db"
            store = AgentStore(db_path)
            payload = {"path": "a.txt", "normalized_path": "a.txt", "sha256": "hash-a"}
            self.assertTrue(store.enqueue_task(task_id="upload-1", task_type="UPLOAD", payload=payload, max_retries=1))
            self.assertTrue(store.claim_task("upload-1"))
            store.retry_task("upload-1", "grpc port unavailable")
            self.assertEqual(_queue_rows(db_path)[0]["status"], "FAILED")

            self.assertTrue(store.enqueue_task(task_id="upload-1", task_type="UPLOAD", payload=payload, max_retries=5))
            row = _queue_rows(db_path)[0]
            self.assertEqual(row["status"], "PENDING")
            self.assertEqual(row["retry_count"], 0)
            self.assertIsNone(row["last_error"])
            self.assertEqual(row["max_retries"], 5)


if __name__ == "__main__":
    unittest.main()
