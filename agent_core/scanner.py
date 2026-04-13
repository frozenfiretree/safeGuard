import hashlib
import ctypes
import os
import queue
import string
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import psutil
except ImportError:
    psutil = None

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from .config import AgentRuntimeConfig, is_temp_filename, normalize_path, now_iso, sha256_of_file, should_exclude_path
from .store import AgentStore


def build_upload_task_id(normalized_path: str, file_hash: str) -> str:
    seed = f"upload|{normalized_path}|{file_hash}"
    return hashlib.sha256(seed.encode("utf-8", errors="ignore")).hexdigest()


def build_event_task_id(
    event_type: str,
    file_path: str,
    timestamp: float,
    *,
    old_path: Optional[str] = None,
    new_path: Optional[str] = None,
) -> str:
    coarse_time = int(float(timestamp) * 1000)
    seed = "|".join(
        [
            "event",
            event_type,
            normalize_path(file_path or new_path or old_path or ""),
            normalize_path(old_path or ""),
            normalize_path(new_path or ""),
            str(coarse_time),
        ]
    )
    return hashlib.sha256(seed.encode("utf-8", errors="ignore")).hexdigest()


def _safe_parent(path: str) -> str:
    try:
        return normalize_path(str(Path(path).parent))
    except Exception:
        return normalize_path(os.path.dirname(path))


def _same_parent(path_a: str, path_b: str) -> bool:
    return _safe_parent(path_a) == _safe_parent(path_b)


def _now_ts() -> float:
    return time.time()


def _is_temp_path(path: str) -> bool:
    return is_temp_filename(Path(path).name)


def _signature(size: int, mtime: float) -> Tuple[int, float]:
    return int(size or 0), round(float(mtime or 0.0), 1)


@dataclass
class FileSnapshot:
    path: str
    normalized_path: str
    size: int
    mtime: float
    sha256: str
    extension: str

    @classmethod
    def from_path(cls, path: str) -> "FileSnapshot":
        stat = os.stat(path)
        normalized = normalize_path(path)
        return cls(
            path=str(path),
            normalized_path=normalized,
            size=int(stat.st_size),
            mtime=float(stat.st_mtime),
            sha256=sha256_of_file(Path(path)),
            extension=Path(path).suffix.lower(),
        )


class MovePairTracker:
    def __init__(self, window_seconds: float):
        self.window_seconds = max(0.5, float(window_seconds or 2.0))
        self._items: List[Dict[str, Any]] = []
        self._lock = threading.RLock()

    def record_delete(self, *, path: str, size: int, mtime: float, file_hash: str):
        record = {
            "path": normalize_path(path),
            "size": int(size or 0),
            "mtime": float(mtime or 0.0),
            "hash": file_hash or "",
            "signature": _signature(size, mtime),
            "timestamp": _now_ts(),
        }
        with self._lock:
            self._items.append(record)
            self._cleanup_locked()

    def try_match_create(self, *, path: str, size: int, mtime: float, file_hash: str) -> Optional[Dict[str, Any]]:
        normalized = normalize_path(path)
        sig = _signature(size, mtime)
        with self._lock:
            self._cleanup_locked()
            candidates = []
            for item in self._items:
                if item["path"] == normalized:
                    continue
                score = 0
                if file_hash and item.get("hash") == file_hash:
                    score += 3
                if item.get("signature") == sig:
                    score += 2
                elif int(item.get("size") or 0) == int(size or 0):
                    score += 1
                if score > 0:
                    candidates.append((score, item))
            if not candidates:
                return None
            candidates.sort(key=lambda x: (x[0], x[1]["timestamp"]), reverse=True)
            best = candidates[0][1]
            self._items.remove(best)
            return best

    def cleanup(self):
        with self._lock:
            self._cleanup_locked()

    def _cleanup_locked(self):
        cutoff = _now_ts() - self.window_seconds
        self._items = [item for item in self._items if float(item.get("timestamp") or 0.0) >= cutoff]


class _WatchHandler(FileSystemEventHandler):
    def __init__(self, scanner: "AgentScanner"):
        super().__init__()
        self.scanner = scanner

    def on_created(self, event):
        if event.is_directory:
            return
        self.scanner.record_fs_event("created", str(event.src_path))

    def on_modified(self, event):
        if event.is_directory:
            return
        self.scanner.record_fs_event("modified", str(event.src_path))

    def on_deleted(self, event):
        if event.is_directory:
            return
        self.scanner.record_fs_event("deleted", str(event.src_path))

    def on_moved(self, event):
        if event.is_directory:
            return
        self.scanner.record_fs_event("moved", str(event.dest_path), src_path=str(event.src_path))


class AgentScanner:
    def __init__(self, store: AgentStore, logger, runtime_config: AgentRuntimeConfig):
        self.store = store
        self.logger = logger
        self.runtime_config = runtime_config
        self.event_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self.observer: Optional[Observer] = None
        self.watch_handler = _WatchHandler(self)
        self._watched_dirs: set[str] = set()
        self._debounced_events: Dict[str, Dict[str, Any]] = {}
        self._debounce_lock = threading.RLock()
        self._usb_seen: set[str] = set()
        self._move_pairs = MovePairTracker(runtime_config.move_pair_window_seconds)

    def update_runtime_config(self, runtime_config: AgentRuntimeConfig):
        self.runtime_config = runtime_config
        self._move_pairs = MovePairTracker(runtime_config.move_pair_window_seconds)
        self.sync_watch_dirs()

    def should_process_file(self, path: str) -> bool:
        try:
            file_path = Path(path)
            if not file_path.exists() or not file_path.is_file():
                return False
            if should_exclude_path(str(file_path), self.runtime_config.exclude_paths):
                return False
            if _is_temp_path(str(file_path)):
                return False
            ext = file_path.suffix.lower()
            if ext not in set(self.runtime_config.include_extensions or []):
                return False
            max_bytes = int(self.runtime_config.max_file_size_mb or 100) * 1024 * 1024
            if max_bytes > 0 and file_path.stat().st_size > max_bytes:
                return False
            return True
        except OSError:
            return False

    def enqueue_upload_for_path(self, path: str) -> bool:
        if not self.should_process_file(path):
            return False
        snapshot = self._wait_for_stable_snapshot(path)
        if not snapshot:
            return False
        payload = {
            "path": snapshot.path,
            "normalized_path": snapshot.normalized_path,
            "size": snapshot.size,
            "mtime": snapshot.mtime,
            "sha256": snapshot.sha256,
            "extension": snapshot.extension,
            "detected_at": now_iso(),
        }
        task_id = build_upload_task_id(snapshot.normalized_path, snapshot.sha256)
        created = self.store.enqueue_task(
            task_id=task_id,
            task_type="UPLOAD",
            payload=payload,
            max_retries=self.runtime_config.max_retries,
        )
        if created:
            self.store.upsert_baseline(
                file_path=snapshot.normalized_path,
                file_hash=snapshot.sha256,
                file_size=snapshot.size,
                mtime=snapshot.mtime,
                uploaded=0,
            )
            self.logger.info("queued upload task: %s", snapshot.path)
        return created

    def enqueue_event(
        self,
        *,
        event_type: str,
        file_path: str,
        timestamp: float,
        old_hash: Optional[str] = None,
        new_hash: Optional[str] = None,
        file_size: Optional[int] = None,
        old_path: Optional[str] = None,
        new_path: Optional[str] = None,
        event_details: Optional[Dict[str, Any]] = None,
        usb_context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        payload = {
            "event_id": build_event_task_id(
                event_type,
                file_path,
                timestamp,
                old_path=old_path,
                new_path=new_path,
            ),
            "event_type": event_type,
            "file_path": file_path,
            "old_path": old_path,
            "new_path": new_path,
            "old_hash": old_hash,
            "new_hash": new_hash,
            "file_size": file_size,
            "timestamp": timestamp,
            "event_details": event_details or {},
            "usb_context": usb_context or {},
        }
        created = self.store.enqueue_task(
            task_id=payload["event_id"],
            task_type="EVENT",
            payload=payload,
            max_retries=self.runtime_config.max_retries,
        )
        if created:
            self.logger.info("queued event task: type=%s path=%s", event_type, file_path)
        return created

    def initial_scan(self, stop_event: threading.Event) -> Dict[str, Any]:
        roots = list(self.runtime_config.scan_roots or [])
        self.logger.info("initial scan start: roots=%s", roots)
        started_at = _now_ts()
        checkpoint = self.store.get_scan_checkpoint()
        resume_found = checkpoint is None
        stats = {"total_files": 0, "scanned": 0, "uploaded": 0, "skipped": 0, "errors": 0, "duration_sec": 0.0}

        for root in roots:
            if stop_event.is_set():
                break
            root_path = Path(root)
            if not root_path.exists():
                continue
            for current_root, dirs, files in os.walk(root):
                if stop_event.is_set():
                    break
                dirs[:] = [
                    item for item in dirs
                    if not should_exclude_path(os.path.join(current_root, item), self.runtime_config.exclude_paths)
                ]
                for name in files:
                    if stop_event.is_set():
                        break
                    full_path = os.path.join(current_root, name)
                    normalized = normalize_path(full_path)
                    if checkpoint and not resume_found:
                        if normalized == normalize_path(checkpoint):
                            resume_found = True
                        else:
                            continue

                    self.store.set_scan_checkpoint(normalized)
                    stats["total_files"] += 1
                    if not self.should_process_file(full_path):
                        stats["skipped"] += 1
                        continue
                    try:
                        snapshot = self._wait_for_stable_snapshot(full_path)
                        if not snapshot:
                            stats["skipped"] += 1
                            continue
                        stats["scanned"] += 1
                        baseline = self.store.get_baseline(snapshot.normalized_path)
                        if baseline and baseline.get("file_hash") == snapshot.sha256:
                            self.store.upsert_baseline(
                                file_path=snapshot.normalized_path,
                                file_hash=snapshot.sha256,
                                file_size=snapshot.size,
                                mtime=snapshot.mtime,
                                uploaded=int(baseline.get("uploaded") or 0),
                            )
                            stats["skipped"] += 1
                            continue
                        if self.enqueue_upload_for_path(full_path):
                            stats["uploaded"] += 1
                    except Exception as exc:
                        stats["errors"] += 1
                        self.logger.warning("initial scan file failed: path=%s, error=%s", full_path, exc)

        self.store.set_scan_checkpoint(None)
        self.store.set_scan_completed(True)
        stats["duration_sec"] = round(_now_ts() - started_at, 3)
        self.logger.info("initial scan completed")
        return stats

    def start_monitoring(self):
        watch_dirs = [item for item in (self.runtime_config.watch_dirs or []) if Path(item).exists()]
        if self.observer:
            self.sync_watch_dirs()
            return
        self.observer = Observer()
        self._watched_dirs = set()
        for item in watch_dirs:
            self._schedule_watch_dir(item)
        self.observer.start()
        self.logger.info("watchdog started: dirs=%s", sorted(self._watched_dirs))

    def stop_monitoring(self):
        observer = self.observer
        self.observer = None
        if observer:
            observer.stop()
            observer.join(timeout=5)
        self._watched_dirs = set()

    def _schedule_watch_dir(self, path: str):
        observer = self.observer
        if not observer:
            return
        normalized = normalize_path(path)
        if normalized in self._watched_dirs:
            return
        if should_exclude_path(path, self.runtime_config.exclude_paths):
            return
        if not Path(path).exists():
            return
        observer.schedule(self.watch_handler, path, recursive=True)
        self._watched_dirs.add(normalized)

    def sync_watch_dirs(self):
        observer = self.observer
        if not observer:
            return
        target_dirs = {
            normalize_path(item)
            for item in (self.runtime_config.watch_dirs or [])
            if item and Path(item).exists() and not should_exclude_path(item, self.runtime_config.exclude_paths)
        }
        if target_dirs == self._watched_dirs:
            return
        self.stop_monitoring()
        self.start_monitoring()

    def record_fs_event(self, event_kind: str, path: str, *, src_path: Optional[str] = None):
        primary = normalize_path(path)
        event = {
            "kind": event_kind,
            "path": str(path),
            "src_path": str(src_path) if src_path else None,
            "timestamp": _now_ts(),
        }
        with self._debounce_lock:
            if event_kind == "deleted":
                self._debounced_events[primary] = event
                return
            if event_kind == "moved" and src_path:
                src_norm = normalize_path(src_path)
                self._debounced_events[src_norm] = event
                self._debounced_events[primary] = event
                return
            self._debounced_events[primary] = event

    def flush_debounced_events(self, stop_event: threading.Event):
        while not stop_event.is_set():
            due: List[Dict[str, Any]] = []
            now_ts = _now_ts()
            with self._debounce_lock:
                keys_to_delete = []
                for key, event in self._debounced_events.items():
                    if now_ts - float(event.get("timestamp") or 0.0) >= float(self.runtime_config.debounce_seconds or 2.0):
                        due.append(event)
                        keys_to_delete.append(key)
                for key in keys_to_delete:
                    self._debounced_events.pop(key, None)

            deduped = self._dedupe_ready_events(due)
            for event in deduped:
                try:
                    self._handle_stable_event(event)
                except Exception as exc:
                    self.logger.warning("event handle failed: event=%s, error=%s", event, exc)
            self._move_pairs.cleanup()
            stop_event.wait(0.5)

    def poll_usb_events(self, stop_event: threading.Event):
        self._usb_seen = self._list_removable_roots()
        while not stop_event.is_set():
            current = self._list_removable_roots()
            added = current - self._usb_seen
            removed = self._usb_seen - current
            for root in sorted(added):
                self.enqueue_event(
                    event_type="usb_inserted",
                    file_path=root,
                    timestamp=_now_ts(),
                    usb_context={"drive": root, "action": "inserted"},
                    event_details={"drive": root},
                )
            for root in sorted(removed):
                self.enqueue_event(
                    event_type="usb_removed",
                    file_path=root,
                    timestamp=_now_ts(),
                    usb_context={"drive": root, "action": "removed"},
                    event_details={"drive": root},
                )
            self._usb_seen = current
            stop_event.wait(max(5, int(self.runtime_config.usb_poll_interval or 30)))

    def _dedupe_ready_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        unique: List[Dict[str, Any]] = []
        seen = set()
        for event in sorted(events, key=lambda item: float(item.get("timestamp") or 0.0)):
            key = (
                event.get("kind"),
                normalize_path(str(event.get("path") or "")),
                normalize_path(str(event.get("src_path") or "")),
                int(float(event.get("timestamp") or 0.0) * 10),
            )
            if key in seen:
                continue
            seen.add(key)
            unique.append(event)
        return unique

    def _handle_stable_event(self, event: Dict[str, Any]):
        kind = str(event.get("kind") or "")
        path = str(event.get("path") or "")
        src_path = str(event.get("src_path") or "")
        if kind == "deleted":
            self._handle_deleted(path, event)
        elif kind == "moved":
            self._handle_moved(src_path, path, event)
        elif kind == "created":
            self._handle_created(path, event)
        elif kind == "modified":
            self._handle_modified(path, event)

    def _handle_deleted(self, path: str, event: Dict[str, Any]):
        normalized = normalize_path(path)
        baseline = self.store.get_baseline(normalized)
        old_hash = str((baseline or {}).get("file_hash") or "")
        old_size = int((baseline or {}).get("file_size") or 0)
        old_mtime = float((baseline or {}).get("mtime") or 0.0)
        if baseline:
            self._move_pairs.record_delete(path=normalized, size=old_size, mtime=old_mtime, file_hash=old_hash)
        self.store.delete_baseline(normalized)
        if _is_temp_path(path):
            return
        self.enqueue_event(
            event_type="file_deleted",
            file_path=normalized,
            timestamp=float(event.get("timestamp") or _now_ts()),
            old_hash=old_hash or None,
            file_size=old_size or None,
            event_details={"source": "watchdog_deleted"},
        )

    def _handle_moved(self, src_path: str, dst_path: str, event: Dict[str, Any]):
        if not dst_path:
            return
        old_normalized = normalize_path(src_path) if src_path else ""
        new_snapshot = self._wait_for_stable_snapshot(dst_path)
        if not new_snapshot:
            return

        baseline = self.store.get_baseline(old_normalized) if old_normalized else None
        old_hash = str((baseline or {}).get("file_hash") or "") or new_snapshot.sha256
        old_size = int((baseline or {}).get("file_size") or 0) or new_snapshot.size
        old_mtime = float((baseline or {}).get("mtime") or 0.0) or new_snapshot.mtime
        if old_normalized:
            self.store.delete_baseline(old_normalized)

        event_type = "file_moved"
        details: Dict[str, Any] = {"source": "watchdog_moved"}
        if _is_temp_path(src_path) and not _is_temp_path(dst_path):
            event_type = "file_overwritten"
            details["save_pattern"] = "temp_replace"
        elif _same_parent(src_path, dst_path):
            event_type = "file_renamed"
        else:
            event_type = "file_moved"

        self.store.upsert_baseline(
            file_path=new_snapshot.normalized_path,
            file_hash=new_snapshot.sha256,
            file_size=new_snapshot.size,
            mtime=new_snapshot.mtime,
            uploaded=0,
        )
        self.enqueue_event(
            event_type=event_type,
            file_path=new_snapshot.normalized_path,
            old_path=old_normalized or None,
            new_path=new_snapshot.normalized_path,
            timestamp=float(event.get("timestamp") or _now_ts()),
            old_hash=old_hash or None,
            new_hash=new_snapshot.sha256,
            file_size=new_snapshot.size,
            event_details=details,
        )
        self.enqueue_upload_for_path(new_snapshot.path)

    def _handle_created(self, path: str, event: Dict[str, Any]):
        if _is_temp_path(path):
            return
        snapshot = self._wait_for_stable_snapshot(path)
        if not snapshot or not self.should_process_file(snapshot.path):
            return

        previous_baseline = self.store.get_baseline(snapshot.normalized_path)
        matched_delete = self._move_pairs.try_match_create(
            path=snapshot.normalized_path,
            size=snapshot.size,
            mtime=snapshot.mtime,
            file_hash=snapshot.sha256,
        )
        copy_sources = self.store.find_paths_by_hash(snapshot.sha256, exclude_path=snapshot.normalized_path)

        if matched_delete:
            old_path = str(matched_delete.get("path") or "")
            event_type = "file_renamed" if _same_parent(old_path, snapshot.normalized_path) else "file_moved"
            self.store.delete_baseline(old_path)
            details = {"source": "delete_create_pair", "matched_by": "hash_or_signature"}
            self.enqueue_event(
                event_type=event_type,
                file_path=snapshot.normalized_path,
                old_path=old_path,
                new_path=snapshot.normalized_path,
                timestamp=float(event.get("timestamp") or _now_ts()),
                old_hash=str(matched_delete.get("hash") or "") or None,
                new_hash=snapshot.sha256,
                file_size=snapshot.size,
                event_details=details,
            )
        elif previous_baseline and previous_baseline.get("file_hash") != snapshot.sha256:
            self.enqueue_event(
                event_type="file_overwritten",
                file_path=snapshot.normalized_path,
                timestamp=float(event.get("timestamp") or _now_ts()),
                old_hash=str(previous_baseline.get("file_hash") or "") or None,
                new_hash=snapshot.sha256,
                file_size=snapshot.size,
                event_details={"source": "created_on_existing_path"},
            )
        elif copy_sources:
            copied_from = str(copy_sources[0].get("file_path") or "")
            self.enqueue_event(
                event_type="file_copied",
                file_path=snapshot.normalized_path,
                old_path=copied_from or None,
                new_path=snapshot.normalized_path,
                timestamp=float(event.get("timestamp") or _now_ts()),
                old_hash=snapshot.sha256,
                new_hash=snapshot.sha256,
                file_size=snapshot.size,
                event_details={"source": "hash_match", "copied_from": copied_from},
            )
        else:
            self.enqueue_event(
                event_type="file_created",
                file_path=snapshot.normalized_path,
                timestamp=float(event.get("timestamp") or _now_ts()),
                new_hash=snapshot.sha256,
                file_size=snapshot.size,
                event_details={"source": "watchdog_created"},
            )

        self.store.upsert_baseline(
            file_path=snapshot.normalized_path,
            file_hash=snapshot.sha256,
            file_size=snapshot.size,
            mtime=snapshot.mtime,
            uploaded=0,
        )
        self.enqueue_upload_for_path(snapshot.path)

    def _handle_modified(self, path: str, event: Dict[str, Any]):
        if _is_temp_path(path):
            return
        snapshot = self._wait_for_stable_snapshot(path)
        if not snapshot or not self.should_process_file(snapshot.path):
            return

        baseline = self.store.get_baseline(snapshot.normalized_path)
        if baseline:
            same_size = int(baseline.get("file_size") or 0) == snapshot.size
            same_mtime = abs(float(baseline.get("mtime") or 0.0) - snapshot.mtime) < 0.0001
            if same_size and same_mtime:
                return
            old_hash = str(baseline.get("file_hash") or "")
            if old_hash == snapshot.sha256:
                self.store.upsert_baseline(
                    file_path=snapshot.normalized_path,
                    file_hash=snapshot.sha256,
                    file_size=snapshot.size,
                    mtime=snapshot.mtime,
                    uploaded=int(baseline.get("uploaded") or 0),
                )
                return
            self.enqueue_event(
                event_type="file_modified",
                file_path=snapshot.normalized_path,
                timestamp=float(event.get("timestamp") or _now_ts()),
                old_hash=old_hash or None,
                new_hash=snapshot.sha256,
                file_size=snapshot.size,
                event_details={"source": "content_hash_changed"},
            )
        else:
            self.enqueue_event(
                event_type="file_modified",
                file_path=snapshot.normalized_path,
                timestamp=float(event.get("timestamp") or _now_ts()),
                new_hash=snapshot.sha256,
                file_size=snapshot.size,
                event_details={"source": "modified_without_baseline"},
            )

        self.store.upsert_baseline(
            file_path=snapshot.normalized_path,
            file_hash=snapshot.sha256,
            file_size=snapshot.size,
            mtime=snapshot.mtime,
            uploaded=0,
        )
        self.enqueue_upload_for_path(snapshot.path)

    def _wait_for_stable_snapshot(self, path: str) -> Optional[FileSnapshot]:
        normalized = normalize_path(path)
        deadline = _now_ts() + max(2.0, float(self.runtime_config.write_stable_seconds or 1.0) + 3.0)
        last_sig = None
        stable_since = None
        while _now_ts() < deadline:
            try:
                stat = os.stat(path)
                current_sig = (int(stat.st_size), round(float(stat.st_mtime), 4))
                if current_sig == last_sig:
                    if stable_since is None:
                        stable_since = _now_ts()
                    if _now_ts() - stable_since >= float(self.runtime_config.write_stable_seconds or 1.0):
                        return FileSnapshot(
                            path=str(path),
                            normalized_path=normalized,
                            size=int(stat.st_size),
                            mtime=float(stat.st_mtime),
                            sha256=sha256_of_file(Path(path)),
                            extension=Path(path).suffix.lower(),
                        )
                else:
                    last_sig = current_sig
                    stable_since = None
            except (FileNotFoundError, PermissionError, OSError):
                pass
            time.sleep(0.2)
        return None

    def _list_removable_roots(self) -> set[str]:
        roots = set()
        if psutil:
            try:
                for part in psutil.disk_partitions(all=False):
                    opts = (part.opts or "").lower()
                    if "removable" in opts or "cdrom" in opts:
                        roots.add(normalize_path(part.mountpoint))
            except Exception:
                pass
        if roots:
            return roots
        for letter in string.ascii_uppercase:
            drive = f"{letter}:\\"
            if not os.path.exists(drive):
                continue
            try:
                drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive)
                if int(drive_type) == 2:
                    roots.add(normalize_path(drive))
            except Exception:
                continue
        return roots
