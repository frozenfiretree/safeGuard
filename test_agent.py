import argparse
import hashlib
import json
import os
import shutil
import socket
import sqlite3
import threading
import time
import traceback
import uuid
from concurrent import futures
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

import grpc


DEFAULT_EXTENSIONS = [
    ".docx",
    ".xlsx",
    ".pdf",
    ".pptx",
    ".csv",
    ".txt",
    ".png",
    ".jpg",
    ".jpeg",
    ".bmp",
]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def find_free_port(host: str = "127.0.0.1") -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, 0))
    port = int(sock.getsockname()[1])
    sock.close()
    return port


def wait_until(predicate, timeout: float, interval: float = 0.2, description: str = "condition") -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(interval)
    raise TimeoutError(f"timed out waiting for {description}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Full local SafeGuard Agent test harness without service install, registry writes, or autostart."
    )
    parser.add_argument(
        "--work-dir",
        default=None,
        help="Test workspace. Default: .agent_local_fulltest under the project root.",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Delete the test workspace before running.",
    )
    parser.add_argument(
        "--http-host",
        default="127.0.0.1",
        help="Mock HTTP server host. Default: 127.0.0.1.",
    )
    parser.add_argument(
        "--http-port",
        type=int,
        default=0,
        help="Mock HTTP server port. Default: choose a free port automatically.",
    )
    parser.add_argument(
        "--grpc-host",
        default="127.0.0.1",
        help="Mock gRPC server host. Default: 127.0.0.1.",
    )
    parser.add_argument(
        "--grpc-port",
        type=int,
        default=0,
        help="Mock gRPC server port. Default: choose a free port automatically.",
    )
    parser.add_argument(
        "--runtime-timeout",
        type=int,
        default=45,
        help="Overall runtime timeout in seconds. Default: 45.",
    )
    parser.add_argument(
        "--simulate-usb",
        action="store_true",
        help="Simulate USB inserted/removed events during the test.",
    )
    return parser.parse_args()


def project_root() -> Path:
    return Path(__file__).resolve().parent


def default_work_dir() -> Path:
    return project_root() / ".agent_local_fulltest"


def prepare_directories(work_dir: Path, clean: bool) -> dict[str, Path]:
    if clean and work_dir.exists():
        shutil.rmtree(work_dir)
    paths = {
        "root": work_dir,
        "scan_root": work_dir / "scan_root",
        "downloads": work_dir / "downloads",
        "mock_http": work_dir / "mock_http",
    }
    for path in paths.values():
        path.mkdir(parents=True, exist_ok=True)
    return paths


def create_sample_files(scan_root: Path) -> list[Path]:
    files = [
        scan_root / "initial_report.txt",
        scan_root / "initial_sheet.csv",
        scan_root / "nested" / "notes.txt",
    ]
    files[0].write_text("alpha secret report\n", encoding="utf-8")
    files[1].write_text("name,value\nfoo,123\n", encoding="utf-8")
    files[2].parent.mkdir(parents=True, exist_ok=True)
    files[2].write_text("nested note\n", encoding="utf-8")
    return files


def write_install_settings(work_dir: Path, server_base: str, grpc_target: str) -> Path:
    settings_path = work_dir / "install_config.json"
    payload = {
        "schema_version": 1,
        "server_base": server_base.rstrip("/"),
        "work_dir": str(work_dir),
        "grpc_upload_target": grpc_target,
        "written_by": "test_agent_harness",
        "written_at": time.time(),
    }
    settings_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return settings_path


def prepare_environment(work_dir: Path, server_base: str, grpc_target: str) -> None:
    os.environ["SAFEGUARD_AGENT_WORKDIR"] = str(work_dir)
    os.environ["SAFEGUARD_AGENT_SETTINGS_FILE"] = str(work_dir / "install_config.json")
    os.environ["SAFEGUARD_SERVER_BASE"] = server_base.rstrip("/")
    os.environ["SAFEGUARD_GRPC_UPLOAD_TARGET"] = grpc_target


def runtime_config_payload(scan_root: Path, version: int) -> dict[str, Any]:
    return {
        "status": "ok",
        "config_version": version,
        "scan_dirs": [str(scan_root)],
        "watch_dirs": [str(scan_root)],
        "include_extensions": list(DEFAULT_EXTENSIONS),
        "exclude_paths": [
            r"C:\Windows",
            r"C:\Program Files",
            r"C:\Program Files (x86)",
            r"C:\ProgramData\Microsoft",
        ],
        "max_file_size_mb": 100,
        "heartbeat_interval_sec": 2,
        "config_pull_interval_sec": 4,
        "debounce_seconds": 0.4,
        "write_stable_seconds": 0.2,
        "move_pair_window_seconds": 0.4,
        "upload_workers": 2,
        "queue_batch_size": 10,
        "event_batch_size": 10,
        "chunk_size_bytes": 256 * 1024,
        "usb_poll_interval_sec": 5,
        "request_timeout_sec": 5,
        "max_retries": 2,
        "scan": {"bootstrap_scan_enabled": False},
        "guard": {"monitor_roots": [str(scan_root)]},
    }


@dataclass
class MockControl:
    scan_root: Path
    lock: threading.RLock = field(default_factory=threading.RLock)
    server_base: str = ""
    grpc_target: str = ""
    token: str = "test-agent-token"
    config_v1: dict[str, Any] = field(default_factory=dict)
    config_v2: dict[str, Any] = field(default_factory=dict)
    current_config: dict[str, Any] = field(default_factory=dict)
    registered_agents: list[dict[str, Any]] = field(default_factory=list)
    heartbeats: list[dict[str, Any]] = field(default_factory=list)
    config_requests: list[dict[str, Any]] = field(default_factory=list)
    events_batches: list[dict[str, Any]] = field(default_factory=list)
    scan_complete_reports: list[dict[str, Any]] = field(default_factory=list)
    upgrade_reports: list[dict[str, Any]] = field(default_factory=list)
    artifacts_downloaded: list[str] = field(default_factory=list)
    upgrade_downloads: list[str] = field(default_factory=list)
    uploads: list[dict[str, Any]] = field(default_factory=list)
    sessions: dict[str, dict[str, Any]] = field(default_factory=dict)
    config_changed_sent: bool = False
    upgrade_sent: bool = False
    artifact_bytes: bytes = b"artifact-payload-for-test"
    upgrade_bytes: bytes = b"fake-upgrade-binary"

    def __post_init__(self) -> None:
        self.current_config = dict(self.config_v1)
        self.upgrade_version = "2.0.1-test"
        self.upgrade_checksum = sha256_bytes(self.upgrade_bytes)

    def require_auth(self, headers: dict[str, str]) -> bool:
        auth = headers.get("Authorization") or ""
        return auth == f"Bearer {self.token}"


def make_handler(control: MockControl):
    class MockAgentApiHandler(BaseHTTPRequestHandler):
        server_version = "SafeGuardAgentTest/1.0"

        def log_message(self, format: str, *args) -> None:
            return

        def _send_json(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_bytes(self, status: int, payload: bytes, content_type: str = "application/octet-stream") -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def _read_json(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0:
                return {}
            raw = self.rfile.read(length)
            if not raw:
                return {}
            return json.loads(raw.decode("utf-8"))

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path
            query = parse_qs(parsed.query)

            if path.startswith("/api/artifacts/"):
                artifact_id = path.rsplit("/", 1)[-1]
                with control.lock:
                    control.artifacts_downloaded.append(artifact_id)
                self._send_bytes(HTTPStatus.OK, control.artifact_bytes)
                return

            if path == f"/api/v1/upgrades/{control.upgrade_version}/download":
                with control.lock:
                    control.upgrade_downloads.append(control.upgrade_version)
                self._send_bytes(HTTPStatus.OK, control.upgrade_bytes)
                return

            if path.endswith("/config"):
                if not control.require_auth(dict(self.headers)):
                    self._send_json(HTTPStatus.UNAUTHORIZED, {"detail": "unauthorized"})
                    return
                current_version = str(query.get("config_version", [""])[0] or "")
                with control.lock:
                    control.config_requests.append({"path": path, "config_version": current_version, "ts": time.time()})
                    payload = dict(control.current_config)
                if current_version and current_version == str(payload.get("config_version") or ""):
                    self.send_response(HTTPStatus.NOT_MODIFIED)
                    self.end_headers()
                    return
                self._send_json(HTTPStatus.OK, payload)
                return

            self._send_json(HTTPStatus.NOT_FOUND, {"detail": f"GET {path} not found"})

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path
            payload = self._read_json()

            if path == "/api/v1/agents/register":
                agent_id = str(payload.get("agent_id") or uuid.uuid4())
                response = {
                    "status": "ok",
                    "agent_id": agent_id,
                    "token": control.token,
                    "token_expires": time.time() + 3600,
                    "config_version": int(control.current_config.get("config_version") or 1),
                }
                with control.lock:
                    control.registered_agents.append({"payload": payload, "response": response, "ts": time.time()})
                self._send_json(HTTPStatus.OK, response)
                return

            if path.endswith("/heartbeat"):
                if not control.require_auth(dict(self.headers)):
                    self._send_json(HTTPStatus.UNAUTHORIZED, {"detail": "unauthorized"})
                    return
                response = {"status": "ok", "server_time": time.time()}
                with control.lock:
                    control.heartbeats.append({"payload": payload, "ts": time.time()})
                    beat_count = len(control.heartbeats)
                    if beat_count >= 2 and not control.config_changed_sent:
                        control.current_config = dict(control.config_v2)
                        control.config_changed_sent = True
                        response["config_changed"] = True
                    if beat_count >= 3 and not control.upgrade_sent:
                        control.upgrade_sent = True
                        response["upgrade"] = {
                            "version": control.upgrade_version,
                            "checksum": control.upgrade_checksum,
                        }
                self._send_json(HTTPStatus.OK, response)
                return

            if path == "/api/v1/events/batch":
                if not control.require_auth(dict(self.headers)):
                    self._send_json(HTTPStatus.UNAUTHORIZED, {"detail": "unauthorized"})
                    return
                events = list(payload.get("events") or [])
                with control.lock:
                    control.events_batches.append({"events": events, "ts": time.time()})
                self._send_json(HTTPStatus.OK, {"status": "ok", "accepted": len(events), "duplicates": 0})
                return

            if path.endswith("/scan-complete"):
                if not control.require_auth(dict(self.headers)):
                    self._send_json(HTTPStatus.UNAUTHORIZED, {"detail": "unauthorized"})
                    return
                with control.lock:
                    control.scan_complete_reports.append({"payload": payload, "ts": time.time()})
                self._send_json(HTTPStatus.OK, {"status": "ok"})
                return

            if path.endswith("/upgrade-report"):
                if not control.require_auth(dict(self.headers)):
                    self._send_json(HTTPStatus.UNAUTHORIZED, {"detail": "unauthorized"})
                    return
                with control.lock:
                    control.upgrade_reports.append({"payload": payload, "ts": time.time()})
                self._send_json(HTTPStatus.OK, {"status": "ok"})
                return

            self._send_json(HTTPStatus.NOT_FOUND, {"detail": f"POST {path} not found"})

    return MockAgentApiHandler


class MockUploadServicer:
    def __init__(self, control: MockControl):
        from agent_core.grpc_proto import safeguard_upload_pb2  # type: ignore

        self.control = control
        self.pb2 = safeguard_upload_pb2

    def InitUpload(self, request, context):
        if request.agent_token != self.control.token:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "invalid agent token")
        with self.control.lock:
            for item in self.control.uploads:
                if item["file_hash"] == request.file_hash:
                    return self.pb2.InitUploadResponse(status="dedup", session_id="", file_id=item["file_hash"], uploaded_chunks=[])
            session_id = str(uuid.uuid4())
            self.control.sessions[session_id] = {
                "agent_id": request.agent_id,
                "file_hash": request.file_hash,
                "file_name": request.file_name,
                "file_type": request.file_type,
                "file_path": request.file_path,
                "file_size": int(request.file_size),
                "total_chunks": int(request.total_chunks),
                "priority": request.priority,
                "chunks": {},
            }
        return self.pb2.InitUploadResponse(status="created", session_id=session_id, file_id=request.file_hash, uploaded_chunks=[])

    def UploadChunks(self, request_iterator, context):
        session_id: Optional[str] = None
        uploaded_chunks: list[int] = []
        with self.control.lock:
            for request in request_iterator:
                session_id = request.session_id or session_id
                if not session_id or session_id not in self.control.sessions:
                    context.abort(grpc.StatusCode.NOT_FOUND, "session not found")
                session = self.control.sessions[session_id]
                digest = sha256_bytes(bytes(request.content))
                if request.chunk_sha256 and digest != request.chunk_sha256:
                    context.abort(grpc.StatusCode.INVALID_ARGUMENT, "chunk sha256 mismatch")
                session["chunks"][int(request.index)] = bytes(request.content)
            if session_id:
                uploaded_chunks = sorted(int(x) for x in self.control.sessions[session_id]["chunks"].keys())
        return self.pb2.UploadChunksResponse(status="ok", session_id=session_id or "", uploaded_chunks=uploaded_chunks)

    def GetUploadStatus(self, request, context):
        session_id = str(request.session_id or "")
        with self.control.lock:
            session = self.control.sessions.get(session_id)
            if not session:
                context.abort(grpc.StatusCode.NOT_FOUND, "session not found")
            uploaded_chunks = sorted(int(x) for x in session["chunks"].keys())
            total_chunks = int(session["total_chunks"])
        return self.pb2.UploadStatusResponse(
            session_id=session_id,
            status="UPLOADING",
            uploaded_chunks=uploaded_chunks,
            total_chunks=total_chunks,
        )

    def CompleteUpload(self, request, context):
        session_id = str(request.session_id or "")
        with self.control.lock:
            session = self.control.sessions.get(session_id)
            if not session:
                context.abort(grpc.StatusCode.NOT_FOUND, "session not found")
            ordered = b"".join(session["chunks"][index] for index in sorted(session["chunks"]))
            upload_info = {
                "session_id": session_id,
                "file_hash": session["file_hash"],
                "file_name": session["file_name"],
                "file_type": session["file_type"],
                "file_path": session["file_path"],
                "file_size": session["file_size"],
                "priority": request.priority or session["priority"],
                "uploaded_bytes": len(ordered),
                "uploaded_chunks": sorted(session["chunks"].keys()),
                "ts": time.time(),
            }
            self.control.uploads.append(upload_info)
            task_id = f"mock-task-{len(self.control.uploads)}"
        return self.pb2.CompleteUploadResponse(status="ok", session_id=session_id, file_hash=session["file_hash"], task_id=task_id)


def start_http_server(control: MockControl, host: str, port: int):
    handler = make_handler(control)
    server = ThreadingHTTPServer((host, port), handler)
    thread = threading.Thread(target=server.serve_forever, name="mock-http", daemon=True)
    thread.start()
    return server, thread


def start_grpc_server(control: MockControl, host: str, port: int):
    from agent_core.grpc_proto import safeguard_upload_pb2_grpc  # type: ignore

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    safeguard_upload_pb2_grpc.add_UploadServiceServicer_to_server(MockUploadServicer(control), server)
    server.add_insecure_port(f"{host}:{port}")
    server.start()
    return server


def patch_usb_simulation(simulate_usb: bool, start_ts: float):
    from agent_core.scanner import AgentScanner

    original = AgentScanner._list_removable_roots

    def fake_list_removable_roots(self):
        if not simulate_usb:
            return set()
        elapsed = time.time() - start_ts
        if 6 <= elapsed < 11:
            return {r"R:\SAFEGUARD_TEST_USB"}
        return set()

    AgentScanner._list_removable_roots = fake_list_removable_roots
    return AgentScanner, original


def runtime_thread_target(runtime, errors: list[dict[str, Any]]):
    try:
        runtime.start()
    except Exception as exc:
        errors.append({"error": str(exc)})


def trigger_file_workload(runtime, scan_root: Path) -> dict[str, str]:
    created_path = scan_root / "created_note.txt"
    created_path.write_text("created content\n", encoding="utf-8")
    runtime.scanner.record_fs_event("created", str(created_path))
    time.sleep(1.2)

    modified_path = scan_root / "initial_report.txt"
    modified_path.write_text("alpha secret report\nmodified line\n", encoding="utf-8")
    runtime.scanner.record_fs_event("modified", str(modified_path))
    time.sleep(1.2)

    renamed_path = scan_root / "renamed_note.txt"
    created_path.rename(renamed_path)
    runtime.scanner.record_fs_event("moved", str(renamed_path), src_path=str(created_path))
    time.sleep(1.2)

    deleted_path = scan_root / "initial_sheet.csv"
    if deleted_path.exists():
        deleted_path.unlink()
    runtime.scanner.record_fs_event("deleted", str(deleted_path))
    time.sleep(1.2)

    return {
        "created": str(created_path),
        "modified": str(modified_path),
        "renamed": str(renamed_path),
        "deleted": str(deleted_path),
    }


def task_queue_snapshot(db_path: Path) -> dict[str, int]:
    if not db_path.exists():
        return {}
    conn = sqlite3.connect(str(db_path))
    try:
        rows = conn.execute("SELECT status, COUNT(1) FROM task_queue GROUP BY status").fetchall()
        return {str(status): int(count) for status, count in rows}
    finally:
        conn.close()


def build_summary(
    *,
    work_dir: Path,
    settings_path: Path,
    control: MockControl,
    runtime,
    artifact_path: Path,
    manual_upgrade_path: Path,
    runtime_errors: list[dict[str, Any]],
    touched_paths: dict[str, str],
) -> dict[str, Any]:
    event_types = []
    for batch in control.events_batches:
        for item in batch.get("events") or []:
            event_types.append(str(item.get("event_type") or ""))
    summary = {
        "status": "ok" if not runtime_errors else "error",
        "mode": "full-local-harness",
        "work_dir": str(work_dir),
        "settings_file": str(settings_path),
        "service_install_disabled": True,
        "registry_write_disabled": True,
        "autostart_disabled": True,
        "server_base": control.server_base,
        "grpc_target": control.grpc_target,
        "registered_agents": len(control.registered_agents),
        "heartbeats": len(control.heartbeats),
        "config_requests": len(control.config_requests),
        "config_changed_seen": control.config_changed_sent,
        "upgrade_piggyback_seen": control.upgrade_sent,
        "events_batches": len(control.events_batches),
        "event_types": sorted(set(event_types)),
        "uploads": len(control.uploads),
        "scan_complete_reports": len(control.scan_complete_reports),
        "upgrade_reports": len(control.upgrade_reports),
        "artifact_downloads": len(control.artifacts_downloaded),
        "upgrade_downloads": len(control.upgrade_downloads),
        "artifact_download_path": str(artifact_path) if artifact_path.exists() else None,
        "manual_upgrade_download_path": str(manual_upgrade_path) if manual_upgrade_path.exists() else None,
        "runtime_state": runtime.store.get_current_state() if runtime else None,
        "scan_completed": runtime.store.is_scan_completed() if runtime else False,
        "config_version": runtime.store.get_state("config_version") if runtime else None,
        "agent_id": runtime.store.get_state("agent_id") if runtime else None,
        "task_queue_status": task_queue_snapshot(Path(work_dir) / "agent.db"),
        "touched_paths": touched_paths,
        "runtime_errors": runtime_errors,
        "checks": {
            "register_ok": len(control.registered_agents) >= 1,
            "heartbeat_ok": len(control.heartbeats) >= 2,
            "config_sync_ok": control.config_changed_sent,
            "scan_complete_ok": len(control.scan_complete_reports) >= 1,
            "event_upload_ok": len(control.events_batches) >= 1,
            "file_upload_ok": len(control.uploads) >= 1,
            "upgrade_report_ok": len(control.upgrade_reports) >= 1,
            "artifact_download_ok": artifact_path.exists(),
            "manual_upgrade_download_ok": manual_upgrade_path.exists(),
        },
    }
    summary["status"] = "ok" if all(summary["checks"].values()) and not runtime_errors else "error"
    return summary


def run_full_harness(args: argparse.Namespace) -> int:
    root = project_root()
    work_dir = Path(args.work_dir).resolve() if args.work_dir else default_work_dir()
    paths = prepare_directories(work_dir, args.clean)
    sample_files = create_sample_files(paths["scan_root"])

    http_port = args.http_port or find_free_port(args.http_host)
    grpc_port = args.grpc_port or find_free_port(args.grpc_host)
    server_base = f"http://{args.http_host}:{http_port}"
    grpc_target = f"{args.grpc_host}:{grpc_port}"
    settings_path = write_install_settings(work_dir, server_base, grpc_target)
    prepare_environment(work_dir, server_base, grpc_target)

    config_v1 = runtime_config_payload(paths["scan_root"], version=1)
    config_v2 = runtime_config_payload(paths["scan_root"], version=2)
    config_v2["request_timeout_sec"] = 6
    config_v2["event_batch_size"] = 6

    control = MockControl(scan_root=paths["scan_root"], server_base=server_base, grpc_target=grpc_target, config_v1=config_v1, config_v2=config_v2)

    http_server = None
    grpc_server = None
    runtime = None
    runtime_thread = None
    runtime_errors: list[dict[str, Any]] = []
    artifact_path = paths["downloads"] / "artifact-demo.bin"
    manual_upgrade_path = paths["downloads"] / "manual-upgrade.bin"
    touched_paths: dict[str, str] = {}
    patch_target = None
    original_usb = None

    try:
        try:
            http_server, _ = start_http_server(control, args.http_host, http_port)
            grpc_server = start_grpc_server(control, args.grpc_host, grpc_port)

            start_ts = time.time()
            from agent_core.main import AgentRuntime  # imported after env is ready

            patch_target, original_usb = patch_usb_simulation(args.simulate_usb, start_ts)
            runtime = AgentRuntime()
            runtime_thread = threading.Thread(target=runtime_thread_target, args=(runtime, runtime_errors), name="agent-runtime", daemon=True)
            runtime_thread.start()

            wait_until(lambda: len(control.registered_agents) >= 1, 12, description="agent registration")
            wait_until(lambda: len(control.scan_complete_reports) >= 1, 18, description="initial scan complete")
            wait_until(lambda: len(control.uploads) >= 1, 18, description="initial upload")

            runtime.client.download_artifact("artifact-demo", artifact_path)
            runtime.client.download_upgrade(control.upgrade_version, manual_upgrade_path)
            runtime.client.report_upgrade_result(
                {
                    "old_version": "2.0.0",
                    "new_version": "manual-check",
                    "success": True,
                    "error_message": None,
                }
            )

            touched_paths = trigger_file_workload(runtime, paths["scan_root"])

            wait_until(lambda: len(control.events_batches) >= 1, 18, description="event batch upload")
            wait_until(lambda: len(control.heartbeats) >= 3, 18, description="multiple heartbeats")
            wait_until(lambda: len(control.upgrade_reports) >= 1, 24, description="upgrade report")

            time.sleep(2.5)
        except Exception as exc:
            runtime_errors.append(
                {
                    "fatal_error": str(exc),
                    "traceback": traceback.format_exc(),
                }
            )
    finally:
        if runtime:
            try:
                runtime.stop()
            except Exception:
                pass
        if runtime_thread:
            runtime_thread.join(timeout=8)
        if patch_target and original_usb:
            patch_target._list_removable_roots = original_usb
        if http_server:
            http_server.shutdown()
            http_server.server_close()
        if grpc_server:
            grpc_server.stop(grace=0)

    summary = build_summary(
        work_dir=work_dir,
        settings_path=settings_path,
        control=control,
        runtime=runtime,
        artifact_path=artifact_path,
        manual_upgrade_path=manual_upgrade_path,
        runtime_errors=runtime_errors,
        touched_paths=touched_paths,
    )
    report_path = work_dir / "test_agent_report.json"
    report_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"\nreport_path={report_path}")
    return 0 if summary["status"] == "ok" else 1


def main() -> int:
    args = parse_args()
    return run_full_harness(args)


if __name__ == "__main__":
    raise SystemExit(main())
