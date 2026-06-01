import ctypes
import hashlib
import html
import json
import os
import subprocess
import sys
import threading
import time
import traceback
from pathlib import Path

import servicemanager
import win32service
import win32serviceutil

from .comms import ServerClient
from .config import (
    AGENT_VERSION,
    DEFAULT_SERVER_BASE,
    INSTALL_CONFIG_PATH,
    LOG_DIR,
    PROGRAM_DATA_DIR,
    SERVER_BASE,
    SERVICE_DESCRIPTION,
    SERVICE_DISPLAY_NAME,
    SERVICE_NAME,
    WORK_DIR,
    agent_config_diagnostics,
    default_grpc_target,
    ensure_dirs,
    parse_runtime_config,
    server_base_from_ip,
    setup_logging,
)
from .scanner import AgentScanner
from .store import AgentStore


ERROR_ALREADY_EXISTS = 183
RUNTIME_MUTEX_NAME = "Global\\SafeGuardAgentRuntime"
INSTALLER_MUTEX_NAME = "Global\\SafeGuardAgentInstaller"
SERVICE_ALREADY_RUNNING_ERROR = 1056
SERVICE_START_TIMEOUT_ERROR = 1053
UPGRADE_FAILURE_COOLDOWN_SECONDS = 3600
MIN_UPGRADE_EXE_SIZE_BYTES = 1024 * 1024


class AgentRuntime:
    def __init__(self):
        ensure_dirs()
        self.logger = setup_logging()
        self.store = AgentStore()
        self.store.recover_if_needed()
        self.store.reset_in_progress_tasks()
        self.client = ServerClient(self.store, self.logger)
        self._log_base_config()
        cached_config = self.store.get_json_state("config_json", {})
        self.runtime_config = parse_runtime_config(cached_config)
        self.client.request_timeout = int(self.runtime_config.request_timeout)
        self._log_runtime_config("cache" if cached_config else "defaults", self.runtime_config)
        self.scanner = AgentScanner(self.store, self.logger, self.runtime_config)
        self.stop_event = threading.Event()
        self.threads: dict[str, threading.Thread] = {}
        self._upgrade_lock = threading.Lock()
        self._server_switch_lock = threading.Lock()

    def _log_base_config(self):
        payload = agent_config_diagnostics()
        self.logger.info("agent base config effective=%s", json.dumps(payload, ensure_ascii=False, sort_keys=True))
        for conflict in payload.get("conflicts") or []:
            self.logger.warning("agent base config conflict=%s", json.dumps(conflict, ensure_ascii=False, sort_keys=True))

    def _log_runtime_config(self, source: str, runtime_config):
        payload = {
            "source": source,
            "config_version": runtime_config.config_version,
            "scan_roots": runtime_config.scan_roots,
            "watch_dirs": runtime_config.watch_dirs,
            "include_extensions": runtime_config.include_extensions,
            "exclude_paths": runtime_config.exclude_paths,
            "heartbeat_interval": runtime_config.heartbeat_interval,
            "config_pull_interval": runtime_config.config_pull_interval,
            "upload_workers": runtime_config.upload_workers,
            "request_timeout": runtime_config.request_timeout,
        }
        self.logger.info("agent runtime config effective=%s", json.dumps(payload, ensure_ascii=False, sort_keys=True))

    def set_state(self, value: str):
        self.store.set_current_state(value)
        self.logger.info("state -> %s", value)

    def start(self):
        self.set_state("STARTING")
        self._register_or_resume()
        self._load_or_fetch_config()
        self._start_workers()

        self.set_state("SCANNING")
        self.store.set_scan_completed(False)
        scan_stats = self.scanner.initial_scan(self.stop_event)
        self._report_scan_complete(scan_stats)
        if not self.stop_event.is_set():
            self.scanner.start_monitoring()
            self.set_state("RUNNING")

        while not self.stop_event.is_set():
            time.sleep(1)

    def stop(self):
        self.set_state("STOPPING")
        self.stop_event.set()
        try:
            self.scanner.stop_monitoring()
        except Exception:
            pass
        for thread in list(self.threads.values()):
            thread.join(timeout=5)

    def _register_or_resume(self):
        attempt = 0
        while not self.stop_event.is_set():
            try:
                self._handle_base_config_change()
                self.client.register()
                return
            except Exception as exc:
                attempt += 1
                cached_agent_id = self.store.get_state("agent_id")
                self.logger.warning("register failed: %s", exc)
                if cached_agent_id:
                    self.logger.info("using cached agent_id while offline: %s", cached_agent_id)
                    return
                self.client.backoff_sleep(attempt)

    def _load_or_fetch_config(self):
        self._handle_base_config_change()
        cached = self.store.get_json_state("config_json", {})
        if cached:
            self.runtime_config = parse_runtime_config(cached)
            self.client.request_timeout = int(self.runtime_config.request_timeout)
            self._log_runtime_config("cache", self.runtime_config)
            self.scanner.update_runtime_config(self.runtime_config)

        try:
            fresh = self.client.fetch_config()
            if fresh.get("status") == "ok":
                self.runtime_config = parse_runtime_config(fresh)
                self.client.request_timeout = int(self.runtime_config.request_timeout)
                self._log_runtime_config("server", self.runtime_config)
                self.scanner.update_runtime_config(self.runtime_config)
        except Exception as exc:
            self.logger.warning("initial config fetch failed, continue with cache: %s", exc)

    def _start_thread(self, name: str, target):
        thread = threading.Thread(target=target, name=name, daemon=True)
        thread.start()
        self.threads[name] = thread

    def _start_workers(self):
        self._start_thread("heartbeat", self._heartbeat_loop)
        self._start_thread("config-sync", self._config_loop)
        self._start_thread("debounce-flusher", lambda: self.scanner.flush_debounced_events(self.stop_event))
        self._start_thread("usb-poller", lambda: self.scanner.poll_usb_events(self.stop_event))
        self._start_thread("maintenance", self._maintenance_loop)
        for index in range(max(1, int(self.runtime_config.upload_workers))):
            self._start_thread(f"uploader-{index + 1}", self._uploader_loop)

    def _heartbeat_loop(self):
        failures = 0
        while not self.stop_event.is_set():
            try:
                if self._handle_base_config_change():
                    failures = 0
                    continue
                result = self.client.heartbeat(
                    self.store.get_current_state(),
                    self.store.get_state("config_version", "") or "",
                    self.store.pending_task_count(),
                )
                if self.store.get_current_state() == "OFFLINE":
                    self.set_state("RUNNING" if self.store.is_scan_completed() else "SCANNING")
                failures = 0
                self._handle_piggyback(result)
                self._ensure_threads_alive()
            except Exception as exc:
                failures += 1
                self.logger.warning("heartbeat failed: %s", exc)
                if failures >= 3:
                    self.set_state("OFFLINE")
            self.stop_event.wait(self.runtime_config.heartbeat_interval)

    def _config_loop(self):
        while not self.stop_event.is_set():
            try:
                if self._handle_base_config_change():
                    continue
                data = self.client.fetch_config()
                if data.get("status") == "ok":
                    self.runtime_config = parse_runtime_config(data)
                    self.client.request_timeout = int(self.runtime_config.request_timeout)
                    self._log_runtime_config("server", self.runtime_config)
                    self.scanner.update_runtime_config(self.runtime_config)
                    if self.store.is_scan_completed():
                        self.scanner.start_monitoring()
                    if self.store.get_current_state() == "OFFLINE":
                        self.set_state("RUNNING")
            except Exception as exc:
                self.logger.warning("config sync failed: %s", exc)
            self.stop_event.wait(self.runtime_config.config_pull_interval)

    def _uploader_loop(self):
        while not self.stop_event.is_set():
            if self._handle_base_config_change():
                continue
            event_tasks = self.store.fetch_pending_tasks(limit=self.runtime_config.event_batch_size, task_type="EVENT")
            if event_tasks:
                claimed = [task for task in event_tasks if self.store.claim_task(task["task_id"])]
                if claimed:
                    try:
                        self._process_event_batch(claimed)
                        for task in claimed:
                            self.store.complete_task(task["task_id"])
                    except Exception as exc:
                        self.logger.warning("event batch failed: %s", exc)
                        for task in claimed:
                            self.store.retry_task(task["task_id"], str(exc))
                    continue

            tasks = self.store.fetch_pending_tasks(limit=1, task_type="UPLOAD")
            if not tasks:
                self.stop_event.wait(2)
                continue

            for task in tasks:
                if self.stop_event.is_set():
                    break
                task_id = task["task_id"]
                if not self.store.claim_task(task_id):
                    continue
                try:
                    payload = self._decode_payload(task["payload"])
                    if task["task_type"] == "UPLOAD":
                        self._process_upload_task(payload)
                    self.store.complete_task(task_id)
                except Exception as exc:
                    self.logger.warning("task failed: id=%s, error=%s", task_id, exc)
                    self.store.retry_task(task_id, str(exc))

    def _decode_payload(self, payload: str | dict):
        if isinstance(payload, dict):
            return payload
        return json.loads(payload)

    def _process_upload_task(self, payload: dict):
        path = Path(payload["path"])
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(path)
        response = self.client.submit_file(payload, self.runtime_config.chunk_size_bytes, self.stop_event)
        if response.get("status") != "ok":
            raise RuntimeError(f"upload response not ok: {response}")
        self.store.mark_uploaded(payload["normalized_path"], payload["sha256"])
        self.logger.info("upload task done: %s", payload["path"])

    def _process_event_batch(self, tasks: list[dict]):
        payloads = [self._decode_payload(item["payload"]) for item in tasks]
        self.client.submit_events_batch(payloads)
        self.logger.info("event batch done: count=%s", len(payloads))

    def _handle_piggyback(self, payload: dict):
        if payload.get("config_changed"):
            try:
                data = self.client.fetch_config()
                if data.get("status") == "ok":
                    self.runtime_config = parse_runtime_config(data)
                    self.client.request_timeout = int(self.runtime_config.request_timeout)
                    self._log_runtime_config("server", self.runtime_config)
                    self.scanner.update_runtime_config(self.runtime_config)
            except Exception as exc:
                self.logger.warning("piggyback config refresh failed: %s", exc)

        upgrade = payload.get("upgrade")
        if upgrade:
            self._handle_upgrade(upgrade)

    def _report_scan_complete(self, stats: dict):
        try:
            self._handle_base_config_change()
            self.client.submit_scan_complete(stats)
        except Exception as exc:
            self.logger.warning("scan complete report failed: %s", exc)

    def _maintenance_loop(self):
        while not self.stop_event.is_set():
            try:
                self._handle_base_config_change()
                self.store.cleanup_tasks()
                self._retry_pending_upgrade_report()
            except Exception as exc:
                self.logger.warning("maintenance failed: %s", exc)
            self.stop_event.wait(600)

    def _handle_upgrade(self, upgrade: dict):
        version = str(upgrade.get("version") or "").strip()
        checksum = str(upgrade.get("checksum") or "").strip().lower()
        if not version:
            return
        upgrade_key = f"{version}:{checksum or 'no-checksum'}"
        if self._consume_upgrade_rollback_marker(version, checksum, upgrade_key):
            return
        current_exe_checksum = ""
        if getattr(sys, "frozen", False):
            try:
                current_exe_checksum = self._sha256_of_path(Path(sys.executable))
            except Exception:
                current_exe_checksum = ""
        if version == AGENT_VERSION and (not checksum or checksum == current_exe_checksum):
            if self.store.get_state("last_successful_upgrade_key", "") != upgrade_key:
                self._report_upgrade_result(
                    {
                        "old_version": AGENT_VERSION,
                        "new_version": version,
                        "success": True,
                        "error_message": "agent is already running the requested version",
                    }
                )
                self.store.set_state("last_successful_upgrade_key", upgrade_key)
            return
        failed_key = self.store.get_state("last_failed_upgrade_key", "")
        try:
            failed_at = float(self.store.get_state("last_failed_upgrade_at", "0") or 0)
        except Exception:
            failed_at = 0
        if failed_key == upgrade_key and time.time() - failed_at < UPGRADE_FAILURE_COOLDOWN_SECONDS:
            self.logger.warning("skip repeated upgrade attempt during cooldown: version=%s checksum=%s", version, checksum)
            return
        if not self._upgrade_lock.acquire(blocking=False):
            return
        restart_scheduled = False
        try:
            self.set_state("UPGRADING")
            updates_dir = PROGRAM_DATA_DIR / "updates" / version
            target = updates_dir / "SafeGuardAgent.exe"
            self.store.set_json_state(
                "last_upgrade_attempt",
                {
                    "version": version,
                    "checksum": checksum,
                    "target": str(target),
                    "started_at": time.time(),
                    "status": "downloading",
                },
            )
            self.client.download_upgrade(version, target)
            self._validate_upgrade_exe(target)
            if checksum and self._sha256_of_path(target) != checksum:
                raise RuntimeError("upgrade checksum mismatch")
            self.store.set_json_state(
                "last_upgrade_attempt",
                {
                    "version": version,
                    "checksum": checksum,
                    "target": str(target),
                    "started_at": time.time(),
                    "status": "applying",
                },
            )
            restart_scheduled = self._apply_service_upgrade(target, version, checksum)
            self._report_upgrade_result(
                {
                    "old_version": AGENT_VERSION,
                    "new_version": version,
                    "success": True,
                    "error_message": None if restart_scheduled else "package downloaded; service restart skipped in non-service mode",
                }
            )
            self.store.set_state("last_successful_upgrade_key", upgrade_key)
            self.store.set_json_state(
                "last_upgrade_attempt",
                {
                    "version": version,
                    "checksum": checksum,
                    "target": str(target),
                    "completed_at": time.time(),
                    "status": "restart_scheduled" if restart_scheduled else "downloaded_only",
                },
            )
            self.logger.info("upgrade package downloaded: version=%s, path=%s", version, target)
        except Exception as exc:
            self.logger.warning("upgrade handling failed: %s", exc)
            self.store.set_state("last_failed_upgrade_key", upgrade_key)
            self.store.set_state("last_failed_upgrade_at", str(time.time()))
            self.store.set_json_state(
                "last_upgrade_attempt",
                {
                    "version": version,
                    "checksum": checksum,
                    "failed_at": time.time(),
                    "status": "failed",
                    "error": str(exc),
                },
            )
            self._report_upgrade_result(
                {
                    "old_version": AGENT_VERSION,
                    "new_version": version,
                    "success": False,
                    "error_message": str(exc),
                }
            )
        finally:
            if not self.stop_event.is_set() and not restart_scheduled:
                self.set_state("RUNNING" if self.store.is_scan_completed() else "SCANNING")
            self._upgrade_lock.release()

    def _consume_upgrade_rollback_marker(self, version: str, checksum: str, upgrade_key: str) -> bool:
        marker = PROGRAM_DATA_DIR / "updates" / version / "upgrade_failed.json"
        if not marker.exists():
            return False
        try:
            data = json.loads(marker.read_text(encoding="utf-8"))
        except Exception:
            data = {}
        marker_checksum = str(data.get("checksum") or "").strip().lower()
        if marker_checksum and marker_checksum != checksum:
            return False
        error_message = str(data.get("error") or "new agent executable failed to start; rolled back to previous executable")
        self.logger.warning("upgrade rollback marker found: version=%s checksum=%s error=%s", version, checksum, error_message)
        self.store.set_state("last_failed_upgrade_key", upgrade_key)
        self.store.set_state("last_failed_upgrade_at", str(time.time()))
        self.store.set_json_state(
            "last_upgrade_attempt",
            {
                "version": version,
                "checksum": checksum,
                "failed_at": time.time(),
                "status": "rolled_back",
                "error": error_message,
            },
        )
        self._report_upgrade_result(
            {
                "old_version": AGENT_VERSION,
                "new_version": version,
                "success": False,
                "error_message": error_message,
            }
        )
        try:
            marker.unlink()
        except Exception:
            pass
        return True

    def _report_upgrade_result(self, payload: dict):
        self.store.set_json_state("last_upgrade_report_payload", payload)
        try:
            result = self.client.report_upgrade_result(payload)
            self.store.set_json_state("last_upgrade_report_result", result)
            self.store.set_state("last_upgrade_report_at", str(time.time()))
            self.store.set_json_state("last_upgrade_report_error", None)
            return result
        except Exception as exc:
            self.logger.warning("upgrade report failed: %s", exc)
            self.store.set_json_state("last_upgrade_report_error", {"error": str(exc), "at": time.time()})
            return None

    def _retry_pending_upgrade_report(self):
        error = self.store.get_json_state("last_upgrade_report_error", None)
        payload = self.store.get_json_state("last_upgrade_report_payload", None)
        if not error or not isinstance(payload, dict):
            return
        try:
            result = self.client.report_upgrade_result(payload)
            self.store.set_json_state("last_upgrade_report_result", result)
            self.store.set_state("last_upgrade_report_at", str(time.time()))
            self.store.set_json_state("last_upgrade_report_error", None)
        except Exception as exc:
            self.logger.warning("pending upgrade report retry failed: %s", exc)

    def _sha256_of_path(self, path: Path) -> str:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest().lower()

    def _validate_upgrade_exe(self, target: Path):
        if not target.exists() or not target.is_file():
            raise RuntimeError(f"upgrade package not found after download: {target}")
        size = target.stat().st_size
        if size < MIN_UPGRADE_EXE_SIZE_BYTES:
            raise RuntimeError(f"upgrade package is too small to be a valid agent executable: {size} bytes")
        with open(target, "rb") as handle:
            if handle.read(2) != b"MZ":
                raise RuntimeError("upgrade package is not a Windows executable")

    def _apply_service_upgrade(self, target: Path, version: str, checksum: str) -> bool:
        if not getattr(sys, "frozen", False):
            self.logger.info("skip service binary switch in non-frozen mode")
            return False
        current_exe = Path(sys.executable).resolve()
        if current_exe == target.resolve():
            self.logger.info("upgrade target is current executable; no service switch needed")
            return False

        scm = None
        service = None
        try:
            scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)
            service = win32service.OpenService(scm, SERVICE_NAME, win32service.SERVICE_ALL_ACCESS)
            script = self._write_upgrade_restart_script(current_exe, target, version, checksum)
            self._schedule_service_restart(script)
            return True
        finally:
            if service:
                win32service.CloseServiceHandle(service)
            if scm:
                win32service.CloseServiceHandle(scm)

    def _write_upgrade_restart_script(self, previous_exe: Path, target: Path, version: str, checksum: str) -> Path:
        script_dir = PROGRAM_DATA_DIR / "updates" / version
        script_dir.mkdir(parents=True, exist_ok=True)
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        script_path = script_dir / "apply_upgrade.cmd"
        log_path = LOG_DIR / "agent_upgrade.log"
        marker_path = script_dir / "upgrade_failed.json"
        content = f"""@echo off
setlocal EnableExtensions
set "SERVICE={SERVICE_NAME}"
set "NEW_EXE={target}"
set "OLD_EXE={previous_exe}"
set "LOG={log_path}"
set "MARKER={marker_path}"
echo [%date% %time%] applying SafeGuard Agent upgrade version={version} checksum={checksum} >> "%LOG%"
if exist "%MARKER%" del /f /q "%MARKER%" >nul 2>nul
sc stop "%SERVICE%" >> "%LOG%" 2>>&1
for /l %%i in (1,1,45) do (
  sc query "%SERVICE%" | findstr /I "STOPPED" >nul 2>nul
  if not errorlevel 1 goto stopped
  ping 127.0.0.1 -n 2 >nul
)
:stopped
sc config "%SERVICE%" binPath= "\"%NEW_EXE%\" --service" >> "%LOG%" 2>>&1
sc start "%SERVICE%" >> "%LOG%" 2>>&1
for /l %%i in (1,1,45) do (
  sc query "%SERVICE%" | findstr /I "RUNNING" >nul 2>nul
  if not errorlevel 1 goto success
  ping 127.0.0.1 -n 2 >nul
)
echo [%date% %time%] new service failed to reach RUNNING; rolling back >> "%LOG%"
echo {{"version":"{version}","checksum":"{checksum}","failed_at":"%date% %time%","error":"new agent executable failed to reach RUNNING; rolled back to previous executable"}} > "%MARKER%"
sc stop "%SERVICE%" >> "%LOG%" 2>>&1
ping 127.0.0.1 -n 4 >nul
sc config "%SERVICE%" binPath= "\"%OLD_EXE%\" --service" >> "%LOG%" 2>>&1
sc start "%SERVICE%" >> "%LOG%" 2>>&1
exit /b 1
:success
echo [%date% %time%] upgrade service start succeeded >> "%LOG%"
exit /b 0
"""
        script_path.write_text(content, encoding="utf-8")
        return script_path

    def _schedule_service_restart(self, script: Path):
        subprocess.Popen(
            ["cmd", "/c", str(script)],
            creationflags=getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
            close_fds=True,
        )

    def _ensure_threads_alive(self):
        for name, thread in list(self.threads.items()):
            if thread.is_alive():
                continue
            self.logger.warning("worker thread died, rebuilding: %s", name)
            if name.startswith("uploader-"):
                self._start_thread(name, self._uploader_loop)
            elif name == "heartbeat":
                self._start_thread(name, self._heartbeat_loop)
            elif name == "config-sync":
                self._start_thread(name, self._config_loop)
            elif name == "debounce-flusher":
                self._start_thread(name, lambda: self.scanner.flush_debounced_events(self.stop_event))
            elif name == "usb-poller":
                self._start_thread(name, lambda: self.scanner.poll_usb_events(self.stop_event))
            elif name == "maintenance":
                self._start_thread(name, self._maintenance_loop)

    def _handle_base_config_change(self) -> bool:
        _, server_changed = self.client.refresh_base_config()
        if not server_changed:
            return False
        if not self._server_switch_lock.acquire(blocking=False):
            self.stop_event.wait(1)
            return True
        try:
            if self.stop_event.is_set():
                return True
            self.logger.warning("server address changed; clearing local state and bootstrapping against new server")
            self.set_state("RECONFIGURING")
            try:
                self.scanner.stop_monitoring()
            except Exception:
                pass
            self.store.clear_runtime_state_for_server_switch()
            self.store.set_scan_completed(False)
            self._register_or_resume()
            self._load_or_fetch_config()
            if self.stop_event.is_set():
                return True
            self.set_state("SCANNING")
            scan_stats = self.scanner.initial_scan(self.stop_event)
            self._report_scan_complete(scan_stats)
            if not self.stop_event.is_set():
                self.scanner.start_monitoring()
                self.set_state("RUNNING")
            return True
        finally:
            self._server_switch_lock.release()


class AgentWindowsService(win32serviceutil.ServiceFramework):
    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = SERVICE_DISPLAY_NAME
    _svc_description_ = SERVICE_DESCRIPTION

    def __init__(self, args):
        super().__init__(args)
        self.runtime = AgentRuntime()

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.runtime.stop()

    def SvcDoRun(self):
        servicemanager.LogInfoMsg(f"{SERVICE_NAME} starting")
        try:
            self.ReportServiceStatus(win32service.SERVICE_RUNNING)
            self.runtime.start()
            servicemanager.LogInfoMsg(f"{SERVICE_NAME} stopped")
        except Exception as exc:
            try:
                self.runtime.logger.exception("service runtime crashed: %s", exc)
            except Exception:
                pass
            servicemanager.LogErrorMsg(f"{SERVICE_NAME} crashed: {exc}\n{traceback.format_exc()}")
            raise


def _message_box(title: str, message: str, flags: int = 0x40):
    try:
        ctypes.windll.user32.MessageBoxW(None, message, title, flags)
    except Exception:
        pass


class _SingleInstanceGuard:
    def __init__(self, name: str):
        self.name = name
        self.handle = None

    def acquire(self) -> bool:
        kernel32 = ctypes.windll.kernel32
        kernel32.SetLastError(0)
        self.handle = kernel32.CreateMutexW(None, False, self.name)
        if not self.handle:
            return False
        return kernel32.GetLastError() != ERROR_ALREADY_EXISTS

    def release(self):
        if not self.handle:
            return
        kernel32 = ctypes.windll.kernel32
        kernel32.ReleaseMutex(self.handle)
        kernel32.CloseHandle(self.handle)
        self.handle = None


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _is_runtime_already_running() -> bool:
    guard = _SingleInstanceGuard(RUNTIME_MUTEX_NAME)
    if not guard.acquire():
        return True
    guard.release()
    return False


def _service_exe_path() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve()
    return Path(__file__).resolve().parents[1] / "agent.py"


def _packaged_install_settings() -> dict:
    path = _service_exe_path().with_name("agent-install.json")
    try:
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def _read_install_settings(path: Path = INSTALL_CONFIG_PATH) -> dict:
    try:
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def _write_install_settings(server_base: str, work_dir: str, grpc_upload_target: str):
    PROGRAM_DATA_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "server_base": server_base.rstrip("/"),
        "work_dir": str(Path(work_dir)),
        "grpc_upload_target": grpc_upload_target,
        "written_by": "safeguard_agent_installer",
        "written_at": time.time(),
    }
    INSTALL_CONFIG_PATH.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _clear_local_state_for_server_switch(work_dir: str):
    store = AgentStore(Path(work_dir) / "agent.db")
    store.clear_runtime_state_for_server_switch()


def _run_sc(*args: str):
    return subprocess.run(
        ["sc.exe", *args],
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
    )


def _read_service_state() -> str:
    result = _run_sc("query", SERVICE_NAME)
    if result.returncode != 0:
        return "NOT_INSTALLED"
    text = result.stdout or ""
    if "RUNNING" in text:
        return "RUNNING"
    if "STOPPED" in text:
        return "STOPPED"
    if "START_PENDING" in text:
        return "START_PENDING"
    if "STOP_PENDING" in text:
        return "STOP_PENDING"
    return "UNKNOWN"


def _requested_grpc_target(server_base: str) -> str:
    return str(_value_after_flag("--grpc-upload-target") or default_grpc_target(server_base))


def _requested_work_dir() -> str:
    return str(_value_after_flag("--work-dir") or WORK_DIR)


def _install_request_changes_existing_config(server_base: str, grpc_upload_target: str) -> bool:
    existing_settings = _read_install_settings()
    previous_server_base = str(existing_settings.get("server_base") or "").rstrip("/")
    previous_grpc_target = str(existing_settings.get("grpc_upload_target") or "").strip()
    if not previous_server_base:
        return False
    return previous_server_base != server_base.rstrip("/") or (
        bool(previous_grpc_target) and previous_grpc_target != str(grpc_upload_target).strip()
    )


def _safe_start_service() -> bool:
    state = _read_service_state()
    if state == "RUNNING":
        return True
    try:
        win32serviceutil.StartService(SERVICE_NAME)
        return True
    except Exception as exc:
        winerror = getattr(exc, "winerror", None)
        if winerror == SERVICE_ALREADY_RUNNING_ERROR:
            return True
        if winerror == SERVICE_START_TIMEOUT_ERROR:
            try:
                logger = setup_logging()
                logger.warning("service start timed out; current_state=%s error=%s", _read_service_state(), exc)
            except Exception:
                pass
            return False
        raise


def _show_already_running_message(server_base: str, work_dir: str, grpc_upload_target: str, server_changed: bool = False):
    if server_changed:
        message = (
            "SafeGuard Agent is already running.\n\n"
            "The requested server address is different from the installed configuration. "
            "Run this installer as administrator to switch servers and restart the service.\n\n"
            f"Requested server: {server_base}\n"
            f"Work directory: {work_dir}\n"
            f"gRPC upload target: {grpc_upload_target}"
        )
    else:
        message = (
            "SafeGuard Agent is already running.\n\n"
            "No second Agent process was started.\n\n"
            f"Server: {server_base}\n"
            f"Work directory: {work_dir}\n"
            f"gRPC upload target: {grpc_upload_target}\n"
            f"Service state: {_read_service_state()}"
        )
    _message_box("SafeGuard Agent", message)


def _format_time_text(raw_value) -> str:
    try:
        value = float(raw_value)
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(value))
    except Exception:
        return "-"


def _build_install_report_html(
    *,
    server_base: str,
    work_dir: str,
    service_state: str,
    agent_id: str,
    config_version: str,
    register_at: str,
    register_result: dict | None,
    heartbeat_at: str,
    heartbeat_result: dict | None,
    scan_roots: list[str],
    grpc_upload_target: str,
    config_sources: dict | None,
) -> str:
    scan_roots_html = "".join(f"<li>{html.escape(item)}</li>" for item in scan_roots) or "<li>(未获取到)</li>"
    register_json = html.escape(json.dumps(register_result or {}, ensure_ascii=False, indent=2))
    heartbeat_json = html.escape(json.dumps(heartbeat_result or {}, ensure_ascii=False, indent=2))
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <title>SafeGuard Agent 安装结果</title>
  <style>
    body {{ font-family: "Microsoft YaHei UI", "Segoe UI", sans-serif; background:#f5f7fb; color:#162031; margin:0; padding:24px; }}
    .card {{ max-width:920px; margin:0 auto; background:#fff; border-radius:16px; padding:24px 28px; box-shadow:0 14px 40px rgba(20,33,61,.12); }}
    h1 {{ margin:0 0 8px; font-size:28px; }}
    .muted {{ color:#5d6b82; margin-bottom:20px; }}
    .grid {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:14px; margin:18px 0 24px; }}
    .item {{ background:#f7f9fc; border:1px solid #e3e9f3; border-radius:12px; padding:14px 16px; }}
    .label {{ font-size:12px; color:#617089; text-transform:uppercase; letter-spacing:.04em; }}
    .value {{ margin-top:6px; font-size:15px; word-break:break-word; }}
    h2 {{ margin:22px 0 10px; font-size:18px; }}
    ul {{ margin:8px 0 0 18px; }}
    pre {{ background:#0f172a; color:#dbeafe; padding:14px; border-radius:12px; overflow:auto; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>SafeGuard Agent 安装完成</h1>
    <div class="muted">服务已安装并尝试启动，以下是当前检测到的生效信息。</div>
    <div class="grid">
      <div class="item"><div class="label">服务端地址</div><div class="value">{html.escape(server_base)}</div></div>
      <div class="item"><div class="label">工作目录</div><div class="value">{html.escape(work_dir)}</div></div>
      <div class="item"><div class="label">gRPC 上传地址</div><div class="value">{html.escape(grpc_upload_target)}</div></div>
      <div class="item"><div class="label">主配置文件</div><div class="value">{html.escape(str(INSTALL_CONFIG_PATH))}</div></div>
      <div class="item"><div class="label">服务状态</div><div class="value">{html.escape(service_state)}</div></div>
      <div class="item"><div class="label">Agent ID</div><div class="value">{html.escape(agent_id or "-")}</div></div>
      <div class="item"><div class="label">当前配置版本</div><div class="value">{html.escape(config_version or "-")}</div></div>
      <div class="item"><div class="label">最近注册时间</div><div class="value">{html.escape(register_at)}</div></div>
      <div class="item"><div class="label">最近心跳时间</div><div class="value">{html.escape(heartbeat_at)}</div></div>
      <div class="item"><div class="label">日志目录</div><div class="value">{html.escape(str(Path(work_dir) / "logs"))}</div></div>
    </div>
    <h2>当前生效扫描目录</h2>
    <ul>{scan_roots_html}</ul>
    <h2>基础配置来源</h2>
    <pre>{html.escape(json.dumps(config_sources or {}, ensure_ascii=False, indent=2))}</pre>
    <h2>最近一次注册结果</h2>
    <pre>{register_json}</pre>
    <h2>最近一次心跳结果</h2>
    <pre>{heartbeat_json}</pre>
  </div>
</body>
</html>
"""


def _show_install_result_page(*, server_base: str, work_dir: str, grpc_upload_target: str, temp_store: AgentStore, scan_roots: list[str]):
    agent_id = temp_store.get_state("agent_id", "") or ""
    config_version = temp_store.get_state("config_version", "") or ""
    register_at = _format_time_text(temp_store.get_state("last_register_at", ""))
    register_result = temp_store.get_json_state("last_register_result", {})
    heartbeat_at = _format_time_text(temp_store.get_state("last_heartbeat_at", ""))
    heartbeat_result = temp_store.get_json_state("last_heartbeat_result", {})
    service_state = _read_service_state()
    report_path = Path(work_dir) / "install_result.html"
    report_path.write_text(
        _build_install_report_html(
            server_base=server_base,
            work_dir=work_dir,
            grpc_upload_target=grpc_upload_target,
            config_sources=agent_config_diagnostics(),
            service_state=service_state,
            agent_id=agent_id,
            config_version=config_version,
            register_at=register_at,
            register_result=register_result,
            heartbeat_at=heartbeat_at,
            heartbeat_result=heartbeat_result,
            scan_roots=scan_roots,
        ),
        encoding="utf-8",
    )
    try:
        os.startfile(str(report_path))
        return
    except Exception:
        pass
    _message_box(
        "SafeGuard Agent",
        "安装完成，服务已启动。\n\n"
        f"服务端地址: {server_base}\n"
        f"工作目录: {work_dir}\n"
        f"gRPC 上传地址: {grpc_upload_target}\n"
        f"主配置文件: {INSTALL_CONFIG_PATH}\n"
        f"服务状态: {service_state}\n"
        f"Agent ID: {agent_id or '-'}\n"
        f"当前配置版本: {config_version or '-'}\n"
        f"最近注册时间: {register_at}\n"
        f"最近心跳时间: {heartbeat_at}",
    )


def _service_exists() -> bool:
    return _run_sc("query", SERVICE_NAME).returncode == 0


def _stop_service_if_exists():
    if not _service_exists():
        return
    subprocess.run(["sc.exe", "stop", SERVICE_NAME], capture_output=True, text=True, errors="replace", check=False)
    for _ in range(30):
        state = _run_sc("query", SERVICE_NAME).stdout
        if "STOPPED" in state or "FAILED 1060" in state:
            return
        time.sleep(1)


def _configure_existing_service(exe_path: Path):
    if getattr(sys, "frozen", False):
        try:
            _run_sc("config", SERVICE_NAME, "binPath=", f'"{exe_path}" --service')
        except Exception:
            pass
    _run_sc("config", SERVICE_NAME, "start=", "auto")
    _run_sc("failure", SERVICE_NAME, "reset=", "86400", "actions=", "restart/60000/restart/60000/restart/300000")
    _run_sc("failureflag", SERVICE_NAME, "1")


def _install_service(server_base: str | None = None, work_dir: str | None = None, grpc_upload_target: str | None = None, auto_start: bool = True):
    server_base = str(server_base or SERVER_BASE or DEFAULT_SERVER_BASE).rstrip("/")
    work_dir = str(work_dir or WORK_DIR)
    grpc_upload_target = str(grpc_upload_target or default_grpc_target(server_base))
    exe_path = _service_exe_path()
    existing_settings = _read_install_settings()
    previous_server_base = str(existing_settings.get("server_base") or "").rstrip("/")
    previous_grpc_target = str(existing_settings.get("grpc_upload_target") or "").strip()
    previous_work_dir = str(existing_settings.get("work_dir") or work_dir)
    service_exists = _service_exists()
    server_changed = bool(previous_server_base) and (
        previous_server_base != server_base or (previous_grpc_target and previous_grpc_target != grpc_upload_target)
    )

    Path(work_dir).mkdir(parents=True, exist_ok=True)

    if service_exists and not server_changed:
        _write_install_settings(server_base, work_dir, grpc_upload_target)
        _configure_existing_service(exe_path)
        if auto_start:
            _safe_start_service()
        return

    if service_exists:
        _stop_service_if_exists()
        if server_changed:
            if previous_work_dir and previous_work_dir != work_dir:
                _clear_local_state_for_server_switch(previous_work_dir)
            _clear_local_state_for_server_switch(work_dir)
    _write_install_settings(server_base, work_dir, grpc_upload_target)
    if service_exists:
        try:
            win32serviceutil.RemoveService(SERVICE_NAME)
        except Exception:
            pass
        time.sleep(1)

    win32serviceutil.InstallService(
        f"{AgentWindowsService.__module__}.{AgentWindowsService.__name__}",
        SERVICE_NAME,
        SERVICE_DISPLAY_NAME,
        startType=win32service.SERVICE_AUTO_START,
        exeName=str(exe_path),
        exeArgs="--service",
        description=SERVICE_DESCRIPTION,
    )
    _configure_existing_service(exe_path)
    if auto_start:
        _safe_start_service()


def _remove_service():
    if not _service_exists():
        return
    _stop_service_if_exists()
    win32serviceutil.RemoveService(SERVICE_NAME)


def _restart_service():
    _stop_service_if_exists()
    _safe_start_service()


def _elevate_for_install(server_base: str, work_dir: str, grpc_upload_target: str) -> bool:
    exe_path = str(_service_exe_path())
    params = f'--self-install --server-base "{server_base}" --work-dir "{work_dir}" --grpc-upload-target "{grpc_upload_target}"'
    result = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe_path, params, None, 1)
    if int(result) <= 32:
        _message_box(
            "SafeGuard Agent",
            "SafeGuard Agent needs administrator permission to install or update the Windows service.\n\n"
            f"Elevation failed or was cancelled. Code: {int(result)}",
            0x30,
        )
        return False
    return True


def _value_after_flag(flag: str) -> str | None:
    if flag not in sys.argv:
        return None
    index = sys.argv.index(flag)
    if index + 1 >= len(sys.argv):
        return None
    return sys.argv[index + 1]


def _requested_server_base() -> str:
    server_ip = _value_after_flag("--server-ip")
    if server_ip:
        return server_base_from_ip(server_ip)
    return str(_value_after_flag("--server-base") or SERVER_BASE or DEFAULT_SERVER_BASE).rstrip("/")


def _self_install():
    installer_guard = _SingleInstanceGuard(INSTALLER_MUTEX_NAME)
    if not installer_guard.acquire():
        _message_box("SafeGuard Agent", "已有另一个 SafeGuard 安装程序正在运行。")
        return
    server_base = _requested_server_base()
    work_dir = _requested_work_dir()
    grpc_upload_target = _requested_grpc_target(server_base)
    server_changed = _install_request_changes_existing_config(server_base, grpc_upload_target)
    try:
        if _is_runtime_already_running() and not server_changed:
            _show_already_running_message(server_base, work_dir, grpc_upload_target)
            return
        if _is_runtime_already_running() and server_changed and not _is_admin():
            _show_already_running_message(server_base, work_dir, grpc_upload_target, server_changed=True)
            return
        if not _is_admin():
            _elevate_for_install(server_base, work_dir, grpc_upload_target)
            return

        _install_service(server_base=server_base, work_dir=work_dir, grpc_upload_target=grpc_upload_target, auto_start=True)
        effective_scan_roots = []
        temp_store = None
        try:
            temp_store = AgentStore(Path(work_dir) / "agent.db")
            config_data = None
            for _ in range(10):
                config_data = temp_store.get_json_state("config_json", None)
                if config_data:
                    break
                time.sleep(1)
            runtime_config = parse_runtime_config(config_data or {})
            effective_scan_roots = list(runtime_config.scan_roots or [])
        except Exception:
            effective_scan_roots = []

        if not effective_scan_roots:
            try:
                effective_scan_roots = list(parse_runtime_config({}).scan_roots or [])
            except Exception:
                effective_scan_roots = []
        temp_store = temp_store or AgentStore(Path(work_dir) / "agent.db")
        _show_install_result_page(
            server_base=server_base,
            work_dir=work_dir,
            grpc_upload_target=grpc_upload_target,
            temp_store=temp_store,
            scan_roots=effective_scan_roots,
        )
    finally:
        installer_guard.release()


def run_console():
    guard = _SingleInstanceGuard(RUNTIME_MUTEX_NAME)
    if not guard.acquire():
        _message_box("SafeGuard Agent", "检测到本机已有 SafeGuard Agent 正在运行。")
        return
    runtime = AgentRuntime()
    try:
        runtime.start()
    except KeyboardInterrupt:
        runtime.logger.info("console stop requested")
    finally:
        runtime.stop()
        guard.release()


def run_service():
    guard = _SingleInstanceGuard(RUNTIME_MUTEX_NAME)
    if not guard.acquire():
        servicemanager.LogErrorMsg(f"{SERVICE_NAME} already running, skip duplicate service instance")
        return
    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(AgentWindowsService)
    try:
        servicemanager.StartServiceCtrlDispatcher()
    finally:
        guard.release()


def entrypoint():
    if "--service" in sys.argv:
        run_service()
        return

    if "--self-install" in sys.argv:
        _self_install()
        return

    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        if command == "install":
            install_server_base = _requested_server_base()
            _install_service(
                server_base=install_server_base,
                work_dir=_requested_work_dir(),
                grpc_upload_target=_requested_grpc_target(install_server_base),
                auto_start=True,
            )
            return
        if command == "remove":
            _remove_service()
            return
        if command == "start":
            _safe_start_service()
            return
        if command == "stop":
            _stop_service_if_exists()
            return
        if command == "restart":
            _restart_service()
            return
        if command == "debug":
            run_console()
            return
        if "--server-ip" in sys.argv or "--server-base" in sys.argv:
            _self_install()
            return
        win32serviceutil.HandleCommandLine(AgentWindowsService)
        return

    if getattr(sys, "frozen", False):
        _self_install()
        return

    run_console()
