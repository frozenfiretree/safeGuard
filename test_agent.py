import argparse
import json
import os
import shutil
from pathlib import Path


def _configure_local_workdir(root: Path) -> Path:
    work_dir = root / ".agent_local_dryrun"
    os.environ["SAFEGUARD_AGENT_WORKDIR"] = str(work_dir)
    os.environ["SAFEGUARD_AGENT_SETTINGS_FILE"] = str(work_dir / "install_config.json")
    return work_dir


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run SafeGuard Agent in the foreground without installing a service or enabling autostart."
    )
    parser.add_argument(
        "scan_dirs",
        nargs="*",
        default=[r"C:\test"],
        help=r"Directory/directories to scan. Default: C:\test",
    )
    parser.add_argument(
        "--server-base",
        default="http://10.0.80.28",
        help="Server base URL. Default: http://10.0.80.28.",
    )
    parser.add_argument(
        "--work-dir",
        default=None,
        help="Local dry-run work directory. Default: .agent_local_dryrun under the project root.",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Delete the local test work directory before running.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Only run the local scanner. Do not register, heartbeat, upload, or contact the server.",
    )
    parser.add_argument(
        "--max-file-size-mb",
        type=int,
        default=100,
        help="Maximum file size to scan. Default: 100.",
    )
    return parser.parse_args()


def _write_settings(work_dir: Path, server_base: str) -> Path:
    work_dir.mkdir(parents=True, exist_ok=True)
    settings_path = work_dir / "install_config.json"
    settings_path.write_text(
        json.dumps(
            {
                "server_base": server_base.rstrip("/"),
                "work_dir": str(work_dir),
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    return settings_path


def _run_dry_scan(args: argparse.Namespace, work_dir: Path, settings_path: Path) -> int:
    import threading

    from agent_core.config import ensure_dirs, parse_runtime_config, setup_logging
    from agent_core.scanner import AgentScanner
    from agent_core.store import AgentStore

    ensure_dirs()
    logger = setup_logging("agent-local-dryrun")
    store = AgentStore()
    config = parse_runtime_config(
        {
            "scan_dirs": args.scan_dirs,
            "watch_dirs": [],
            "include_extensions": [
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
            ],
            "max_file_size_mb": args.max_file_size_mb,
        }
    )
    scanner = AgentScanner(store, logger, config)
    stats = scanner.initial_scan(threading.Event())

    print(
        json.dumps(
            {
                "status": "ok",
                "mode": "local-dryrun",
                "server_base": str(args.server_base).rstrip("/"),
                "work_dir": str(work_dir),
                "settings_file": str(settings_path),
                "scan_dirs": args.scan_dirs,
                "stats": stats,
                "network_disabled": True,
                "service_install_disabled": True,
                "autostart_disabled": True,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def _run_foreground_agent(args: argparse.Namespace, work_dir: Path, settings_path: Path) -> int:
    os.environ["SAFEGUARD_SERVER_BASE"] = str(args.server_base).rstrip("/")
    local_config = {
        "status": "ok",
        "config_version": 1,
        "scan_dirs": args.scan_dirs,
        "watch_dirs": [],
        "include_extensions": [
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
        ],
        "exclude_paths": [
            r"C:\Users\lyp\Downloads",
            r"C:\Users\lyp\Documents",
        ],
        "max_file_size_mb": args.max_file_size_mb,
        "heartbeat_interval_sec": 60,
        "config_pull_interval_sec": 300,
    }
    from agent_core.comms import ServerClient
    from agent_core.main import run_console

    def fetch_local_test_config(self):
        self.store.set_state("config_version", str(local_config["config_version"]))
        self.store.set_json_state("config_json", local_config)
        return dict(local_config)

    ServerClient.fetch_config = fetch_local_test_config

    print(
        json.dumps(
            {
                "status": "starting",
                "mode": "foreground-agent",
                "server_base": str(args.server_base).rstrip("/"),
                "work_dir": str(work_dir),
                "settings_file": str(settings_path),
                "scan_dirs": args.scan_dirs,
                "excluded_paths": local_config["exclude_paths"],
                "server_config_fetch_disabled": True,
                "register_enabled": True,
                "heartbeat_enabled": True,
                "upload_enabled": True,
                "service_install_disabled": True,
                "autostart_disabled": True,
                "stop": "Press Ctrl+C to stop.",
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    run_console()
    return 0


def main() -> int:
    project_root = Path(__file__).resolve().parent
    args = _parse_args()

    work_dir = Path(args.work_dir).resolve() if args.work_dir else _configure_local_workdir(project_root)
    os.environ["SAFEGUARD_AGENT_WORKDIR"] = str(work_dir)
    os.environ["SAFEGUARD_AGENT_SETTINGS_FILE"] = str(work_dir / "install_config.json")

    if args.clean and work_dir.exists():
        shutil.rmtree(work_dir)

    settings_path = _write_settings(work_dir, str(args.server_base))
    if args.dry_run:
        return _run_dry_scan(args, work_dir, settings_path)
    return _run_foreground_agent(args, work_dir, settings_path)


if __name__ == "__main__":
    raise SystemExit(main())
