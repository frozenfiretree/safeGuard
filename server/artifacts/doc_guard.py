#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
doc_guard.py — 通用文档操作监控器 (Windows)
==============================================

这是整合版单文件脚本：
  - 保留旧版 doc_guard.py 的运行和使用方式（--run / --rescan / --status / 自启管理）
  - 内部引入 doc_monitor.py 的高性能监控链路（前置过滤、异步队列、去抖、稳定等待、批量写库、低频重扫）
  - 兼容旧版的输出目录、日志文件命名、显式文件、监控目录、自启安装与状态查看
  - 保留旧版可选的进程归因与 Windows Security 审计增强能力

推荐依赖：
  pip install watchdog portalocker psutil
可选增强：
  pip install pywin32

默认运行方式保持不变：
  python doc_guard.py --run
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import fnmatch
import hashlib
import json
import logging
import logging.handlers
import os
import pathlib
import platform
import subprocess
import re
import queue
import signal
import sqlite3
import sys
import tempfile
import threading
import time
import traceback
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

# ─────────────────────────────────────────────────────────────
# 第三方依赖
# ─────────────────────────────────────────────────────────────
try:
    from watchdog.observers import Observer          # Windows 上默认用 ReadDirectoryChangesW
    from watchdog.observers.polling import PollingObserver
    from watchdog.events import (
        FileSystemEventHandler,
        FileCreatedEvent,
        FileDeletedEvent,
        FileModifiedEvent,
        FileMovedEvent,
        DirCreatedEvent,
        DirDeletedEvent,
        DirModifiedEvent,
        DirMovedEvent,
    )
except ImportError:
    print("[FATAL] watchdog 未安装。请执行: pip install watchdog", file=sys.stderr)
    sys.exit(1)

try:
    import portalocker
    HAS_PORTALOCKER = True
except ImportError:
    HAS_PORTALOCKER = False

try:
    import psutil  # type: ignore
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# pywin32 可选增强
_HAS_PYWIN32 = False
try:
    import win32con  # type: ignore
    import win32evtlog  # type: ignore
    import win32file  # type: ignore
    _HAS_PYWIN32 = True
except ImportError:
    pass


# ═════════════════════════════════════════════════════════════
# 全局常量
# ═════════════════════════════════════════════════════════════

VERSION = "2.0.0-compat"

APP_NAME = "DocGuard"
APP_REG_KEY = r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
APP_TASK_NAME = "DocGuardAutostart"

# ── 正式文档后缀 ──
DOCUMENT_EXTENSIONS: Set[str] = {
    # Word / Writer
    ".doc", ".docx", ".docm", ".dot", ".dotx", ".dotm", ".rtf", ".wps", ".wpt",
    # Excel / 表格
    ".xls", ".xlsx", ".xlsm", ".xlsb", ".xlt", ".xltx", ".xltm", ".csv", ".et", ".ett",
    # PowerPoint / 演示
    ".ppt", ".pptx", ".pptm", ".pps", ".ppsx", ".ppsm",
    ".pot", ".potx", ".potm", ".dps", ".dpt",
}

# ── 可选兼容后缀 ──
OPTIONAL_EXTENSIONS: Set[str] = {
    ".txt", ".html", ".htm", ".xml", ".pdf", ".ofd",
}

# ── 临时/伴生文件模式 ──
TEMP_PATTERNS: List[str] = ["~$*", "*.tmp"]
# 额外已知的 Office 临时文件前缀/后缀
TEMP_PREFIXES: Tuple[str, ...] = ("~$", "~WRL", "~WRD", "ppt", ".~")
TEMP_SUFFIXES: Tuple[str, ...] = (".tmp", ".wbk", ".bak")

# ── 默认排除目录（小写） ──
DEFAULT_EXCLUDE_DIRS: Set[str] = {
    ".git", ".svn", "__pycache__", "node_modules", ".vs",
    "$recycle.bin", "system volume information",
}

# ── 哈希相关 ──
HASH_ALGORITHM = "sha256"
HASH_READ_CHUNK = 256 * 1024  # 256 KB 每次读取块

# ── 事件类型 ──
EVT_FILE_CREATED = "file_created"
EVT_FILE_MODIFIED = "file_modified"
EVT_FILE_DELETED = "file_deleted"
EVT_FILE_RENAMED = "file_renamed"
EVT_FILE_MOVED = "file_moved"
EVT_TEMP_FILE_CREATED = "temp_file_created"
EVT_TEMP_FILE_MODIFIED = "temp_file_modified"
EVT_TEMP_FILE_DELETED = "temp_file_deleted"
EVT_LOCK_FILE_CREATED = "lock_file_created"
EVT_TARGET_REPLACED_BY_TEMP = "target_replaced_by_temp"
EVT_INFERRED_REAL_SAVE = "inferred_real_save"
EVT_INFERRED_CREATED = "inferred_created"
EVT_INFERRED_DELETED = "inferred_deleted"
EVT_INFERRED_MODIFIED = "inferred_modified"


# ═════════════════════════════════════════════════════════════
# 配置
# ═════════════════════════════════════════════════════════════

# 旧版 doc_guard.py 兼容配置（命名和默认用法不变）
CONFIG: Dict[str, Any] = {
    "monitor_roots": [
        os.path.expanduser("C:/test"),
        os.path.expanduser("~/Documents"),
    ],
    "explicit_files": [],
    "target_extensions": {
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".wps", ".et", ".dps",
        ".docm", ".xlsm", ".pptm",
        ".dotx", ".xltx", ".potx",
        ".rtf",
    },
    "include_temp_patterns": ["~$*", "~*.tmp", "*.tmp", ".~lock.*#"],
    "process_name_watchlist": [],
    "parent_process_watchlist": [],
    "cmdline_keyword_watchlist": [],
    "username_watchlist": [],
    "output_dir": os.path.join(os.path.expanduser("~"), ".doc_guard"),
    "hash_algorithm": "sha256",
    "debounce_seconds": 0.8,
    "stable_wait_seconds": 1.2,
    "enable_security_audit_mode": False,
    "enable_autostart_on_install": False,
    "autostart_mode": "run_key",
    "log_rotate_mb": 10,
    "log_rotate_count": 5,
    "audit_rotate_lines": 100000,
    "lock_file_name": "doc_guard.lock",
    "periodic_rescan_seconds": 300,
    "quick_hash_bytes": 65536,
}

@dataclass
class MonitorConfig:
    """监控器完整配置。"""

    # ── 监控路径 ──
    watch_dirs: List[str] = field(default_factory=lambda: ["."])
    explicit_files: List[str] = field(default_factory=list)
    recursive: bool = True

    # ── 后缀 ──
    document_extensions: List[str] = field(
        default_factory=lambda: sorted(DOCUMENT_EXTENSIONS)
    )
    optional_extensions: List[str] = field(
        default_factory=lambda: sorted(OPTIONAL_EXTENSIONS)
    )
    enable_optional_extensions: bool = False

    # ── 排除 ──
    exclude_dirs: List[str] = field(
        default_factory=lambda: sorted(DEFAULT_EXCLUDE_DIRS)
    )

    # ── 去抖 ──
    debounce_seconds: float = 1.5       # modified 事件去抖窗口
    stable_wait_seconds: float = 2.0    # 文件稳定等待（写完再处理）
    move_pair_window: float = 2.0       # rename/move 配对窗口

    # ── 哈希 ──
    hash_enabled: bool = True
    hash_on_create: bool = True
    hash_on_modify: bool = True
    hash_max_size_mb: int = 512         # 超过此大小跳过哈希
    hash_algorithm: str = HASH_ALGORITHM

    # ── 重扫 ──
    rescan_interval_seconds: int = 300  # 5 分钟低频重扫
    rescan_enabled: bool = True

    # ── 持久化 ──
    db_path: str = "doc_monitor.db"
    db_batch_interval: float = 5.0      # 批量写库间隔

    # ── 日志 ──
    audit_log_path: str = "doc_monitor_audit.jsonl"
    audit_log_max_bytes: int = 50 * 1024 * 1024   # 50 MB
    audit_log_backup_count: int = 5
    app_log_path: str = "doc_monitor_app.log"
    app_log_max_bytes: int = 20 * 1024 * 1024
    app_log_backup_count: int = 3
    app_log_level: str = "INFO"

    # ── 单实例 ──
    lock_file_path: str = "doc_monitor.lock"

    # ── 网络盘降级 ──
    network_paths: List[str] = field(default_factory=list)
    polling_interval: float = 5.0       # PollingObserver 间隔

    # ── 队列 ──
    worker_queue_size: int = 10000

    def effective_extensions(self) -> Set[str]:
        """返回当前生效的全部后缀集合（小写）。"""
        exts = set(e.lower() for e in self.document_extensions)
        if self.enable_optional_extensions:
            exts |= set(e.lower() for e in self.optional_extensions)
        return exts

    @classmethod
    def from_file(cls, path: str) -> "MonitorConfig":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(**{k: v for k, v in data.items() if k in {
            fi.name for fi in dataclasses.fields(cls)
        }})

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


# ═════════════════════════════════════════════════════════════
# 工具函数
# ═════════════════════════════════════════════════════════════

def normalize_path(p: str) -> str:
    """
    将路径规范化为绝对路径，统一大小写（Windows 不区分），统一分隔符。
    性能说明：pathlib.resolve() 在 Windows 上会解析符号链接并返回绝对路径，
    调用频率低（仅在事件入口和基线扫描时），不构成瓶颈。

    额外处理：
      - 剥离 Windows CMD 传参时可能残留的首尾引号字符
      - 去除首尾空白
    """
    # Windows CMD 某些场景下 argparse 会保留路径两端的引号字符
    p = p.strip().strip('"').strip("'")
    try:
        return str(pathlib.Path(p).resolve())
    except (OSError, ValueError):
        return os.path.abspath(p)


def normalize_path_lower(p: str) -> str:
    """规范化后转小写，用于 Windows 路径比对。"""
    return normalize_path(p).lower()


def is_temp_file(name: str) -> bool:
    """
    判断文件名是否属于临时/伴生文件。
    性能说明：纯字符串操作，O(1)，无 I/O。
    """
    lower = name.lower()
    # 检查 ~$ 锁定文件
    if name.startswith("~$"):
        return True
    # 检查 fnmatch 模式
    for pat in TEMP_PATTERNS:
        if fnmatch.fnmatch(lower, pat.lower()):
            return True
    # 检查已知前缀/后缀
    for pfx in TEMP_PREFIXES:
        if lower.startswith(pfx.lower()):
            return True
    for sfx in TEMP_SUFFIXES:
        if lower.endswith(sfx.lower()):
            return True
    return False


def is_lock_file(name: str) -> bool:
    """判断是否为 Office/WPS 锁文件（~$开头）。"""
    return name.startswith("~$")


def get_extension(path: str) -> str:
    """返回小写后缀，例如 '.docx'。"""
    return pathlib.Path(path).suffix.lower()


def safe_stat(path: str) -> Optional[os.stat_result]:
    """
    安全获取文件 stat，失败返回 None。
    性能说明：单次系统调用，比 exists()+getsize()+getmtime() 分三次调用更快。
    """
    try:
        return os.stat(path)
    except (OSError, PermissionError):
        return None


def safe_hash(path: str, algorithm: str = HASH_ALGORITHM,
              max_size_mb: int = 512) -> Optional[str]:
    """
    安全计算文件哈希。超过 max_size_mb 或出错则返回 None。
    性能说明：
      - 先 stat 检查大小，超限直接跳过，避免无谓 I/O
      - 使用 256 KB 分块读取，避免大文件一次性加载到内存
      - 读取时共享锁打开，减少与 Office 冲突
    """
    try:
        st = os.stat(path)
        if st.st_size > max_size_mb * 1024 * 1024:
            return None
        if st.st_size == 0:
            return hashlib.new(algorithm, b"").hexdigest()
        h = hashlib.new(algorithm)
        with open(path, "rb") as f:
            while True:
                chunk = f.read(HASH_READ_CHUNK)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError, FileNotFoundError):
        return None


def now_iso() -> str:
    """返回当前 UTC 时间 ISO 字符串。"""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def make_event_id() -> str:
    """生成唯一事件 ID。使用 uuid4 的前 12 位即可满足唯一性。"""
    return uuid.uuid4().hex[:16]


def is_in_excluded_dir(path: str, exclude_set_lower: Set[str]) -> bool:
    """
    检查路径是否位于被排除的目录下。
    性能说明：逐段检查路径组件，纯字符串操作，无 I/O。
    """
    parts = pathlib.Path(path).parts
    for part in parts:
        if part.lower() in exclude_set_lower:
            return True
    return False


# ═════════════════════════════════════════════════════════════
# 审计日志写入器 (JSONL)
# ═════════════════════════════════════════════════════════════

class AuditLogger:
    """
    JSONL 审计日志写入器。

    性能优化：
      - 使用 logging.handlers.RotatingFileHandler 实现自动轮转
      - 日志写入在后台线程中批量进行，不阻塞事件回调
      - 只有真正有效的事件才写入审计日志
    """

    def __init__(self, config: MonitorConfig):
        self._logger = logging.getLogger("doc_monitor.audit")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False

        handler = logging.handlers.RotatingFileHandler(
            config.audit_log_path,
            maxBytes=config.audit_log_max_bytes,
            backupCount=config.audit_log_backup_count,
            encoding="utf-8",
        )
        # 不加格式，纯 JSONL
        handler.setFormatter(logging.Formatter("%(message)s"))
        self._logger.addHandler(handler)

    def write_event(self, event: Dict[str, Any]) -> None:
        """写一条 JSONL 记录。json.dumps 带 ensure_ascii=False 减少转义开销。"""
        try:
            line = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
            self._logger.info(line)
        except Exception:
            pass  # 审计日志写入失败不应影响主流程



class AuditWriter(AuditLogger):
    """旧版命名兼容层。"""
    def __init__(self, output_dir: str, max_lines: int = 0):
        cfg = MonitorConfig(
            watch_dirs=[],
            audit_log_path=os.path.join(output_dir, "audit.jsonl"),
            app_log_path=os.path.join(output_dir, "doc_guard.log"),
            db_path=os.path.join(output_dir, "baseline.db"),
            lock_file_path=os.path.join(output_dir, CONFIG["lock_file_name"]),
        )
        super().__init__(cfg)

def setup_logging(output_dir: str, rotate_mb: int, rotate_count: int) -> logging.Logger:
    """旧版 setup_logging 兼容层，输出 doc_guard.log。"""
    cfg = MonitorConfig(
        watch_dirs=[],
        audit_log_path=os.path.join(output_dir, "audit.jsonl"),
        app_log_path=os.path.join(output_dir, "doc_guard.log"),
        app_log_max_bytes=rotate_mb * 1024 * 1024,
        app_log_backup_count=rotate_count,
        db_path=os.path.join(output_dir, "baseline.db"),
        lock_file_path=os.path.join(output_dir, CONFIG["lock_file_name"]),
    )
    return setup_app_logger(cfg)

def norm_path(p: str) -> str:
    return normalize_path_lower(p).replace("\\", "/")

def ext_of(p: str) -> str:
    return get_extension(p)

def basename_of(p: str) -> str:
    return os.path.basename(p)

def is_target_ext(p: str, exts: set) -> bool:
    return get_extension(p) in exts

def is_temp_or_companion(filename: str, patterns: list, target_basenames: set) -> bool:
    low = filename.lower()
    if is_temp_file(filename):
        return True
    for pat in patterns:
        if fnmatch.fnmatch(low, pat.lower()):
            return True
    for tb in target_basenames:
        tb_no_ext = os.path.splitext(tb)[0].lower()
        if tb_no_ext and tb_no_ext in low and (low.endswith('.tmp') or low.startswith('~')):
            return True
    return False

def compute_hash(filepath: str, algorithm: str = 'sha256', max_bytes: int = 0) -> Optional[str]:
    try:
        h = hashlib.new(algorithm)
        read = 0
        with open(filepath, 'rb') as f:
            while True:
                size = 65536
                if max_bytes > 0:
                    size = min(size, max_bytes - read)
                    if size <= 0:
                        break
                buf = f.read(size)
                if not buf:
                    break
                h.update(buf)
                read += len(buf)
        return h.hexdigest()
    except Exception:
        return None

def file_stat_safe(filepath: str) -> dict:
    st = safe_stat(filepath)
    if not st:
        return {"size": 0, "mtime": 0, "ctime": 0, "inode_or_file_id": 0}
    return {"size": st.st_size, "mtime": st.st_mtime, "ctime": getattr(st, 'st_ctime', 0), "inode_or_file_id": getattr(st, 'st_ino', 0)}

def wait_file_stable(filepath: str, timeout: float = 3.0, interval: float = 0.3) -> bool:
    prev_size = -1
    prev_mtime = -1.0
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        st = safe_stat(filepath)
        if st is None:
            return False
        if st.st_size == prev_size and st.st_mtime == prev_mtime:
            return True
        prev_size = st.st_size
        prev_mtime = st.st_mtime
        time.sleep(interval)
    return True

class ProcessAttributor:
    """保留旧版的进程归因能力，作为事件增强信息。"""
    def __init__(self, cfg: dict):
        self._proc_names = {n.lower() for n in cfg.get('process_name_watchlist', [])}
        self._parent_names = {n.lower() for n in cfg.get('parent_process_watchlist', [])}
        self._cmdline_kws = [k.lower() for k in cfg.get('cmdline_keyword_watchlist', [])]
        self._usernames = {u.lower() for u in cfg.get('username_watchlist', [])}

    def _build_actor(self, pinfo: dict) -> dict:
        pid = pinfo.get('pid', 0)
        name = pinfo.get('name', '') or ''
        exe = pinfo.get('exe', '') or ''
        cmdline = pinfo.get('cmdline') or []
        ppid = pinfo.get('ppid', 0)
        username = pinfo.get('username', '') or ''
        parent_name = ''
        if HAS_PSUTIL and ppid:
            try:
                parent_name = psutil.Process(ppid).name()
            except Exception:
                pass
        actor = {
            'pid': pid, 'process_name': name, 'exe': exe,
            'cmdline': cmdline if len(cmdline) <= 10 else cmdline[:10] + ['...'],
            'ppid': ppid, 'parent_name': parent_name, 'username': username,
            'actor_matched': False, 'actor_match_reason': [],
        }
        reasons = []
        if self._proc_names and name.lower() in self._proc_names:
            reasons.append('process_name')
        if self._parent_names and parent_name.lower() in self._parent_names:
            reasons.append('parent_process')
        if self._cmdline_kws:
            cmd_str = ' '.join(cmdline).lower()
            for kw in self._cmdline_kws:
                if kw in cmd_str:
                    reasons.append(f'cmdline_keyword:{kw}')
                    break
        if self._usernames and username.lower() in self._usernames:
            reasons.append('username')
        if reasons:
            actor['actor_matched'] = True
            actor['actor_match_reason'] = reasons
        return actor

    def find_actors_for_file(self, filepath: str) -> List[dict]:
        if not HAS_PSUTIL:
            return []
        results = []
        normed = normalize_path_lower(filepath)
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'ppid', 'username']):
                try:
                    try:
                        open_files = proc.open_files()
                    except Exception:
                        open_files = []
                    if not any(normalize_path_lower(of.path) == normed for of in open_files):
                        continue
                    results.append(self._build_actor(proc.info))
                except Exception:
                    continue
        except Exception:
            return []
        return results

class SecurityAuditEnhancer:
    TARGET_EVENT_IDS = {4663, 4656, 4658, 4660}
    CORRELATION_WINDOW = 5.0

    def __init__(self, enabled: bool):
        self.enabled = enabled
        self.available = False
        self.degrade_reason = ''
        self._cache: List[dict] = []
        self._cache_lock = threading.Lock()
        self._poll_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        if not enabled:
            self.degrade_reason = '配置中未启用安全审计增强模式'
            return
        if not _HAS_PYWIN32:
            self.degrade_reason = 'pywin32 未安装，无法读取安全日志'
            return
        if platform.system() != 'Windows':
            self.degrade_reason = '非 Windows 系统'
            return
        try:
            hand = win32evtlog.OpenEventLog(None, 'Security')
            win32evtlog.CloseEventLog(hand)
            self.available = True
        except Exception as exc:
            self.degrade_reason = f'无法打开安全日志: {exc}'

    def start(self):
        if not self.available:
            return
        self._stop_event.clear()
        self._poll_thread = threading.Thread(target=self._poll_loop, name='AuditPoll', daemon=True)
        self._poll_thread.start()

    def stop(self):
        self._stop_event.set()
        if self._poll_thread and self._poll_thread.is_alive():
            self._poll_thread.join(timeout=5)

    def _poll_loop(self):
        try:
            hand = win32evtlog.OpenEventLog(None, 'Security')
        except Exception:
            self.available = False
            return
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        while not self._stop_event.is_set():
            try:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                for ev in events:
                    event_id = ev.EventID & 0xFFFF
                    if event_id not in self.TARGET_EVENT_IDS:
                        continue
                    strings = ev.StringInserts or []
                    rec = {
                        'event_id': event_id,
                        'ts': ev.TimeGenerated.isoformat() if ev.TimeGenerated else '',
                        'SubjectUserName': strings[1] if len(strings) > 1 else '',
                        'ObjectName': strings[6] if len(strings) > 6 else '',
                        'ProcessName': strings[11] if len(strings) > 11 else '',
                        'ProcessId': strings[12] if len(strings) > 12 else '',
                        'AccessMask': strings[8] if len(strings) > 8 else '',
                    }
                    with self._cache_lock:
                        self._cache.append(rec)
                        if len(self._cache) > 1000:
                            self._cache = self._cache[-500:]
            except Exception:
                pass
            self._stop_event.wait(2.0)
        try:
            win32evtlog.CloseEventLog(hand)
        except Exception:
            pass

    def correlate(self, filepath: str, event_time: float) -> Optional[dict]:
        if not self.available:
            return None
        normed_fp = os.path.normpath(filepath).lower()
        best = None
        best_delta = self.CORRELATION_WINDOW + 1
        with self._cache_lock:
            for rec in reversed(self._cache):
                obj_name = (rec.get('ObjectName') or '').lower()
                if normed_fp not in obj_name and obj_name not in normed_fp:
                    continue
                try:
                    rec_time = datetime.datetime.fromisoformat(rec['ts']).timestamp()
                except Exception:
                    continue
                delta = abs(event_time - rec_time)
                if delta < best_delta:
                    best_delta = delta
                    best = rec
        if best and best_delta <= self.CORRELATION_WINDOW:
            return {
                'audit_event_id': best.get('event_id'),
                'SubjectUserName': best.get('SubjectUserName', ''),
                'ProcessName': best.get('ProcessName', ''),
                'ProcessId': best.get('ProcessId', ''),
                'AccessMask': best.get('AccessMask', ''),
                'ObjectName': best.get('ObjectName', ''),
                'correlation_delta_s': round(best_delta, 3),
            }
        return None

# ═════════════════════════════════════════════════════════════
# SQLite 基线数据库
# ═════════════════════════════════════════════════════════════

class BaselineDB:
    """
    SQLite 基线数据库，记录每个被监控文件的最新状态。

    性能优化：
      - WAL 模式：读写并发不阻塞
      - 同步模式 NORMAL：在 WAL 下足够安全且更快
      - 批量 upsert：通过 executemany + 事务合并
      - journal_size_limit 限制 WAL 文件大小
      - cache_size 设为 2000 页 (~8MB)，减少磁盘读取
    """

    DDL = """
    CREATE TABLE IF NOT EXISTS baseline (
        normalized_path TEXT PRIMARY KEY,
        path            TEXT NOT NULL,
        exists_flag     INTEGER NOT NULL DEFAULT 1,
        size            INTEGER,
        mtime           REAL,
        hash            TEXT,
        is_temp         INTEGER NOT NULL DEFAULT 0,
        last_seen       TEXT,
        last_event_type TEXT,
        extension       TEXT,
        extra           TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_baseline_ext ON baseline(extension);
    CREATE INDEX IF NOT EXISTS idx_baseline_exists ON baseline(exists_flag);
    """

    def __init__(self, db_path: str):
        self._db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._lock = threading.Lock()
        self._connect()

    def _connect(self) -> None:
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._conn.execute("PRAGMA cache_size=2000;")
        self._conn.execute("PRAGMA journal_size_limit=8388608;")  # 8 MB
        self._conn.executescript(self.DDL)
        self._conn.commit()

    def upsert(self, record: Dict[str, Any]) -> None:
        """单条 upsert。"""
        with self._lock:
            self._conn.execute("""
                INSERT INTO baseline (
                    normalized_path, path, exists_flag, size, mtime,
                    hash, is_temp, last_seen, last_event_type, extension, extra
                ) VALUES (
                    :normalized_path, :path, :exists_flag, :size, :mtime,
                    :hash, :is_temp, :last_seen, :last_event_type, :extension, :extra
                )
                ON CONFLICT(normalized_path) DO UPDATE SET
                    path=excluded.path,
                    exists_flag=excluded.exists_flag,
                    size=excluded.size,
                    mtime=excluded.mtime,
                    hash=excluded.hash,
                    is_temp=excluded.is_temp,
                    last_seen=excluded.last_seen,
                    last_event_type=excluded.last_event_type,
                    extension=excluded.extension,
                    extra=excluded.extra
            """, record)
            self._conn.commit()

    def upsert_batch(self, records: List[Dict[str, Any]]) -> None:
        """
        批量 upsert。
        性能说明：单事务内 executemany 比逐条 commit 快 10-100 倍。
        """
        if not records:
            return
        with self._lock:
            self._conn.executemany("""
                INSERT INTO baseline (
                    normalized_path, path, exists_flag, size, mtime,
                    hash, is_temp, last_seen, last_event_type, extension, extra
                ) VALUES (
                    :normalized_path, :path, :exists_flag, :size, :mtime,
                    :hash, :is_temp, :last_seen, :last_event_type, :extension, :extra
                )
                ON CONFLICT(normalized_path) DO UPDATE SET
                    path=excluded.path,
                    exists_flag=excluded.exists_flag,
                    size=excluded.size,
                    mtime=excluded.mtime,
                    hash=excluded.hash,
                    is_temp=excluded.is_temp,
                    last_seen=excluded.last_seen,
                    last_event_type=excluded.last_event_type,
                    extension=excluded.extension,
                    extra=excluded.extra
            """, records)
            self._conn.commit()

    def get(self, normalized_path: str) -> Optional[Dict[str, Any]]:
        """查询单条基线记录。"""
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM baseline WHERE normalized_path=?",
                (normalized_path,)
            )
            row = cur.fetchone()
            if row is None:
                return None
            cols = [d[0] for d in cur.description]
            return dict(zip(cols, row))

    def get_all_existing(self) -> List[Dict[str, Any]]:
        """获取所有 exists_flag=1 的记录。"""
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM baseline WHERE exists_flag=1"
            )
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def mark_deleted(self, normalized_path: str, event_type: str = EVT_FILE_DELETED) -> None:
        """标记文件为已删除。"""
        with self._lock:
            self._conn.execute("""
                UPDATE baseline SET exists_flag=0, last_seen=?, last_event_type=?
                WHERE normalized_path=?
            """, (now_iso(), event_type, normalized_path))
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None


# ═════════════════════════════════════════════════════════════
# 事件构造器
# ═════════════════════════════════════════════════════════════

def build_event(
    event_type: str,
    path: str,
    *,
    old_path: Optional[str] = None,
    new_path: Optional[str] = None,
    size: Optional[int] = None,
    mtime: Optional[float] = None,
    file_hash: Optional[str] = None,
    extension: Optional[str] = None,
    is_temp: bool = False,
    source: str = "watchdog",
    confidence: str = "high",
    details: Optional[str] = None,
) -> Dict[str, Any]:
    """构造一条标准审计事件。"""
    return {
        "event_id": make_event_id(),
        "ts": now_iso(),
        "event_type": event_type,
        "path": path,
        "old_path": old_path,
        "new_path": new_path,
        "size": size,
        "mtime": mtime,
        "hash": file_hash,
        "extension": extension or get_extension(path),
        "is_temp": is_temp,
        "source": source,
        "confidence": confidence,
        "details": details,
    }


# ═════════════════════════════════════════════════════════════
# 去抖器 (Debouncer)
# ═════════════════════════════════════════════════════════════

class Debouncer:
    """
    事件去抖器：将短窗口内同一文件的重复 modified 合并为一次。

    性能优化原理：
      - Office 保存一个 .docx 会在几百毫秒内触发 5-20 次 modified 事件
      - 不去抖会导致每次都做 stat/hash/写库，浪费大量 I/O
      - 去抖后只处理最后一次稳定事件，CPU 和 I/O 降低 10x 以上
      - 使用 dict 实现 O(1) 查找/更新
    """

    def __init__(self, debounce_sec: float = 1.5, stable_wait_sec: float = 2.0):
        self._debounce_sec = debounce_sec
        self._stable_wait_sec = stable_wait_sec
        # key: normalized_path_lower -> (latest_raw_event_type, first_seen_time, last_update_time, raw_event)
        self._pending: Dict[str, Tuple[str, float, float, Any]] = {}
        self._lock = threading.Lock()

    def submit(self, norm_path_lower: str, raw_event_type: str, raw_event: Any) -> None:
        """提交一个原始事件到去抖窗口。"""
        now = time.monotonic()
        with self._lock:
            existing = self._pending.get(norm_path_lower)
            if existing is not None:
                # 合并：更新最后时间和事件
                _, first_seen, _, _ = existing
                self._pending[norm_path_lower] = (raw_event_type, first_seen, now, raw_event)
            else:
                self._pending[norm_path_lower] = (raw_event_type, now, now, raw_event)

    def collect_stable(self) -> List[Tuple[str, str, Any]]:
        """
        收集已超过 stable wait 的事件。
        返回 [(norm_path_lower, event_type, raw_event), ...]
        """
        now = time.monotonic()
        stable = []
        with self._lock:
            to_remove = []
            for key, (evt_type, first_seen, last_update, raw_evt) in self._pending.items():
                # 文件必须在 stable_wait_sec 内没有新事件才认为稳定
                if now - last_update >= self._stable_wait_sec:
                    stable.append((key, evt_type, raw_evt))
                    to_remove.append(key)
            for key in to_remove:
                del self._pending[key]
        return stable

    def remove(self, norm_path_lower: str) -> Optional[Tuple[str, Any]]:
        """立即移除并返回（用于 delete 事件，无需等待稳定）。"""
        with self._lock:
            item = self._pending.pop(norm_path_lower, None)
            if item:
                return (item[0], item[3])
            return None

    @property
    def pending_count(self) -> int:
        with self._lock:
            return len(self._pending)


# ═════════════════════════════════════════════════════════════
# 移动/重命名配对器
# ═════════════════════════════════════════════════════════════

class MovePairTracker:
    """
    跟踪 delete+create 对，尝试配对为 rename/move。

    性能说明：
      - watchdog 在 Windows 上通常直接给 FileMovedEvent，但某些场景
        （跨卷移动、某些编辑器）会拆成 delete+create
      - 此组件用 size+mtime 做轻量匹配，不额外算哈希
      - 过期条目定期清理，内存占用极小
    """

    def __init__(self, window_sec: float = 2.0):
        self._window = window_sec
        # key: (size, mtime_rounded) -> [(norm_lower, original_path, ts)]
        self._deletes: Dict[Tuple[Optional[int], Optional[float]], List[Tuple[str, str, float]]] = {}
        self._lock = threading.Lock()

    def record_delete(self, norm_lower: str, original_path: str,
                      size: Optional[int], mtime: Optional[float]) -> None:
        """记录一个删除事件的文件特征。"""
        key = (size, round(mtime, 1) if mtime else None)
        now = time.monotonic()
        with self._lock:
            lst = self._deletes.setdefault(key, [])
            lst.append((norm_lower, original_path, now))

    def try_match_create(self, norm_lower: str, size: Optional[int],
                         mtime: Optional[float]) -> Optional[str]:
        """
        尝试为一个 create 事件匹配之前的 delete。
        返回匹配的旧路径（原始路径），或 None。
        """
        key = (size, round(mtime, 1) if mtime else None)
        now = time.monotonic()
        with self._lock:
            lst = self._deletes.get(key)
            if not lst:
                return None
            # 找最近的、在窗口内的、路径不同的
            for i in range(len(lst) - 1, -1, -1):
                del_norm, del_orig, del_ts = lst[i]
                if now - del_ts <= self._window and del_norm != norm_lower:
                    lst.pop(i)
                    return del_orig
            return None

    def cleanup(self) -> None:
        """清理过期条目。"""
        now = time.monotonic()
        with self._lock:
            expired_keys = []
            for key, lst in self._deletes.items():
                lst[:] = [(n, o, t) for n, o, t in lst if now - t <= self._window * 2]
                if not lst:
                    expired_keys.append(key)
            for key in expired_keys:
                del self._deletes[key]


# ═════════════════════════════════════════════════════════════
# Office 保存行为推断器
# ═════════════════════════════════════════════════════════════

class SaveInferrer:
    """
    推断 Office/WPS 的真实保存行为。

    典型保存流程（Word 为例）：
      1. 创建 ~$doc.docx 锁文件 → lock_file_created
      2. 写入临时文件（随机名 .tmp）→ temp_file_created
      3. 删除原文件 → (内部中间态)
      4. 将临时文件重命名为原文件 → target_replaced_by_temp
      5. 最终 → inferred_real_save

    性能说明：
      - 仅在内存中维护短窗口内的文件事件序列
      - 不做额外 I/O，只依据已有事件信息推断
      - 窗口自动过期，内存恒定
    """

    def __init__(self, window_sec: float = 10.0):
        self._window = window_sec
        # key: directory_lower -> list of (ts, event_type, path, details)
        self._recent: Dict[str, List[Tuple[float, str, str, Optional[str]]]] = {}
        self._lock = threading.Lock()

    def record(self, dir_lower: str, event_type: str, path: str,
               details: Optional[str] = None) -> Optional[str]:
        """
        记录一个事件，返回推断的高层事件类型（如果能推断的话）。
        """
        now = time.monotonic()
        with self._lock:
            lst = self._recent.setdefault(dir_lower, [])
            lst.append((now, event_type, path, details))
            # 清理过期
            lst[:] = [(t, e, p, d) for t, e, p, d in lst if now - t < self._window]

            # 尝试推断 inferred_real_save：
            # 如果我们看到同一目录下：temp_file_created/modified + 正式文件 modified
            # 且时间间隔很短，可以推断为一次真实保存
            return self._try_infer(lst, path)

    def _try_infer(self, events: list, current_path: str) -> Optional[str]:
        """基于近期事件序列推断。"""
        if len(events) < 2:
            return None

        # 查找最近是否有 temp 活动 + 正式文件变动
        temp_activity = False
        formal_modified = False
        formal_path = None

        for _, evt_type, p, _ in events:
            name = pathlib.Path(p).name
            if evt_type in (EVT_TEMP_FILE_CREATED, EVT_TEMP_FILE_MODIFIED, EVT_TEMP_FILE_DELETED):
                temp_activity = True
            if evt_type in (EVT_FILE_MODIFIED, EVT_FILE_CREATED) and not is_temp_file(name):
                formal_modified = True
                formal_path = p

        if temp_activity and formal_modified:
            return EVT_INFERRED_REAL_SAVE

        return None

    def cleanup(self) -> None:
        now = time.monotonic()
        with self._lock:
            expired = []
            for key, lst in self._recent.items():
                lst[:] = [(t, e, p, d) for t, e, p, d in lst if now - t < self._window]
                if not lst:
                    expired.append(key)
            for key in expired:
                del self._recent[key]


# ═════════════════════════════════════════════════════════════
# 核心事件处理器 (watchdog Handler)
# ═════════════════════════════════════════════════════════════

class DocEventHandler(FileSystemEventHandler):
    """
    watchdog 文件系统事件处理器。

    性能关键设计：
      1. on_xxx 回调必须尽快返回 —— 所有耗时操作通过 queue 异步处理
      2. 过滤在最前面 —— 排除目录、非目标后缀、目录事件在入口处直接跳过
      3. moved 事件优先处理 —— watchdog 原生 moved 无需配对
      4. modified 事件进入 debouncer —— 不立即处理
      5. created/deleted 事件进入 queue —— 但标记来源
    """

    def __init__(
        self,
        work_queue: queue.Queue,
        config: MonitorConfig,
        explicit_files_lower: Set[str],
        logger: logging.Logger,
    ):
        super().__init__()
        self._queue = work_queue
        self._config = config
        self._effective_exts = config.effective_extensions()
        self._exclude_dirs_lower = set(d.lower() for d in config.exclude_dirs)
        self._explicit_lower = explicit_files_lower
        self._log = logger

    def _should_process(self, path: str) -> bool:
        """
        前置过滤：只有通过此检查的路径才进入后续处理。

        性能说明：
          - 纯字符串操作，无任何 I/O
          - 排除目录检查 O(path_depth * exclude_count)，通常 < 50 次比较
          - 后缀检查 O(1) set lookup
          - 此函数是整个系统最关键的性能守门员
        """
        # 1. 排除目录检查
        if is_in_excluded_dir(path, self._exclude_dirs_lower):
            return False

        name = pathlib.Path(path).name
        ext = get_extension(path)

        # 2. 显式文件列表优先
        norm_lower = normalize_path_lower(path)
        if norm_lower in self._explicit_lower:
            return True

        # 3. 临时/伴生文件 —— 也需要观察（用于推断保存行为）
        if is_temp_file(name):
            return True

        # 4. 后缀过滤
        if ext not in self._effective_exts:
            return False

        return True

    def on_created(self, event) -> None:
        if event.is_directory:
            return
        if not self._should_process(event.src_path):
            return
        self._queue.put(("created", event.src_path, None, time.monotonic()))

    def on_deleted(self, event) -> None:
        if event.is_directory:
            return
        if not self._should_process(event.src_path):
            return
        self._queue.put(("deleted", event.src_path, None, time.monotonic()))

    def on_modified(self, event) -> None:
        if event.is_directory:
            return
        if not self._should_process(event.src_path):
            return
        # modified 是最高频事件，直接入队，后续由 worker 做去抖
        self._queue.put(("modified", event.src_path, None, time.monotonic()))

    def on_moved(self, event) -> None:
        if event.is_directory:
            return
        src_ok = self._should_process(event.src_path)
        dst_ok = self._should_process(event.dest_path)
        if not src_ok and not dst_ok:
            return
        self._queue.put(("moved", event.src_path, event.dest_path, time.monotonic()))


# ═════════════════════════════════════════════════════════════
# 后台工作线程
# ═════════════════════════════════════════════════════════════

class WorkerThread(threading.Thread):
    """
    后台工作线程：从队列中取出事件，进行去抖、语义分析、哈希计算、
    基线更新、审计日志写入。

    性能优化：
      1. 事件回调线程不做任何 I/O，全部交给此线程
      2. modified 事件先进 debouncer，stable 后才处理
      3. 文件哈希只在 stable 后且 size/mtime 变化时才计算
      4. 基线更新使用 batch upsert
      5. 审计日志写入通过 logging handler 自带缓冲
      6. cleanup 定时器合并执行，避免频繁唤醒
    """

    def __init__(
        self,
        work_queue: queue.Queue,
        config: MonitorConfig,
        baseline_db: BaselineDB,
        audit_logger: AuditLogger,
        debouncer: Debouncer,
        move_tracker: MovePairTracker,
        save_inferrer: SaveInferrer,
        explicit_files_lower: Set[str],
        app_logger: logging.Logger,
    ):
        super().__init__(daemon=True, name="DocMonitorWorker")
        self._queue = work_queue
        self._config = config
        self._db = baseline_db
        self._audit = audit_logger
        self._debouncer = debouncer
        self._move_tracker = move_tracker
        self._save_inferrer = save_inferrer
        self._explicit_lower = explicit_files_lower
        self._log = app_logger
        self._effective_exts = config.effective_extensions()
        self._stop_event = threading.Event()
        self._last_cleanup = time.monotonic()
        self._db_batch: List[Dict[str, Any]] = []
        self._last_db_flush = time.monotonic()

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        self._log.info("工作线程启动")
        while not self._stop_event.is_set():
            try:
                self._tick()
            except Exception:
                self._log.error("工作线程异常: %s", traceback.format_exc())
                time.sleep(1)
        # 退出前刷新
        self._flush_db_batch()
        self._log.info("工作线程退出")

    def _tick(self) -> None:
        """
        单次 tick：
          1. 从队列取事件（带超时，避免忙等）
          2. 分发处理
          3. 定期收集 debouncer 中的稳定事件
          4. 定期刷新 DB batch
          5. 定期清理 move_tracker / save_inferrer
        """
        # 步骤 1：取事件
        try:
            item = self._queue.get(timeout=0.5)
            self._dispatch_raw(item)
        except queue.Empty:
            pass

        # 步骤 2：收集去抖稳定事件
        stable_events = self._debouncer.collect_stable()
        for norm_lower, evt_type, raw_evt in stable_events:
            self._process_stable_modified(norm_lower, raw_evt)

        # 步骤 3：周期性 DB flush（每 db_batch_interval 秒）
        now = time.monotonic()
        if now - self._last_db_flush >= self._config.db_batch_interval:
            self._flush_db_batch()
            self._last_db_flush = now

        # 步骤 4：周期性清理（每 30 秒）
        if now - self._last_cleanup >= 30:
            self._move_tracker.cleanup()
            self._save_inferrer.cleanup()
            self._last_cleanup = now

    def _dispatch_raw(self, item: Tuple) -> None:
        """分发原始事件。"""
        evt_type, src_path, dest_path, ts = item

        if evt_type == "modified":
            # 进入去抖器，不立即处理
            norm_lower = normalize_path_lower(src_path)
            self._debouncer.submit(norm_lower, evt_type, src_path)

        elif evt_type == "created":
            self._handle_created(src_path)

        elif evt_type == "deleted":
            self._handle_deleted(src_path)

        elif evt_type == "moved":
            self._handle_moved(src_path, dest_path)

    def _handle_created(self, path: str) -> None:
        """处理文件创建事件。"""
        norm = normalize_path(path)
        norm_lower = norm.lower()
        name = pathlib.Path(path).name
        ext = get_extension(path)
        temp = is_temp_file(name)
        lock = is_lock_file(name)

        st = safe_stat(path)
        size = st.st_size if st else None
        mtime = st.st_mtime if st else None

        # 尝试配对为 rename/move
        if not temp:
            old_path = self._move_tracker.try_match_create(norm_lower, size, mtime)
            if old_path:
                # 判断同目录还是跨目录
                old_dir = str(pathlib.Path(old_path).parent).lower()
                new_dir = str(pathlib.Path(path).parent).lower()
                if old_dir == new_dir:
                    event_type = EVT_FILE_RENAMED
                else:
                    event_type = EVT_FILE_MOVED

                file_hash = self._maybe_hash(path, st)
                evt = build_event(
                    event_type, path,
                    old_path=old_path, new_path=path,
                    size=size, mtime=mtime, file_hash=file_hash,
                    extension=ext, is_temp=temp,
                    confidence="medium",
                    details=f"由 delete+create 配对推断",
                )
                self._emit(evt)
                self._queue_db_record(norm, norm_lower, path, st, file_hash, temp, event_type, ext)
                return

        # 确定事件类型
        if lock:
            event_type = EVT_LOCK_FILE_CREATED
        elif temp:
            event_type = EVT_TEMP_FILE_CREATED
        else:
            event_type = EVT_FILE_CREATED

        file_hash = None
        if not temp and self._config.hash_on_create:
            file_hash = self._maybe_hash(path, st)

        evt = build_event(
            event_type, path,
            size=size, mtime=mtime, file_hash=file_hash,
            extension=ext, is_temp=temp,
        )
        self._emit(evt)

        # 推断保存行为
        dir_lower = str(pathlib.Path(path).parent).lower()
        inferred = self._save_inferrer.record(dir_lower, event_type, path)
        if inferred:
            inf_evt = build_event(
                inferred, path,
                size=size, mtime=mtime, file_hash=file_hash,
                extension=ext, is_temp=temp,
                source="inferrer", confidence="medium",
                details="由近期事件序列推断",
            )
            self._emit(inf_evt)

        self._queue_db_record(norm, norm_lower, path, st, file_hash, temp, event_type, ext)

    def _handle_deleted(self, path: str) -> None:
        """处理文件删除事件。"""
        norm = normalize_path(path)
        norm_lower = norm.lower()
        name = pathlib.Path(path).name
        ext = get_extension(path)
        temp = is_temp_file(name)

        # 从 debouncer 移除（文件已删，不需要等稳定）
        self._debouncer.remove(norm_lower)

        # 查询基线获取旧的 size/mtime（用于 move 配对）
        baseline = self._db.get(norm_lower)
        old_size = baseline["size"] if baseline else None
        old_mtime = baseline["mtime"] if baseline else None

        # 记录到 move tracker（可能与后续 create 配对）
        if not temp and old_size is not None:
            self._move_tracker.record_delete(norm_lower, path, old_size, old_mtime)

        if temp:
            event_type = EVT_TEMP_FILE_DELETED
        else:
            event_type = EVT_FILE_DELETED

        evt = build_event(
            event_type, path,
            size=old_size, mtime=old_mtime,
            extension=ext, is_temp=temp,
            details="删除事件不做 I/O，仅使用基线数据",
        )
        self._emit(evt)

        # 推断
        dir_lower = str(pathlib.Path(path).parent).lower()
        self._save_inferrer.record(dir_lower, event_type, path)

        # 更新基线
        self._db.mark_deleted(norm_lower, event_type)

    def _handle_moved(self, src_path: str, dest_path: str) -> None:
        """
        处理 watchdog 原生 moved 事件。
        同目录 → rename，跨目录 → move。
        """
        src_norm = normalize_path(src_path)
        dst_norm = normalize_path(dest_path)
        src_lower = src_norm.lower()
        dst_lower = dst_norm.lower()

        src_name = pathlib.Path(src_path).name
        dst_name = pathlib.Path(dest_path).name
        ext = get_extension(dest_path)
        temp_src = is_temp_file(src_name)
        temp_dst = is_temp_file(dst_name)

        # 从 debouncer 移除旧路径
        self._debouncer.remove(src_lower)

        st = safe_stat(dest_path)
        size = st.st_size if st else None
        mtime = st.st_mtime if st else None

        # 判断是否为 "临时文件替换正式文件"（Office 保存行为）
        if temp_src and not temp_dst:
            event_type = EVT_TARGET_REPLACED_BY_TEMP
            file_hash = self._maybe_hash(dest_path, st)
            evt = build_event(
                event_type, dest_path,
                old_path=src_path, new_path=dest_path,
                size=size, mtime=mtime, file_hash=file_hash,
                extension=ext, is_temp=False,
                confidence="high",
                details=f"临时文件 {src_name} 替换为正式文件 {dst_name}",
            )
            self._emit(evt)

            # 同时推断为 real save
            inf_evt = build_event(
                EVT_INFERRED_REAL_SAVE, dest_path,
                old_path=src_path, new_path=dest_path,
                size=size, mtime=mtime, file_hash=file_hash,
                extension=ext, is_temp=False,
                source="inferrer", confidence="high",
                details="temp→formal 重命名，推断为真实保存",
            )
            self._emit(inf_evt)

        else:
            # 普通 rename 或 move
            src_dir = str(pathlib.Path(src_path).parent).lower()
            dst_dir = str(pathlib.Path(dest_path).parent).lower()
            if src_dir == dst_dir:
                event_type = EVT_FILE_RENAMED
            else:
                event_type = EVT_FILE_MOVED

            file_hash = self._maybe_hash(dest_path, st)
            evt = build_event(
                event_type, dest_path,
                old_path=src_path, new_path=dest_path,
                size=size, mtime=mtime, file_hash=file_hash,
                extension=ext, is_temp=temp_dst,
            )
            self._emit(evt)

        # 更新基线：旧路径标记删除，新路径 upsert
        self._db.mark_deleted(src_lower, "moved_from")
        self._queue_db_record(dst_norm, dst_lower, dest_path, st,
                              file_hash if 'file_hash' in dir() else None,
                              temp_dst, event_type, ext)

    def _process_stable_modified(self, norm_lower: str, raw_path: str) -> None:
        """
        处理已稳定的 modified 事件。

        性能优化核心：
          1. 先 safe_stat 获取当前 size/mtime（单次系统调用）
          2. 与基线比较 size+mtime
          3. 如果 size 和 mtime 都没变 → 跳过（仅属性变化或无效事件）
          4. 只有真正变化时才计算哈希
          5. 哈希与基线比较，真正内容变化才发事件
        """
        name = pathlib.Path(raw_path).name
        ext = get_extension(raw_path)
        temp = is_temp_file(name)
        norm = normalize_path(raw_path)

        st = safe_stat(raw_path)
        if st is None:
            # 文件可能已被删除，跳过
            return

        size = st.st_size
        mtime = st.st_mtime

        # 查基线做快速比较
        baseline = self._db.get(norm_lower)
        if baseline and baseline["exists_flag"]:
            old_size = baseline.get("size")
            old_mtime = baseline.get("mtime")
            # 快速路径：size + mtime 均未变 → 跳过
            # 这避免了 >80% 的无效 modified 事件触发昂贵的哈希计算
            if old_size == size and old_mtime is not None and abs(old_mtime - mtime) < 0.01:
                return

        # 计算哈希（仅在此时，文件已稳定且 size/mtime 确实变化）
        file_hash = None
        if self._config.hash_on_modify and not temp:
            file_hash = self._maybe_hash(raw_path, st)

            # 哈希比较：如果哈希与基线相同 → 仅元数据变化，降低置信度
            if baseline and file_hash and baseline.get("hash") == file_hash:
                # 内容没变，可能只是 mtime 被刷新，记录但标记低置信度
                if temp:
                    event_type = EVT_TEMP_FILE_MODIFIED
                else:
                    event_type = EVT_FILE_MODIFIED
                evt = build_event(
                    event_type, raw_path,
                    size=size, mtime=mtime, file_hash=file_hash,
                    extension=ext, is_temp=temp,
                    confidence="low",
                    details="size/mtime 变化但哈希未变，可能仅元数据更新",
                )
                self._emit(evt)
                self._queue_db_record(norm, norm_lower, raw_path, st, file_hash, temp,
                                      event_type, ext)
                return

        # 真正的内容变化
        if temp:
            event_type = EVT_TEMP_FILE_MODIFIED
        else:
            event_type = EVT_FILE_MODIFIED

        evt = build_event(
            event_type, raw_path,
            size=size, mtime=mtime, file_hash=file_hash,
            extension=ext, is_temp=temp,
            confidence="high",
        )
        self._emit(evt)

        # 推断
        dir_lower = str(pathlib.Path(raw_path).parent).lower()
        inferred = self._save_inferrer.record(dir_lower, event_type, raw_path)
        if inferred:
            inf_evt = build_event(
                inferred, raw_path,
                size=size, mtime=mtime, file_hash=file_hash,
                extension=ext, is_temp=temp,
                source="inferrer", confidence="medium",
                details="由近期事件序列推断",
            )
            self._emit(inf_evt)

        self._queue_db_record(norm, norm_lower, raw_path, st, file_hash, temp, event_type, ext)

    def _maybe_hash(self, path: str, st: Optional[os.stat_result]) -> Optional[str]:
        """
        条件性计算哈希。

        性能守卫：
          - hash_enabled 关闭则跳过
          - 文件超过 hash_max_size_mb 则跳过
          - stat 失败则跳过
        """
        if not self._config.hash_enabled:
            return None
        if st and st.st_size > self._config.hash_max_size_mb * 1024 * 1024:
            return None
        return safe_hash(path, self._config.hash_algorithm, self._config.hash_max_size_mb)

    def _emit(self, event: Dict[str, Any]) -> None:
        """发射审计事件。"""
        self._audit.write_event(event)
        self._log.info("事件: %s | %s", event.get("event_type"), event.get("path"))

    def _queue_db_record(self, norm: str, norm_lower: str, path: str,
                         st: Optional[os.stat_result], file_hash: Optional[str],
                         is_temp: bool, event_type: str, ext: str) -> None:
        """
        将基线记录加入批次队列。
        性能说明：不立即写库，攒够一批或到时间后统一写入。
        """
        record = {
            "normalized_path": norm_lower,
            "path": norm,
            "exists_flag": 1,
            "size": st.st_size if st else None,
            "mtime": st.st_mtime if st else None,
            "hash": file_hash,
            "is_temp": 1 if is_temp else 0,
            "last_seen": now_iso(),
            "last_event_type": event_type,
            "extension": ext,
            "extra": None,
        }
        self._db_batch.append(record)

        # 如果批次够大，立即刷新
        if len(self._db_batch) >= 50:
            self._flush_db_batch()

    def _flush_db_batch(self) -> None:
        """批量写入基线数据库。"""
        if not self._db_batch:
            return
        try:
            self._db.upsert_batch(self._db_batch)
        except Exception:
            self._log.error("DB batch flush 失败: %s", traceback.format_exc())
        finally:
            self._db_batch.clear()




def _merge_event_details(event: Dict[str, Any], extras: Dict[str, Any]) -> None:
    if not extras:
        return
    details = event.get('details')
    if isinstance(details, dict):
        details.update(extras)
    elif details is None:
        event['details'] = extras
    else:
        event['details'] = {'message': details, **extras}


class CompatWorkerThread(WorkerThread):
    """在高性能 WorkerThread 基础上，补回旧版的进程归因和安全审计增强。"""

    def __init__(self, *args, attributor: Optional[ProcessAttributor] = None,
                 security: Optional[SecurityAuditEnhancer] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self._attributor_compat = attributor
        self._security_compat = security

    def _emit(self, event: Dict[str, Any]) -> None:
        path = event.get('path') or event.get('new_path') or event.get('old_path')
        extras: Dict[str, Any] = {}
        try:
            if path and self._attributor_compat:
                actors = self._attributor_compat.find_actors_for_file(path)
                if actors:
                    extras['actor_candidates'] = actors
        except Exception:
            pass
        try:
            if path and self._security_compat:
                sec = self._security_compat.correlate(path, time.time())
                if sec:
                    extras['security_audit'] = sec
        except Exception:
            pass
        _merge_event_details(event, extras)
        super()._emit(event)


# ═════════════════════════════════════════════════════════════
# 周期性重扫线程
# ═════════════════════════════════════════════════════════════

class RescanThread(threading.Thread):
    """
    低频周期性重扫，作为 watchdog 的纠偏补偿。

    何时需要重扫：
      - watchdog 在极高负载下可能丢事件
      - 网络盘断线重连期间的变化
      - 程序启动后首次建立基线

    性能约束：
      - 默认每 5 分钟一次，远低于事件驱动频率
      - 使用 os.scandir（比 os.walk+stat 快，减少系统调用）
      - 仅比较 size+mtime，不主动算哈希
      - 发现差异才产生 inferred 事件
    """

    def __init__(
        self,
        config: MonitorConfig,
        baseline_db: BaselineDB,
        audit_logger: AuditLogger,
        app_logger: logging.Logger,
        explicit_files_lower: Set[str],
    ):
        super().__init__(daemon=True, name="DocMonitorRescan")
        self._config = config
        self._db = baseline_db
        self._audit = audit_logger
        self._log = app_logger
        self._explicit_lower = explicit_files_lower
        self._effective_exts = config.effective_extensions()
        self._exclude_dirs_lower = set(d.lower() for d in config.exclude_dirs)
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        self._log.info("重扫线程启动，间隔 %d 秒", self._config.rescan_interval_seconds)
        while not self._stop_event.is_set():
            self._stop_event.wait(self._config.rescan_interval_seconds)
            if self._stop_event.is_set():
                break
            try:
                self._do_rescan()
            except Exception:
                self._log.error("重扫异常: %s", traceback.format_exc())

    def _do_rescan(self) -> None:
        """执行一次全量重扫。"""
        self._log.info("开始周期性重扫...")
        t0 = time.monotonic()
        seen_lower: Set[str] = set()
        batch: List[Dict[str, Any]] = []

        # 扫描所有监控目录
        for watch_dir in self._config.watch_dirs:
            resolved = normalize_path(watch_dir)
            if not os.path.isdir(resolved):
                continue
            self._scan_dir(resolved, seen_lower, batch)

        # 扫描显式文件
        for ef in self._config.explicit_files:
            norm = normalize_path(ef)
            norm_lower = norm.lower()
            if norm_lower in seen_lower:
                continue
            st = safe_stat(norm)
            if st and not st.st_size == 0:  # 存在且非空
                seen_lower.add(norm_lower)
                ext = get_extension(norm)
                batch.append({
                    "normalized_path": norm_lower,
                    "path": norm,
                    "exists_flag": 1,
                    "size": st.st_size,
                    "mtime": st.st_mtime,
                    "hash": None,
                    "is_temp": 1 if is_temp_file(pathlib.Path(norm).name) else 0,
                    "last_seen": now_iso(),
                    "last_event_type": "rescan",
                    "extension": ext,
                    "extra": None,
                })

        # 与基线比对，发现差异
        existing = self._db.get_all_existing()
        existing_map = {r["normalized_path"]: r for r in existing}

        # 新文件（在磁盘上但不在基线中）
        for rec in batch:
            np = rec["normalized_path"]
            if np not in existing_map:
                evt = build_event(
                    EVT_INFERRED_CREATED, rec["path"],
                    size=rec["size"], mtime=rec["mtime"],
                    extension=rec["extension"],
                    is_temp=bool(rec["is_temp"]),
                    source="rescan", confidence="medium",
                    details="重扫发现新文件（可能在 watchdog 事件丢失期间创建）",
                )
                self._audit.write_event(evt)
            else:
                # 检查是否有变化（size 或 mtime）
                old = existing_map[np]
                if (old.get("size") != rec["size"] or
                    (old.get("mtime") is not None and rec["mtime"] is not None
                     and abs(old["mtime"] - rec["mtime"]) > 0.01)):
                    evt = build_event(
                        EVT_INFERRED_MODIFIED, rec["path"],
                        size=rec["size"], mtime=rec["mtime"],
                        extension=rec["extension"],
                        is_temp=bool(rec["is_temp"]),
                        source="rescan", confidence="medium",
                        details="重扫发现文件变化（size/mtime 与基线不一致）",
                    )
                    self._audit.write_event(evt)

        # 消失的文件（在基线中但不在磁盘上）
        for np, old_rec in existing_map.items():
            if np not in seen_lower:
                # 确认文件确实不存在（而非扫描遗漏）
                if not os.path.exists(old_rec["path"]):
                    evt = build_event(
                        EVT_INFERRED_DELETED, old_rec["path"],
                        size=old_rec.get("size"), mtime=old_rec.get("mtime"),
                        extension=old_rec.get("extension", ""),
                        is_temp=bool(old_rec.get("is_temp", 0)),
                        source="rescan", confidence="medium",
                        details="重扫发现文件消失（可能在 watchdog 事件丢失期间删除）",
                    )
                    self._audit.write_event(evt)
                    self._db.mark_deleted(np, EVT_INFERRED_DELETED)

        # 批量更新基线
        if batch:
            self._db.upsert_batch(batch)

        elapsed = time.monotonic() - t0
        self._log.info("重扫完成，耗时 %.2f 秒，扫描 %d 个文件", elapsed, len(seen_lower))

    def _scan_dir(self, dir_path: str, seen_lower: Set[str],
                  batch: List[Dict[str, Any]]) -> None:
        """
        递归扫描目录。使用 os.scandir 减少系统调用。

        性能说明：
          os.scandir 返回 DirEntry 对象，其 stat() 在 Windows 上可以
          直接从目录列表缓存获取，无需额外系统调用，比 os.walk+os.stat 快 2-3 倍。
        """
        try:
            with os.scandir(dir_path) as it:
                for entry in it:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            if entry.name.lower() in self._exclude_dirs_lower:
                                continue
                            if self._config.recursive:
                                self._scan_dir(entry.path, seen_lower, batch)
                        elif entry.is_file(follow_symlinks=False):
                            name = entry.name
                            ext = get_extension(name)
                            norm = normalize_path(entry.path)
                            norm_lower = norm.lower()

                            # 前置过滤
                            is_temp = is_temp_file(name)
                            is_target = (ext in self._effective_exts or
                                         norm_lower in self._explicit_lower or
                                         is_temp)
                            if not is_target:
                                continue

                            if norm_lower in seen_lower:
                                continue
                            seen_lower.add(norm_lower)

                            st = entry.stat(follow_symlinks=False)
                            batch.append({
                                "normalized_path": norm_lower,
                                "path": norm,
                                "exists_flag": 1,
                                "size": st.st_size,
                                "mtime": st.st_mtime,
                                "hash": None,  # 重扫不算哈希，节省 I/O
                                "is_temp": 1 if is_temp else 0,
                                "last_seen": now_iso(),
                                "last_event_type": "rescan",
                                "extension": ext,
                                "extra": None,
                            })
                    except (OSError, PermissionError):
                        continue
        except (OSError, PermissionError):
            pass


# ═════════════════════════════════════════════════════════════
# 初始基线扫描
# ═════════════════════════════════════════════════════════════

def build_initial_baseline(
    config: MonitorConfig,
    db: BaselineDB,
    logger: logging.Logger,
    explicit_lower: Set[str],
) -> int:
    """
    启动时的全量基线扫描。

    与 RescanThread 的区别：
      - 首次扫描需要计算哈希（后续重扫不算）
      - 首次扫描不产生审计事件（这是初始状态）
      - 使用 batch upsert 一次性写入
    """
    logger.info("开始初始基线扫描...")
    t0 = time.monotonic()
    effective_exts = config.effective_extensions()
    exclude_lower = set(d.lower() for d in config.exclude_dirs)
    batch: List[Dict[str, Any]] = []
    seen: Set[str] = set()

    def scan(dir_path: str) -> None:
        try:
            with os.scandir(dir_path) as it:
                for entry in it:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            if entry.name.lower() in exclude_lower:
                                continue
                            if config.recursive:
                                scan(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            name = entry.name
                            ext = get_extension(name)
                            norm = normalize_path(entry.path)
                            norm_lower = norm.lower()
                            is_temp = is_temp_file(name)

                            if not (ext in effective_exts or norm_lower in explicit_lower or is_temp):
                                continue
                            if norm_lower in seen:
                                continue
                            seen.add(norm_lower)

                            st = entry.stat(follow_symlinks=False)
                            # 初始扫描计算哈希（为后续变化检测建立基准）
                            file_hash = None
                            if config.hash_enabled and not is_temp:
                                file_hash = safe_hash(
                                    entry.path, config.hash_algorithm,
                                    config.hash_max_size_mb
                                )

                            batch.append({
                                "normalized_path": norm_lower,
                                "path": norm,
                                "exists_flag": 1,
                                "size": st.st_size,
                                "mtime": st.st_mtime,
                                "hash": file_hash,
                                "is_temp": 1 if is_temp else 0,
                                "last_seen": now_iso(),
                                "last_event_type": "baseline",
                                "extension": ext,
                                "extra": None,
                            })
                    except (OSError, PermissionError):
                        continue
        except (OSError, PermissionError):
            pass

    for wd in config.watch_dirs:
        resolved = normalize_path(wd)
        if os.path.isdir(resolved):
            scan(resolved)

    for ef in config.explicit_files:
        norm = normalize_path(ef)
        norm_lower = norm.lower()
        if norm_lower in seen:
            continue
        st = safe_stat(norm)
        if st:
            seen.add(norm_lower)
            ext = get_extension(norm)
            is_tmp = is_temp_file(pathlib.Path(norm).name)
            file_hash = None
            if config.hash_enabled and not is_tmp:
                file_hash = safe_hash(norm, config.hash_algorithm, config.hash_max_size_mb)
            batch.append({
                "normalized_path": norm_lower,
                "path": norm,
                "exists_flag": 1,
                "size": st.st_size,
                "mtime": st.st_mtime,
                "hash": file_hash,
                "is_temp": 1 if is_tmp else 0,
                "last_seen": now_iso(),
                "last_event_type": "baseline",
                "extension": ext,
                "extra": None,
            })

    if batch:
        db.upsert_batch(batch)

    elapsed = time.monotonic() - t0
    logger.info("初始基线扫描完成：%d 个文件，耗时 %.2f 秒", len(batch), elapsed)
    return len(batch)


# ═════════════════════════════════════════════════════════════
# 单实例锁
# ═════════════════════════════════════════════════════════════

class SingleInstanceLock:
    """
    单实例锁，防止同时运行多个监控进程。

    优先使用 portalocker（跨平台文件锁），
    降级为简单 PID 文件检测。
    """

    def __init__(self, lock_path: str):
        self._lock_path = lock_path
        self._fh = None

    def acquire(self) -> bool:
        if HAS_PORTALOCKER:
            try:
                self._fh = open(self._lock_path, "w")
                portalocker.lock(self._fh, portalocker.LOCK_EX | portalocker.LOCK_NB)
                self._fh.write(str(os.getpid()))
                self._fh.flush()
                return True
            except (portalocker.LockException, OSError):
                return False
        else:
            # 降级：PID 文件检测
            if os.path.exists(self._lock_path):
                try:
                    with open(self._lock_path, "r") as f:
                        old_pid = int(f.read().strip())
                    # 检查旧进程是否还活着
                    if HAS_PSUTIL:
                        if psutil.pid_exists(old_pid):
                            return False
                    else:
                        # 无 psutil，尝试用 os.kill(pid, 0) 检测
                        try:
                            os.kill(old_pid, 0)
                            return False  # 进程存在
                        except (OSError, ProcessLookupError):
                            pass  # 进程不存在，可以获取锁
                except (ValueError, FileNotFoundError):
                    pass
            with open(self._lock_path, "w") as f:
                f.write(str(os.getpid()))
            return True

    def release(self) -> None:
        if self._fh:
            try:
                portalocker.unlock(self._fh)
                self._fh.close()
            except Exception:
                pass
        try:
            os.remove(self._lock_path)
        except OSError:
            pass


# ═════════════════════════════════════════════════════════════
# 应用日志设置
# ═════════════════════════════════════════════════════════════

def setup_app_logger(config: MonitorConfig) -> logging.Logger:
    """配置应用日志（带轮转），输出到文件和控制台。"""
    logger = logging.getLogger("doc_monitor.app")
    logger.setLevel(getattr(logging, config.app_log_level.upper(), logging.INFO))
    logger.propagate = False
    if logger.handlers:
        logger.handlers.clear()

    # 文件 handler（轮转）
    fh = logging.handlers.RotatingFileHandler(
        config.app_log_path,
        maxBytes=config.app_log_max_bytes,
        backupCount=config.app_log_backup_count,
        encoding="utf-8",
    )
    fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logger.addHandler(fh)

    # 控制台 handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    ))
    logger.addHandler(ch)

    return logger


# ═════════════════════════════════════════════════════════════
# 主监控引擎
# ═════════════════════════════════════════════════════════════

class DocMonitorEngine:
    """
    主监控引擎，协调所有组件。

    组件关系：
      watchdog Observer(s)
        └─ DocEventHandler ──→ work_queue ──→ WorkerThread
                                                ├─ Debouncer
                                                ├─ MovePairTracker
                                                ├─ SaveInferrer
                                                ├─ BaselineDB
                                                └─ AuditLogger
      RescanThread（独立定时）
    """

    def __init__(self, config: MonitorConfig):
        self._config = config
        self._log = setup_app_logger(config)
        self._lock = SingleInstanceLock(config.lock_file_path)
        self._db = BaselineDB(config.db_path)
        self._audit = AuditLogger(config)
        self._work_queue: queue.Queue = queue.Queue(maxsize=config.worker_queue_size)
        self._debouncer = Debouncer(config.debounce_seconds, config.stable_wait_seconds)
        self._move_tracker = MovePairTracker(config.move_pair_window)
        self._save_inferrer = SaveInferrer()

        # 解析显式文件列表
        self._explicit_lower: Set[str] = set()
        for ef in config.explicit_files:
            self._explicit_lower.add(normalize_path_lower(ef))

        self._observers: List[Any] = []
        self._worker: Optional[WorkerThread] = None
        self._rescanner: Optional[RescanThread] = None
        self._running = False

    def start(self) -> None:
        """启动监控引擎。"""
        # 0. 路径清洗：剥离 Windows CMD 可能残留的引号字符
        self._config.watch_dirs = [
            d.strip().strip('"').strip("'") for d in self._config.watch_dirs
        ]
        self._config.explicit_files = [
            f.strip().strip('"').strip("'") for f in self._config.explicit_files
        ]
        # 重新计算 explicit_lower（因为路径可能被清洗）
        self._explicit_lower = set()
        for ef in self._config.explicit_files:
            self._explicit_lower.add(normalize_path_lower(ef))

        # 1. 单实例锁
        if not self._lock.acquire():
            self._log.error("另一个 doc_monitor 实例正在运行，退出。")
            sys.exit(1)

        self._log.info("=" * 60)
        self._log.info("Office/WPS 文档监控器 v%s 启动", VERSION)
        self._log.info("=" * 60)
        self._log.info("监控目录: %s", self._config.watch_dirs)
        self._log.info("显式文件: %s", self._config.explicit_files)
        self._log.info("递归: %s", self._config.recursive)
        self._log.info("生效后缀: %s", sorted(self._config.effective_extensions()))
        self._log.info("去抖窗口: %.1fs, 稳定等待: %.1fs",
                       self._config.debounce_seconds, self._config.stable_wait_seconds)
        self._log.info("重扫间隔: %ds", self._config.rescan_interval_seconds)

        # 2. 初始基线
        count = build_initial_baseline(
            self._config, self._db, self._log, self._explicit_lower
        )
        self._log.info("基线文件数: %d", count)

        # 3. 启动工作线程
        self._worker = WorkerThread(
            self._work_queue, self._config, self._db, self._audit,
            self._debouncer, self._move_tracker, self._save_inferrer,
            self._explicit_lower, self._log,
        )
        self._worker.start()

        # 4. 启动 watchdog observer(s)
        self._start_observers()

        # 5. 启动重扫线程
        if self._config.rescan_enabled:
            self._rescanner = RescanThread(
                self._config, self._db, self._audit, self._log, self._explicit_lower,
            )
            self._rescanner.start()

        self._running = True
        self._log.info("监控引擎已启动，按 Ctrl+C 停止")

    def _start_observers(self) -> None:
        """
        创建和启动 watchdog observer。

        策略：
          - 本地磁盘路径 → Observer（ReadDirectoryChangesW，事件驱动，零轮询开销）
          - 网络路径 → PollingObserver（降级兜底）
          - 显式文件 → 复用其父目录的 watcher，应用层做路径过滤
        """
        handler = DocEventHandler(
            self._work_queue, self._config,
            self._explicit_lower, self._log,
        )

        # 收集所有需要监控的目录
        all_dirs: Dict[str, bool] = {}  # path -> is_network

        for wd in self._config.watch_dirs:
            resolved = normalize_path(wd)
            is_net = self._is_network_path(resolved)
            all_dirs[resolved] = is_net

        # 显式文件：加入其父目录
        for ef in self._config.explicit_files:
            parent = str(pathlib.Path(normalize_path(ef)).parent)
            if parent not in all_dirs:
                all_dirs[parent] = self._is_network_path(parent)

        # 按本地/网络分组创建 observer
        local_dirs = [d for d, is_net in all_dirs.items() if not is_net]
        network_dirs = [d for d, is_net in all_dirs.items() if is_net]

        if local_dirs:
            obs = Observer()
            scheduled = 0
            for d in local_dirs:
                if os.path.isdir(d):
                    obs.schedule(handler, d, recursive=self._config.recursive)
                    self._log.info("本地监控 (Observer/ReadDirectoryChangesW): %s", d)
                    scheduled += 1
                else:
                    self._log.error("目录不存在或不可访问，已跳过: %s", d)
            if scheduled > 0:
                obs.start()
                self._observers.append(obs)
            else:
                self._log.error("没有任何本地目录被成功挂载！请检查 --watch-dirs 路径是否正确。")

        if network_dirs:
            # 网络路径使用 PollingObserver 作为降级
            pobs = PollingObserver(timeout=self._config.polling_interval)
            scheduled = 0
            for d in network_dirs:
                if os.path.isdir(d):
                    pobs.schedule(handler, d, recursive=self._config.recursive)
                    self._log.info("网络监控 (PollingObserver, %.1fs): %s",
                                   self._config.polling_interval, d)
                    scheduled += 1
                else:
                    self._log.error("网络目录不存在或不可访问，已跳过: %s", d)
            if scheduled > 0:
                pobs.start()
                self._observers.append(pobs)

    def _is_network_path(self, path: str) -> bool:
        """判断路径是否为网络路径。"""
        # UNC 路径
        if path.startswith("\\\\") or path.startswith("//"):
            return True
        # 配置中标记的网络路径
        path_lower = path.lower()
        for np in self._config.network_paths:
            if path_lower.startswith(normalize_path_lower(np)):
                return True
        return False

    def wait(self) -> None:
        """阻塞等待直到收到停止信号。"""
        try:
            while self._running:
                time.sleep(1)
        except KeyboardInterrupt:
            self._log.info("收到 Ctrl+C，正在停止...")
            self.stop()

    def stop(self) -> None:
        """优雅停止所有组件。"""
        self._running = False
        self._log.info("正在停止监控引擎...")

        # 停止 observers
        for obs in self._observers:
            try:
                obs.stop()
            except Exception:
                pass

        # 等待 observers 结束
        for obs in self._observers:
            try:
                obs.join(timeout=5)
            except Exception:
                pass

        # 停止重扫
        if self._rescanner:
            self._rescanner.stop()
            self._rescanner.join(timeout=5)

        # 停止工作线程
        if self._worker:
            self._worker.stop()
            self._worker.join(timeout=10)

        # 关闭数据库
        self._db.close()

        # 释放锁
        self._lock.release()

        self._log.info("监控引擎已停止")


# ═════════════════════════════════════════════════════════════
# 默认配置 JSON 生成
# ═════════════════════════════════════════════════════════════

def dump_default_config() -> str:
    """生成推荐默认配置 JSON。"""
    return MonitorConfig().to_json(indent=2)


# ═════════════════════════════════════════════════════════════
# 命令行入口
# ═════════════════════════════════════════════════════════════



# ═════════════════════════════════════════════════════════════
# 旧版 doc_guard 兼容层
# ═════════════════════════════════════════════════════════════

def new_event_id() -> str:
    return make_event_id()


def old_cfg_to_monitor_config(cfg: Dict[str, Any]) -> MonitorConfig:
    output_dir = os.path.abspath(cfg['output_dir'])
    os.makedirs(output_dir, exist_ok=True)
    exts = sorted({str(x).lower() for x in cfg.get('target_extensions', set())})
    exts = sorted(set(exts) | {
        '.doc', '.docx', '.docm', '.dot', '.dotx', '.dotm', '.rtf', '.wps', '.wpt',
        '.xls', '.xlsx', '.xlsm', '.xlsb', '.xlt', '.xltx', '.xltm', '.csv', '.et', '.ett',
        '.ppt', '.pptx', '.pptm', '.pps', '.ppsx', '.ppsm', '.pot', '.potx', '.potm', '.dps', '.dpt'
    })
    return MonitorConfig(
        watch_dirs=[os.path.abspath(p) for p in cfg.get('monitor_roots', [])],
        explicit_files=[os.path.abspath(p) for p in cfg.get('explicit_files', [])],
        recursive=True,
        document_extensions=exts,
        optional_extensions=sorted(OPTIONAL_EXTENSIONS),
        enable_optional_extensions=False,
        exclude_dirs=sorted(DEFAULT_EXCLUDE_DIRS),
        debounce_seconds=float(cfg.get('debounce_seconds', 0.8)),
        stable_wait_seconds=float(cfg.get('stable_wait_seconds', 1.2)),
        move_pair_window=max(2.0, float(cfg.get('stable_wait_seconds', 1.2)) + 0.8),
        hash_enabled=True,
        hash_on_create=True,
        hash_on_modify=True,
        hash_max_size_mb=512,
        hash_algorithm=cfg.get('hash_algorithm', 'sha256'),
        rescan_interval_seconds=int(cfg.get('periodic_rescan_seconds', 300) or 0),
        rescan_enabled=bool(cfg.get('periodic_rescan_seconds', 300)),
        db_path=os.path.join(output_dir, 'baseline.db'),
        db_batch_interval=5.0,
        audit_log_path=os.path.join(output_dir, 'audit.jsonl'),
        audit_log_max_bytes=50 * 1024 * 1024,
        audit_log_backup_count=max(1, int(cfg.get('log_rotate_count', 5))),
        app_log_path=os.path.join(output_dir, 'doc_guard.log'),
        app_log_max_bytes=max(1, int(cfg.get('log_rotate_mb', 10))) * 1024 * 1024,
        app_log_backup_count=max(1, int(cfg.get('log_rotate_count', 5))),
        app_log_level='INFO',
        lock_file_path=os.path.join(output_dir, cfg.get('lock_file_name', 'doc_guard.lock')),
        network_paths=[],
        polling_interval=5.0,
        worker_queue_size=10000,
    )


class MonitorEngine:
    """旧类名兼容包装器：外部接口保持 MonitorEngine，不改旧用法。"""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.mcfg = old_cfg_to_monitor_config(cfg)
        self.logger = setup_app_logger(self.mcfg)
        self.db = BaselineDB(self.mcfg.db_path)
        self.audit = AuditLogger(self.mcfg)
        self.attributor = ProcessAttributor(cfg)
        self.security = SecurityAuditEnhancer(cfg.get('enable_security_audit_mode', False))
        self._lock = SingleInstanceLock(self.mcfg.lock_file_path)
        self._work_queue: queue.Queue = queue.Queue(maxsize=self.mcfg.worker_queue_size)
        self._debouncer = Debouncer(self.mcfg.debounce_seconds, self.mcfg.stable_wait_seconds)
        self._move_tracker = MovePairTracker(self.mcfg.move_pair_window)
        self._save_inferrer = SaveInferrer()
        self._explicit_lower: Set[str] = {normalize_path_lower(p) for p in self.mcfg.explicit_files}
        self._observers: List[Any] = []
        self._worker: Optional[CompatWorkerThread] = None
        self._rescanner: Optional[RescanThread] = None
        self._stop_event = threading.Event()
        self._running = False

    def _is_network_path(self, path: str) -> bool:
        return path.startswith('\\\\') or path.startswith('//')

    def _start_observers(self):
        handler = DocEventHandler(self._work_queue, self.mcfg, self._explicit_lower, self.logger)
        all_dirs: Dict[str, bool] = {}
        for wd in self.mcfg.watch_dirs:
            wd_norm = normalize_path(wd)
            all_dirs[wd_norm] = self._is_network_path(wd_norm)
        for ef in self.mcfg.explicit_files:
            parent = str(pathlib.Path(normalize_path(ef)).parent)
            all_dirs.setdefault(parent, self._is_network_path(parent))

        local_dirs = [d for d, is_net in all_dirs.items() if not is_net]
        network_dirs = [d for d, is_net in all_dirs.items() if is_net]

        if local_dirs:
            obs = Observer()
            scheduled = 0
            for d in local_dirs:
                if os.path.isdir(d):
                    obs.schedule(handler, d, recursive=self.mcfg.recursive)
                    self.logger.info(f"已注册监控: {d}")
                    scheduled += 1
                else:
                    self.logger.warning(f"目录不存在，跳过: {d}")
            if scheduled:
                obs.start()
                self._observers.append(obs)

        if network_dirs:
            pobs = PollingObserver(timeout=self.mcfg.polling_interval)
            scheduled = 0
            for d in network_dirs:
                if os.path.isdir(d):
                    pobs.schedule(handler, d, recursive=self.mcfg.recursive)
                    self.logger.info(f"已注册网络监控: {d}")
                    scheduled += 1
                else:
                    self.logger.warning(f"网络目录不存在，跳过: {d}")
            if scheduled:
                pobs.start()
                self._observers.append(pobs)

    def start(self):
        self.mcfg.watch_dirs = [d.strip().strip('"').strip("'") for d in self.mcfg.watch_dirs]
        self.mcfg.explicit_files = [f.strip().strip('"').strip("'") for f in self.mcfg.explicit_files]
        self._explicit_lower = {normalize_path_lower(p) for p in self.mcfg.explicit_files}

        self.logger.info("=" * 60)
        self.logger.info("DocGuard 兼容增强版启动")
        self.logger.info(f"监控目录: {self.mcfg.watch_dirs}")
        self.logger.info(f"显式文件: {self.mcfg.explicit_files}")
        self.logger.info(f"目标扩展名: {sorted(self.mcfg.effective_extensions())}")
        self.logger.info(
            f"安全审计增强: {self.security.available}" +
            (f" ({self.security.degrade_reason})" if not self.security.available else "")
        )
        self.logger.info("=" * 60)

        count = build_initial_baseline(self.mcfg, self.db, self.logger, self._explicit_lower)
        self.logger.info(f"基线文件数: {count}")

        self.security.start()

        self._worker = CompatWorkerThread(
            self._work_queue, self.mcfg, self.db, self.audit,
            self._debouncer, self._move_tracker, self._save_inferrer,
            self._explicit_lower, self.logger,
            attributor=self.attributor, security=self.security,
        )
        self._worker.start()

        self._start_observers()

        if self.mcfg.rescan_enabled:
            self._rescanner = RescanThread(self.mcfg, self.db, self.audit, self.logger, self._explicit_lower)
            self._rescanner.start()

        self._running = True
        self._stop_event.clear()
        self.logger.info("监控引擎已启动，按 Ctrl+C 停止")

    def stop(self):
        if self._stop_event.is_set():
            return
        self.logger.info("正在停止监控引擎...")
        self._stop_event.set()
        self._running = False

        for obs in self._observers:
            try:
                obs.stop()
            except Exception:
                pass
        for obs in self._observers:
            try:
                obs.join(timeout=5)
            except Exception:
                pass

        if self._rescanner:
            self._rescanner.stop()
            self._rescanner.join(timeout=5)

        if self._worker:
            self._worker.stop()
            self._worker.join(timeout=10)

        self.security.stop()
        self.db.close()
        self.logger.info("监控引擎已停止")

    def run_forever(self):
        self.start()
        try:
            while not self._stop_event.is_set():
                self._stop_event.wait(1)
        except KeyboardInterrupt:
            self.logger.info("收到 Ctrl+C，正在退出...")
        finally:
            self.stop()

    def full_rescan(self):
        self.logger.info("开始执行一次全量重扫...")
        rescanner = RescanThread(self.mcfg, self.db, self.audit, self.logger, self._explicit_lower)
        rescanner._do_rescan()
        self.logger.info("全量重扫完成")


def _get_script_cmd() -> str:
    python_exe = sys.executable
    script_path = os.path.abspath(__file__)
    return f'"{python_exe}" "{script_path}" --run'


def install_autostart(mode: str = 'run_key', audit: Optional[AuditWriter] = None,
                      logger: Optional[logging.Logger] = None):
    if not logger:
        logger = logging.getLogger('doc_guard')
    cmd = _get_script_cmd()
    if mode == 'run_key':
        _install_run_key(cmd, logger)
    elif mode == 'task_scheduler':
        _install_task_scheduler(cmd, logger)
    else:
        logger.error(f"未知的自启模式: {mode}")
        return

    logger.info(f"开机自启已注册 (模式={mode})")
    if audit:
        audit.write_event({
            "event_id": new_event_id(),
            "ts": now_iso(),
            "event_type": "startup_registered",
            "path": "",
            "details": {"mode": mode, "command": cmd},
            "source": "system",
        })


def uninstall_autostart(mode: str = 'run_key', audit: Optional[AuditWriter] = None,
                        logger: Optional[logging.Logger] = None):
    if not logger:
        logger = logging.getLogger('doc_guard')

    if mode == 'run_key':
        _uninstall_run_key(logger)
    elif mode == 'task_scheduler':
        _uninstall_task_scheduler(logger)
    else:
        logger.error(f"未知的自启模式: {mode}")
        return

    logger.info(f"开机自启已取消 (模式={mode})")
    if audit:
        audit.write_event({
            "event_id": new_event_id(),
            "ts": now_iso(),
            "event_type": "startup_unregistered",
            "path": "",
            "details": {"mode": mode},
            "source": "system",
        })


def _install_run_key(cmd: str, logger: logging.Logger):
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, APP_REG_KEY, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, cmd)
        winreg.CloseKey(key)
        logger.info("通过 winreg 注册成功")
    except Exception:
        try:
            subprocess.run(
                ["reg", "add", f"HKCU\\{APP_REG_KEY}", "/v", APP_NAME, "/t", "REG_SZ", "/d", cmd, "/f"],
                check=True, capture_output=True
            )
            logger.info("通过 reg 命令注册成功")
        except Exception as exc:
            logger.error(f"注册表写入失败: {exc}")


def _uninstall_run_key(logger: logging.Logger):
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, APP_REG_KEY, 0, winreg.KEY_SET_VALUE)
        try:
            winreg.DeleteValue(key, APP_NAME)
        except FileNotFoundError:
            logger.info("注册表键不存在，无需删除")
        winreg.CloseKey(key)
    except Exception:
        try:
            subprocess.run(
                ["reg", "delete", f"HKCU\\{APP_REG_KEY}", "/v", APP_NAME, "/f"],
                check=True, capture_output=True
            )
        except Exception as exc:
            logger.error(f"注册表删除失败: {exc}")


def _install_task_scheduler(cmd: str, logger: logging.Logger):
    python_exe = sys.executable
    script_path = os.path.abspath(__file__)
    try:
        subprocess.run(["schtasks", "/Delete", "/TN", APP_TASK_NAME, "/F"], capture_output=True)
        subprocess.run([
            "schtasks", "/Create",
            "/TN", APP_TASK_NAME,
            "/TR", f'"{python_exe}" "{script_path}" --run',
            "/SC", "ONLOGON",
            "/RL", "LIMITED",
            "/F",
        ], check=True, capture_output=True)
        logger.info("Task Scheduler 任务创建成功")
    except Exception as exc:
        logger.error(f"Task Scheduler 注册失败: {exc}")


def _uninstall_task_scheduler(logger: logging.Logger):
    try:
        result = subprocess.run(["schtasks", "/Delete", "/TN", APP_TASK_NAME, "/F"], capture_output=True, text=True)
        if result.returncode == 0:
            logger.info("Task Scheduler 任务已删除")
        else:
            logger.info(f"Task Scheduler 任务删除: {result.stderr.strip()}")
    except Exception as exc:
        logger.error(f"Task Scheduler 删除失败: {exc}")


def show_status(cfg: dict):
    output_dir = cfg["output_dir"]
    db_path = os.path.join(output_dir, "baseline.db")
    lock_path = os.path.join(output_dir, cfg["lock_file_name"])
    audit_path = os.path.join(output_dir, "audit.jsonl")

    print(f"{'=' * 50}")
    print("DocGuard 状态报告")
    print(f"{'=' * 50}")
    print(f"输出目录:     {output_dir}")
    print(f"数据库:       {db_path} ({'存在' if os.path.isfile(db_path) else '不存在'})")
    print(f"审计日志:     {audit_path} ({'存在' if os.path.isfile(audit_path) else '不存在'})")

    if os.path.isfile(lock_path):
        try:
            with open(lock_path, "r", encoding="utf-8", errors="ignore") as f:
                pid = int((f.read() or "0").strip() or "0")
            if HAS_PSUTIL and pid and psutil.pid_exists(pid):
                print(f"运行状态:     运行中 (PID={pid})")
            else:
                print(f"运行状态:     未运行 (陈旧锁文件, PID={pid})")
        except Exception:
            print("运行状态:     未知")
    else:
        print("运行状态:     未运行")

    if os.path.isfile(db_path):
        try:
            conn = sqlite3.connect(db_path)
            count = conn.execute("SELECT COUNT(*) FROM baseline").fetchone()[0]
            conn.close()
            print(f"基线文件数:   {count}")
        except Exception:
            print("基线文件数:   (无法读取)")

    if os.path.isfile(audit_path):
        try:
            with open(audit_path, "r", encoding="utf-8") as f:
                lines = sum(1 for _ in f)
            print(f"审计日志行数: {lines}")
        except Exception:
            print("审计日志行数: (无法读取)")

    autostart = False
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, APP_REG_KEY, 0, winreg.KEY_READ)
        try:
            val, _ = winreg.QueryValueEx(key, APP_NAME)
            autostart = True
            print("开机自启:     已注册 (Run Key)")
            print(f"  命令:       {val}")
        except FileNotFoundError:
            pass
        winreg.CloseKey(key)
    except Exception:
        pass

    try:
        result = subprocess.run(["schtasks", "/Query", "/TN", APP_TASK_NAME], capture_output=True, text=True)
        if result.returncode == 0:
            autostart = True
            print("开机自启:     已注册 (Task Scheduler)")
    except Exception:
        pass

    if not autostart:
        print("开机自启:     未注册")

    print(f"{'=' * 50}")
    print("监控目录:")
    for rd in cfg["monitor_roots"]:
        exists = os.path.isdir(rd)
        print(f"  {'[OK]' if exists else '[!!]'} {rd}")
    if cfg["explicit_files"]:
        print("显式文件:")
        for ef in cfg["explicit_files"]:
            exists = os.path.isfile(ef)
            print(f"  {'[OK]' if exists else '[!!]'} {ef}")
    print(f"{'=' * 50}")


def main():
    parser = argparse.ArgumentParser(
        description="DocGuard - 通用文档操作监控器（兼容增强版）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
命令示例:
  python doc_guard.py --run                  启动监控
  python doc_guard.py --install-autostart    注册开机自启
  python doc_guard.py --uninstall-autostart  取消开机自启
  python doc_guard.py --status               查看状态
  python doc_guard.py --rescan               执行一次全量重扫后退出
        """,
    )
    parser.add_argument("--run", action="store_true", help="启动监控（长期驻留）")
    parser.add_argument("--install-autostart", action="store_true", help="注册开机自启")
    parser.add_argument("--uninstall-autostart", action="store_true", help="取消开机自启")
    parser.add_argument("--status", action="store_true", help="查看监控状态")
    parser.add_argument("--rescan", action="store_true", help="执行全量重扫后退出")
    parser.add_argument("--output-dir", type=str, help="覆盖输出目录")
    parser.add_argument("--monitor-root", action="append", help="监控目录，可重复指定")
    args = parser.parse_args()

    if args.output_dir:
        CONFIG["output_dir"] = os.path.abspath(args.output_dir)

    if args.monitor_root:
        CONFIG["monitor_roots"] = [os.path.abspath(p) for p in args.monitor_root]

    if not any([args.run, args.install_autostart, args.uninstall_autostart, args.status, args.rescan]):
        parser.print_help()
        sys.exit(0)

    logger = setup_logging(
        CONFIG["output_dir"],
        CONFIG["log_rotate_mb"],
        CONFIG["log_rotate_count"],
    )

    if args.status:
        show_status(CONFIG)
        return

    if args.install_autostart:
        audit = AuditWriter(CONFIG["output_dir"], CONFIG.get("audit_rotate_lines", 0))
        install_autostart(CONFIG["autostart_mode"], audit, logger)
        return

    if args.uninstall_autostart:
        audit = AuditWriter(CONFIG["output_dir"], CONFIG.get("audit_rotate_lines", 0))
        uninstall_autostart(CONFIG["autostart_mode"], audit, logger)
        return

    if args.rescan:
        engine = MonitorEngine(CONFIG)
        engine.full_rescan()
        engine.db.close()
        logger.info("重扫完成")
        return

    if args.run:
        lock = SingleInstanceLock(os.path.join(os.path.abspath(CONFIG["output_dir"]), CONFIG["lock_file_name"]))
        if not lock.acquire():
            logger.error("另一个 DocGuard 实例已在运行，退出")
            print("错误: 另一个 DocGuard 实例已在运行。")
            sys.exit(1)

        engine = MonitorEngine(CONFIG)

        def signal_handler(sig, frame):
            logger.info(f"收到信号 {sig}，正在退出...")
            engine.stop()
            lock.release()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        try:
            engine._lock = lock
            engine.run_forever()
        except Exception as exc:
            logger.critical(f"引擎异常退出: {exc}\n{traceback.format_exc()}")
        finally:
            lock.release()


if __name__ == "__main__":
    main()
