import hashlib
import json
import re
import shutil
import time
import unicodedata
import uuid
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Optional

from config_app import DATA_DIR
from detection.parsers import extract_file_content
from models import (
    FileRecord,
    FileVersion,
    ParseResult,
    TrackedFile,
    TrackedFileEvent,
    TrackedFileVersion,
)
from path_utils import remote_path_name
from storage import db_session, object_storage


TRACK_ROOT = DATA_DIR / "guard_state"
CONTENT_EVENTS = {"initial", "modified", "restored"}
RETAINED_CONTENT_SNAPSHOTS = 3


def _now() -> float:
    return time.time()


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value or "file")[:160]


def _norm_path(value: Optional[str]) -> str:
    return str(value or "").replace("/", "\\").strip().lower()


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()


def _file_key(agent_id: str, path: str, content_hash: str = "") -> str:
    seed = f"{agent_id}|{_norm_path(path)}|{content_hash[:16]}"
    return _hash_text(seed)[:32]


def _tracked_dir(agent_id: str, tracked_file_id: str) -> Path:
    return TRACK_ROOT / agent_id / "files" / tracked_file_id


def _ensure_dirs(agent_id: str, tracked_file_id: str) -> dict[str, Path]:
    root = _tracked_dir(agent_id, tracked_file_id)
    dirs = {
        "root": root,
        "events": root / "events",
        "versions": root / "versions",
        "highlights": root / "highlights",
        "diffs": root / "diffs",
    }
    for path in dirs.values():
        path.mkdir(parents=True, exist_ok=True)
    return dirs


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _read_text_blocks(path: Optional[Path]) -> list[str]:
    if not path or not path.exists():
        return []
    result = extract_file_content(path)
    blocks = []
    for item in result.get("text_blocks") or []:
        text = str(item.get("text") or "").strip()
        if text:
            blocks.append(text)
    return blocks


def _diff_texts(old_path: Optional[Path], new_path: Optional[Path], rename: Optional[dict] = None, deleted: Optional[dict] = None) -> dict:
    old_texts = _read_text_blocks(old_path)
    new_texts = _read_text_blocks(new_path)
    matcher = SequenceMatcher(a=old_texts, b=new_texts, autojunk=False)
    added: list[str] = []
    removed: list[str] = []
    modified: list[dict[str, str]] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        if tag == "insert":
            added.extend(new_texts[j1:j2])
        elif tag == "delete":
            removed.extend(old_texts[i1:i2])
        elif tag == "replace":
            before = "\n".join(old_texts[i1:i2]).strip()
            after = "\n".join(new_texts[j1:j2]).strip()
            modified.append({"before": before, "after": after})
    summary_parts = []
    if added:
        summary_parts.append(f"新增 {len(added)} 处文本")
    if removed:
        summary_parts.append(f"删除 {len(removed)} 处文本")
    if modified:
        summary_parts.append(f"修改 {len(modified)} 个文本块")
    if rename:
        summary_parts.append(f"文件已重命名：{rename.get('old_name')} -> {rename.get('new_name')}")
    if deleted:
        summary_parts.append(f"文件已于 {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(deleted.get('deleted_at') or _now())))} 删除")
    if not summary_parts:
        summary_parts.append("文件内容无可解析文本差异")
    return {
        "summary": "，".join(summary_parts),
        "added_texts": added[:50],
        "removed_texts": removed[:50],
        "modified_blocks": modified[:50],
        "rename": rename,
        "deleted": deleted,
    }


def _extract_hits(parse_data: dict | None) -> list[dict[str, Any]]:
    hits = []
    for key in ("rule_findings", "ocr_findings", "llm_findings"):
        for item in (parse_data or {}).get(key) or []:
            matched = str(item.get("matched_text") or item.get("text") or "").strip()
            if not matched:
                continue
            hit = dict(item)
            hit["matched_text"] = matched
            hit["source_group"] = key
            hits.append(hit)
    return hits


def _hit_texts(hits: list[dict[str, Any]]) -> list[str]:
    seen = set()
    values = []
    for hit in hits:
        text = str(hit.get("matched_text") or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        values.append(text)
    return values


def _highlight_docx(source: Path, target: Path, hits: list[str]) -> Optional[str]:
    if not hits:
        return None
    from docx import Document
    from docx.enum.text import WD_COLOR_INDEX

    doc = Document(source)

    def mark_paragraph(paragraph):
        text = paragraph.text or ""
        if not any(hit in text for hit in hits):
            return
        for run in paragraph.runs:
            run_text = run.text or ""
            if any(hit in run_text for hit in hits) or run_text:
                run.font.highlight_color = WD_COLOR_INDEX.YELLOW

    for paragraph in doc.paragraphs:
        mark_paragraph(paragraph)
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                for paragraph in cell.paragraphs:
                    mark_paragraph(paragraph)
    target.parent.mkdir(parents=True, exist_ok=True)
    doc.save(target)
    return "docx_highlight"


def _normalize_pdf_text(value: str) -> str:
    value = unicodedata.normalize("NFKC", value or "")
    return re.sub(r"\s+", "", value)


def _highlight_pdf(source: Path, target: Path, hits: list[str]) -> Optional[str]:
    if not hits:
        return None
    import fitz

    doc = fitz.open(source)
    applied = 0
    normalized_hits = [(hit, _normalize_pdf_text(hit)) for hit in hits if hit.strip()]
    for page in doc:
        page_text = page.get_text("text") or ""
        searchable = bool(page_text.strip())
        for raw_hit, normalized_hit in normalized_hits:
            rects = page.search_for(raw_hit)
            if not rects and searchable and normalized_hit and normalized_hit in _normalize_pdf_text(page_text):
                # PyMuPDF search_for keeps native PDF text coordinates. If the exact
                # spacing differs, report fallback instead of pretending precision.
                continue
            for rect in rects:
                annot = page.add_highlight_annot(rect)
                if annot:
                    annot.set_info(content=f"Sensitive hit: {raw_hit[:80]}")
                    annot.update()
                    applied += 1
    if applied <= 0:
        doc.close()
        return None
    target.parent.mkdir(parents=True, exist_ok=True)
    doc.save(target, garbage=4, deflate=True)
    doc.close()
    return "pdf_native_highlight_pdf"


def _create_highlight(source: Optional[Path], target_dir: Path, version_no: int, name: str, hits: list[dict[str, Any]]) -> tuple[Optional[str], Optional[str], dict]:
    if not source or not source.exists():
        return None, None, {"status": "missing_source"}
    suffix = source.suffix.lower()
    hit_values = _hit_texts(hits)
    if suffix == ".docx":
        target = target_dir / f"v{version_no}_{_safe_name(Path(name).stem)}_highlight.docx"
        artifact_type = _highlight_docx(source, target, hit_values)
        return (str(target), artifact_type, {"status": "ok" if artifact_type else "no_hits", "strategy": "docx_run_or_paragraph"})
    if suffix == ".pdf":
        target = target_dir / f"v{version_no}_{_safe_name(Path(name).stem)}_native_highlight.pdf"
        artifact_type = _highlight_pdf(source, target, hit_values)
        status = "ok" if artifact_type else "fallback_text_only"
        return (str(target) if artifact_type else None, artifact_type, {"status": status, "strategy": "pdf_native_textmarkup_annotation"})
    return None, None, {"status": "unsupported_file_type"}


def _copy_snapshot(file_row: FileRecord, dirs: dict[str, Path], version_no: int, name: str) -> Optional[Path]:
    if not file_row.store_path:
        return None
    suffix = Path(name or file_row.file_name or "").suffix or (file_row.file_type or "")
    target = dirs["versions"] / f"v{version_no}_{_safe_name(name or file_row.file_name or file_row.file_hash)}{suffix if suffix and not str(name).lower().endswith(str(suffix).lower()) else ''}"
    data = object_storage.get_bytes(file_row.store_path)
    target.write_bytes(data)
    return target


def _find_tracked(session, agent_id: str, path: Optional[str] = None, content_hash: Optional[str] = None) -> Optional[TrackedFile]:
    query = session.query(TrackedFile).filter(TrackedFile.agent_id == agent_id)
    if path:
        row = query.filter(TrackedFile.current_path == path).first()
        if row:
            return row
        norm = _norm_path(path)
        for item in query.all():
            if _norm_path(item.current_path) == norm or _norm_path(item.original_path) == norm:
                return item
    if content_hash:
        version = session.query(TrackedFileVersion).filter(TrackedFileVersion.content_hash == content_hash).order_by(TrackedFileVersion.snapshot_time.desc()).first()
        if version:
            return session.get(TrackedFile, version.tracked_file_id)
    return None


def _serialize_tracked_file(row: TrackedFile, latest_event_type: str = "") -> dict:
    return {
        "tracked_file_id": row.tracked_file_id,
        "agent_id": row.agent_id,
        "file_key": row.file_key,
        "current_path": row.current_path,
        "current_name": row.current_name,
        "original_path": row.original_path,
        "original_name": row.original_name,
        "file_type": row.file_type,
        "sensitive_level": row.sensitive_level,
        "is_deleted": row.is_deleted,
        "first_seen_at": row.first_seen_at,
        "last_seen_at": row.last_seen_at,
        "deleted_at": row.deleted_at,
        "latest_event_type": latest_event_type,
        "latest_version_no": row.latest_version_no,
        "latest_version_id": row.latest_version_id,
        "rename_count": row.rename_count,
        "modify_count": row.modify_count,
    }


def _serialize_version(row: TrackedFileVersion, tracked_file_id: Optional[str] = None) -> dict:
    base = f"/api/v1/sensitive-files/{tracked_file_id or row.tracked_file_id}/versions/{row.version_id}"
    return {
        "version_id": row.version_id,
        "tracked_file_id": row.tracked_file_id,
        "version_no": row.version_no,
        "snapshot_time": row.snapshot_time,
        "event_type": row.event_type,
        "path_at_that_time": row.path_at_that_time,
        "name_at_that_time": row.name_at_that_time,
        "content_hash": row.content_hash,
        "prev_version_id": row.prev_version_id,
        "change_summary": row.change_summary,
        "change_detail_json": row.change_detail_json or {},
        "sensitive_hits": row.sensitive_hits or [],
        "can_download": bool(row.stored_file_path and row.is_snapshot_retained and Path(row.stored_file_path).exists()),
        "has_highlight": bool(row.highlight_artifact_path and Path(row.highlight_artifact_path).exists()),
        "has_diff": bool(row.diff_artifact_path and Path(row.diff_artifact_path).exists()),
        "download_url": f"{base}/download",
        "highlight_download_url": f"{base}/download-highlight",
        "diff_download_url": f"{base}/download-diff",
        "snapshot_retention_note": "" if row.is_snapshot_retained else "该历史版本仅保留摘要，原文件快照已清理",
        "artifact_type": row.artifact_type,
    }


def _serialize_event(row: TrackedFileEvent) -> dict:
    return {
        "event_id": row.event_id,
        "tracked_file_id": row.tracked_file_id,
        "event_time": row.event_time,
        "event_type": row.event_type,
        "old_path": row.old_path,
        "new_path": row.new_path,
        "old_name": row.old_name,
        "new_name": row.new_name,
        "description": row.description,
        "raw_event_json": row.raw_event_json or {},
        "version_id": row.version_id,
    }


def _sync_metadata(session, tracked: TrackedFile) -> None:
    dirs = _ensure_dirs(tracked.agent_id, tracked.tracked_file_id)
    latest_event = session.query(TrackedFileEvent).filter(TrackedFileEvent.tracked_file_id == tracked.tracked_file_id).order_by(TrackedFileEvent.event_time.desc()).first()
    _write_json(dirs["root"] / "metadata.json", _serialize_tracked_file(tracked, latest_event.event_type if latest_event else ""))


def _prune_old_snapshots(session, tracked: TrackedFile) -> None:
    rows = (
        session.query(TrackedFileVersion)
        .filter(TrackedFileVersion.tracked_file_id == tracked.tracked_file_id, TrackedFileVersion.event_type.in_(list(CONTENT_EVENTS)))
        .order_by(TrackedFileVersion.version_no.desc())
        .all()
    )
    for row in rows[RETAINED_CONTENT_SNAPSHOTS:]:
        if not row.stored_file_path or not row.is_snapshot_retained:
            continue
        path = Path(row.stored_file_path)
        try:
            if path.exists():
                path.unlink()
        except Exception:
            pass
        row.is_snapshot_retained = False
        row.stored_file_path = None
        session.add(row)


def archive_sensitive_file(file_hash: str, agent_id: Optional[str] = None, file_path: Optional[str] = None, event_type: str = "initial", event_time: Optional[float] = None) -> Optional[dict]:
    with db_session() as session:
        file_row = session.get(FileRecord, file_hash)
        parse_row = session.get(ParseResult, file_hash)
        if not file_row or not file_row.is_sensitive:
            return None
        versions_query = session.query(FileVersion).filter(FileVersion.file_hash == file_hash)
        if agent_id:
            versions_query = versions_query.filter(FileVersion.agent_id == agent_id)
        if file_path:
            versions_query = versions_query.filter(FileVersion.file_path == file_path)
        file_versions = versions_query.order_by(FileVersion.created_at.asc()).all()
        if not file_versions:
            file_versions = [FileVersion(agent_id=agent_id or "server", file_path=file_path or file_row.file_name or file_hash, file_hash=file_hash, is_current=True)]

        archived = None
        for current in file_versions:
            archived = _archive_sensitive_row(session, file_row, parse_row, current.agent_id, current.file_path, event_type, event_time)
        return archived


def _archive_sensitive_row(session, file_row: FileRecord, parse_row: Optional[ParseResult], agent_id: str, path: str, event_type: str, event_time: Optional[float]) -> dict:
    event_time = float(event_time or _now())
    name = remote_path_name(path or file_row.file_name, file_row.file_hash)
    content_hash_lookup = None if event_type == "initial" else file_row.file_hash
    tracked = _find_tracked(session, agent_id, path=path, content_hash=content_hash_lookup)
    if not tracked:
        tracked = TrackedFile(
            tracked_file_id=str(uuid.uuid4()),
            agent_id=agent_id,
            file_key=_file_key(agent_id, path, file_row.file_hash),
            current_path=path,
            current_name=name,
            original_path=path,
            original_name=name,
            file_type=file_row.file_type or Path(name).suffix.lower(),
            sensitive_level=file_row.risk_level,
            is_deleted=False,
            first_seen_at=event_time,
            last_seen_at=event_time,
            latest_version_no=0,
            rename_count=0,
            modify_count=0,
        )
        session.add(tracked)
        session.flush()

    existing_hash = (
        session.query(TrackedFileVersion)
        .filter(TrackedFileVersion.tracked_file_id == tracked.tracked_file_id, TrackedFileVersion.content_hash == file_row.file_hash)
        .order_by(TrackedFileVersion.version_no.desc())
        .first()
    )
    if existing_hash and event_type == "initial":
        tracked.current_path = path
        tracked.current_name = name
        tracked.last_seen_at = event_time
        _sync_metadata(session, tracked)
        return _serialize_tracked_file(tracked)

    prev = session.get(TrackedFileVersion, tracked.latest_version_id) if tracked.latest_version_id else None
    actual_event = "initial" if tracked.latest_version_no <= 0 else ("modified" if event_type == "initial" else event_type)
    version_no = int(tracked.latest_version_no or 0) + 1
    dirs = _ensure_dirs(agent_id, tracked.tracked_file_id)
    snapshot_path = _copy_snapshot(file_row, dirs, version_no, name)
    old_path = Path(prev.stored_file_path) if prev and prev.stored_file_path and Path(prev.stored_file_path).exists() else None
    diff = _diff_texts(old_path, snapshot_path)
    diff_path = dirs["diffs"] / f"v{version_no}_diff.json"
    _write_json(diff_path, diff)
    hits = _extract_hits(parse_row.result_data if parse_row else {})
    highlight_path, artifact_type, highlight_detail = _create_highlight(snapshot_path, dirs["highlights"], version_no, name, hits)
    diff["highlight"] = highlight_detail
    _write_json(diff_path, diff)

    version = TrackedFileVersion(
        version_id=str(uuid.uuid4()),
        tracked_file_id=tracked.tracked_file_id,
        version_no=version_no,
        snapshot_time=event_time,
        event_type=actual_event,
        path_at_that_time=path,
        name_at_that_time=name,
        stored_file_path=str(snapshot_path) if snapshot_path else None,
        content_hash=file_row.file_hash,
        prev_version_id=tracked.latest_version_id,
        change_summary="首次敏感文件入库" if actual_event == "initial" else diff["summary"],
        change_detail_json=diff,
        highlight_artifact_path=highlight_path,
        diff_artifact_path=str(diff_path),
        sensitive_hits=hits,
        artifact_type=artifact_type,
        is_snapshot_retained=bool(snapshot_path),
    )
    session.add(version)
    tracked.current_path = path
    tracked.current_name = name
    tracked.file_type = file_row.file_type or tracked.file_type
    tracked.sensitive_level = file_row.risk_level or tracked.sensitive_level
    tracked.is_deleted = False
    tracked.deleted_at = None
    tracked.last_seen_at = event_time
    tracked.latest_version_no = version_no
    tracked.latest_version_id = version.version_id
    if actual_event == "modified":
        tracked.modify_count = int(tracked.modify_count or 0) + 1
    event = TrackedFileEvent(
        event_id=f"version:{version.version_id}",
        tracked_file_id=tracked.tracked_file_id,
        event_time=event_time,
        event_type=actual_event,
        old_path=prev.path_at_that_time if prev else None,
        new_path=path,
        old_name=prev.name_at_that_time if prev else None,
        new_name=name,
        description=version.change_summary,
        raw_event_json={"file_hash": file_row.file_hash},
        version_id=version.version_id,
    )
    session.add(event)
    session.flush()
    _prune_old_snapshots(session, tracked)
    _sync_metadata(session, tracked)
    _write_json(dirs["events"] / f"{event.event_id.replace(':', '_')}.json", _serialize_event(event))
    return _serialize_tracked_file(tracked, actual_event)


def ingest_tracked_event(item: dict) -> Optional[dict]:
    event_type = str(item.get("event_type") or "").lower()
    if event_type in {"file_renamed", "renamed", "rename", "file_moved"}:
        return record_rename_event(item)
    if event_type in {"file_deleted", "deleted", "delete"}:
        return record_delete_event(item)
    if event_type in {"file_modified", "file_overwritten", "modified", "file_changed"}:
        file_hash = item.get("new_hash") or item.get("old_hash")
        if file_hash:
            return archive_sensitive_file(
                str(file_hash),
                agent_id=item.get("agent_id"),
                file_path=item.get("new_path") or item.get("file_path") or item.get("old_path"),
                event_type="modified",
                event_time=float(item.get("timestamp") or _now()),
            )
    return None


def record_rename_event(item: dict) -> Optional[dict]:
    with db_session() as session:
        agent_id = item.get("agent_id")
        old_path = item.get("old_path") or item.get("file_path")
        new_path = item.get("new_path") or item.get("file_path")
        tracked = _find_tracked(session, agent_id, path=old_path, content_hash=item.get("old_hash") or item.get("new_hash"))
        if not tracked or not new_path:
            return None
        event_time = float(item.get("timestamp") or _now())
        old_name = remote_path_name(old_path or tracked.current_path, tracked.current_name or "file")
        new_name = remote_path_name(new_path, tracked.current_name or "file")
        prev = session.get(TrackedFileVersion, tracked.latest_version_id) if tracked.latest_version_id else None
        version_no = int(tracked.latest_version_no or 0) + 1
        detail = {
            "summary": f"文件已重命名：{old_name} -> {new_name}",
            "added_texts": [],
            "removed_texts": [],
            "modified_blocks": [],
            "rename": {"old_name": old_name, "new_name": new_name, "old_path": old_path, "new_path": new_path},
            "deleted": None,
        }
        dirs = _ensure_dirs(agent_id, tracked.tracked_file_id)
        diff_path = dirs["diffs"] / f"v{version_no}_rename.json"
        _write_json(diff_path, detail)
        version = TrackedFileVersion(
            version_id=str(uuid.uuid4()),
            tracked_file_id=tracked.tracked_file_id,
            version_no=version_no,
            snapshot_time=event_time,
            event_type="renamed",
            path_at_that_time=new_path,
            name_at_that_time=new_name,
            stored_file_path=prev.stored_file_path if prev else None,
            content_hash=prev.content_hash if prev else (item.get("new_hash") or item.get("old_hash")),
            prev_version_id=tracked.latest_version_id,
            change_summary=detail["summary"],
            change_detail_json=detail,
            diff_artifact_path=str(diff_path),
            sensitive_hits=prev.sensitive_hits if prev else [],
            is_snapshot_retained=bool(prev and prev.stored_file_path and Path(prev.stored_file_path).exists()),
            artifact_type=prev.artifact_type if prev else None,
            highlight_artifact_path=prev.highlight_artifact_path if prev else None,
        )
        event = TrackedFileEvent(
            event_id=item.get("event_id") or str(uuid.uuid4()),
            tracked_file_id=tracked.tracked_file_id,
            event_time=event_time,
            event_type="renamed",
            old_path=old_path,
            new_path=new_path,
            old_name=old_name,
            new_name=new_name,
            description=detail["summary"],
            raw_event_json=item,
            version_id=version.version_id,
        )
        session.add(version)
        session.add(event)
        tracked.current_path = new_path
        tracked.current_name = new_name
        tracked.last_seen_at = event_time
        tracked.latest_version_no = version_no
        tracked.latest_version_id = version.version_id
        tracked.rename_count = int(tracked.rename_count or 0) + 1
        session.flush()
        _sync_metadata(session, tracked)
        _write_json(dirs["events"] / f"{event.event_id}.json", _serialize_event(event))
        return _serialize_tracked_file(tracked, "renamed")


def record_delete_event(item: dict) -> Optional[dict]:
    with db_session() as session:
        agent_id = item.get("agent_id")
        path = item.get("file_path") or item.get("old_path") or item.get("new_path")
        tracked = _find_tracked(session, agent_id, path=path, content_hash=item.get("old_hash") or item.get("new_hash"))
        if not tracked:
            return None
        event_time = float(item.get("timestamp") or _now())
        prev = session.get(TrackedFileVersion, tracked.latest_version_id) if tracked.latest_version_id else None
        version_no = int(tracked.latest_version_no or 0) + 1
        deleted = {"is_deleted": True, "deleted_at": event_time}
        detail = _diff_texts(None, None, deleted=deleted)
        dirs = _ensure_dirs(agent_id, tracked.tracked_file_id)
        diff_path = dirs["diffs"] / f"v{version_no}_deleted.json"
        _write_json(diff_path, detail)
        version = TrackedFileVersion(
            version_id=str(uuid.uuid4()),
            tracked_file_id=tracked.tracked_file_id,
            version_no=version_no,
            snapshot_time=event_time,
            event_type="deleted",
            path_at_that_time=tracked.current_path,
            name_at_that_time=tracked.current_name,
            stored_file_path=prev.stored_file_path if prev else None,
            content_hash=prev.content_hash if prev else (item.get("old_hash") or item.get("new_hash")),
            prev_version_id=tracked.latest_version_id,
            change_summary=detail["summary"],
            change_detail_json=detail,
            diff_artifact_path=str(diff_path),
            sensitive_hits=prev.sensitive_hits if prev else [],
            is_snapshot_retained=bool(prev and prev.stored_file_path and Path(prev.stored_file_path).exists()),
            artifact_type=prev.artifact_type if prev else None,
            highlight_artifact_path=prev.highlight_artifact_path if prev else None,
        )
        event = TrackedFileEvent(
            event_id=item.get("event_id") or str(uuid.uuid4()),
            tracked_file_id=tracked.tracked_file_id,
            event_time=event_time,
            event_type="deleted",
            old_path=tracked.current_path,
            new_path=None,
            old_name=tracked.current_name,
            new_name=None,
            description=detail["summary"],
            raw_event_json=item,
            version_id=version.version_id,
        )
        session.add(version)
        session.add(event)
        tracked.is_deleted = True
        tracked.deleted_at = event_time
        tracked.last_seen_at = event_time
        tracked.latest_version_no = version_no
        tracked.latest_version_id = version.version_id
        session.flush()
        _sync_metadata(session, tracked)
        _write_json(dirs["events"] / f"{event.event_id}.json", _serialize_event(event))
        return _serialize_tracked_file(tracked, "deleted")


def list_sensitive_files(agent_id: Optional[str] = None, changed_only: bool = False, is_deleted: Optional[bool] = None, keyword: Optional[str] = None, file_type: Optional[str] = None, page: int = 1, page_size: int = 50) -> dict:
    backfill_sensitive_archives(agent_id=agent_id)
    page = max(1, int(page or 1))
    page_size = min(200, max(1, int(page_size or 50)))
    with db_session() as session:
        query = session.query(TrackedFile)
        if agent_id:
            query = query.filter(TrackedFile.agent_id == agent_id)
        if is_deleted is not None:
            query = query.filter(TrackedFile.is_deleted.is_(bool(is_deleted)))
        if changed_only:
            query = query.filter((TrackedFile.modify_count > 0) | (TrackedFile.rename_count > 0) | (TrackedFile.is_deleted.is_(True)))
        if file_type:
            query = query.filter(TrackedFile.file_type == file_type)
        rows = query.order_by(TrackedFile.last_seen_at.desc()).all()
        if keyword:
            needle = str(keyword).lower()
            rows = [row for row in rows if needle in (row.current_name or "").lower() or needle in (row.current_path or "").lower()]
        total = len(rows)
        rows = rows[(page - 1) * page_size : page * page_size]
        latest_events = {
            event.tracked_file_id: event.event_type
            for event in session.query(TrackedFileEvent).filter(TrackedFileEvent.tracked_file_id.in_([row.tracked_file_id for row in rows] or [""])).order_by(TrackedFileEvent.event_time.desc()).all()
            if event.tracked_file_id
        }
        return {
            "items": [_serialize_tracked_file(row, latest_events.get(row.tracked_file_id, "")) for row in rows],
            "page": page,
            "page_size": page_size,
            "total": total,
        }


def backfill_sensitive_archives(agent_id: Optional[str] = None, limit: int = 50) -> int:
    created = 0
    with db_session() as session:
        query = (
            session.query(FileVersion)
            .join(FileRecord, FileRecord.file_hash == FileVersion.file_hash)
            .filter(FileRecord.is_sensitive.is_(True))
            .order_by(FileVersion.created_at.asc())
        )
        if agent_id:
            query = query.filter(FileVersion.agent_id == agent_id)
        rows = query.limit(limit).all()
        for row in rows:
            if _find_tracked(session, row.agent_id, path=row.file_path):
                continue
            file_row = session.get(FileRecord, row.file_hash)
            parse_row = session.get(ParseResult, row.file_hash)
            if not file_row:
                continue
            _archive_sensitive_row(session, file_row, parse_row, row.agent_id, row.file_path, "initial", row.created_at)
            created += 1
    return created


def get_sensitive_file_history(tracked_file_id: str) -> dict:
    with db_session() as session:
        tracked = session.get(TrackedFile, tracked_file_id)
        if not tracked:
            raise ValueError("tracked file not found")
        versions = session.query(TrackedFileVersion).filter(TrackedFileVersion.tracked_file_id == tracked_file_id).order_by(TrackedFileVersion.snapshot_time.asc(), TrackedFileVersion.version_no.asc()).all()
        events = session.query(TrackedFileEvent).filter(TrackedFileEvent.tracked_file_id == tracked_file_id).order_by(TrackedFileEvent.event_time.asc()).all()
        latest_event = events[-1].event_type if events else ""
        return {
            "file": _serialize_tracked_file(tracked, latest_event),
            "current_state": "deleted" if tracked.is_deleted else "active",
            "versions": [_serialize_version(row, tracked_file_id) for row in versions],
            "events": [_serialize_event(row) for row in events],
        }


def get_sensitive_version_detail(tracked_file_id: str, version_id: str) -> dict:
    with db_session() as session:
        tracked = session.get(TrackedFile, tracked_file_id)
        version = session.get(TrackedFileVersion, version_id)
        if not tracked or not version or version.tracked_file_id != tracked_file_id:
            raise ValueError("version not found")
        payload = _serialize_version(version, tracked_file_id)
        payload.update(
            {
                "file": _serialize_tracked_file(tracked),
                "change_summary": version.change_summary,
                "change_detail_json": version.change_detail_json or {},
                "sensitive_hits": version.sensitive_hits or [],
            }
        )
        return payload


def get_version_artifact_path(tracked_file_id: str, version_id: str, artifact: str) -> Path:
    with db_session() as session:
        version = session.get(TrackedFileVersion, version_id)
        if not version or version.tracked_file_id != tracked_file_id:
            raise ValueError("version not found")
        if artifact == "source":
            if not version.stored_file_path or not version.is_snapshot_retained:
                raise FileNotFoundError("snapshot file has been cleaned")
            path = Path(version.stored_file_path)
        elif artifact == "highlight":
            if not version.highlight_artifact_path:
                raise FileNotFoundError("highlight artifact not found")
            path = Path(version.highlight_artifact_path)
        elif artifact == "diff":
            if not version.diff_artifact_path:
                raise FileNotFoundError("diff artifact not found")
            path = Path(version.diff_artifact_path)
        else:
            raise ValueError("unsupported artifact")
        root = TRACK_ROOT.resolve()
        resolved = path.resolve()
        if root not in resolved.parents:
            raise ValueError("artifact path outside guard_state")
        if not resolved.exists():
            raise FileNotFoundError("artifact file not found")
        return resolved
