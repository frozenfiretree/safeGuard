from pathlib import PurePosixPath, PureWindowsPath


def remote_path_name(value: object, default: str = "") -> str:
    text = str(value or "").strip()
    if not text:
        return default
    normalized = text.replace("\\", "/").rstrip("/")
    if not normalized:
        return default
    return PurePosixPath(normalized).name or PureWindowsPath(text).name or default
