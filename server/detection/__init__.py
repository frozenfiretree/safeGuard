from .ocr import OCRUnavailableError
from .pipeline import (
    SUPPORTED_EXTENSIONS,
    build_detection_result,
    detect_file,
    sha256_of_file,
)
from .rules import DEFAULT_KEYWORDS, DEFAULT_REGEX_PATTERNS

__all__ = [
    "DEFAULT_KEYWORDS",
    "DEFAULT_REGEX_PATTERNS",
    "OCRUnavailableError",
    "SUPPORTED_EXTENSIONS",
    "build_detection_result",
    "detect_file",
    "sha256_of_file",
]
