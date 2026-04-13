import logging
from typing import Dict, List

import httpx

from config_app import OCR_SERVICE_TIMEOUT_SECONDS, OCR_SERVICE_URL


logger = logging.getLogger(__name__)


class OCRUnavailableError(RuntimeError):
    pass


def extract_text_from_image_bytes(img_bytes: bytes, location: str) -> List[Dict]:
    try:
        with httpx.Client(timeout=OCR_SERVICE_TIMEOUT_SECONDS) as client:
            response = client.post(
                f"{OCR_SERVICE_URL}/ocr/image",
                files={"file": ("image.png", img_bytes, "application/octet-stream")},
                data={"location": location},
            )
        response.raise_for_status()
        payload = response.json()
    except Exception as e:
        logger.warning("ocr service request failed: location=%s, error=%s", location, e)
        raise OCRUnavailableError(str(e)) from e

    rows = payload.get("items") or []
    if not isinstance(rows, list):
        return []
    return [
        {
            "text": str(item.get("text") or "").strip(),
            "bbox": item.get("bbox"),
            "location": item.get("location") or location,
        }
        for item in rows
        if str(item.get("text") or "").strip()
    ]
