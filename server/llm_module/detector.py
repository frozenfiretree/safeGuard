from __future__ import annotations

import math
from typing import Dict, List, Sequence

from .api_client import LLMClient, LLMClientError
from .config import LLMConfig


PROMPT_SYSTEM = """You are a sensitive-information reviewer for internal enterprise documents.
Return strict JSON only.
Decide whether the provided text blocks contain sensitive information not already caught by rules.
Focus on semantic sensitivity such as internal plans, employee rosters, project code names, credentials, customer lists, pricing, bids, financial disclosures, private contact data, and confidential operational details.

JSON schema:
{
  "has_sensitive": boolean,
  "summary": string,
  "confidence": number,
  "findings": [
    {
      "category": string,
      "sensitivity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
      "reason": string,
      "location": string,
      "matched_text": string,
      "confidence": number
    }
  ]
}
"""


class LLMDetector:
    def __init__(self, config: LLMConfig | None = None):
        self.config = config or LLMConfig.from_env()
        self.client = LLMClient(self.config)

    def should_analyze(
        self,
        *,
        suspicious_blocks: Sequence[Dict],
        total_text_chars: int,
        source_path: str,
        existing_findings_count: int,
    ) -> tuple[bool, str]:
        if not self.config.enabled:
            return False, "llm_disabled"
        if existing_findings_count > 0:
            return False, "rule_or_ocr_already_hit"
        if not suspicious_blocks:
            return False, "no_suspicious_blocks"
        if total_text_chars < 200:
            return False, "content_too_small"

        lowered = (source_path or "").lower()
        suspicious_source = any(
            token in lowered
            for token in [
                "\\downloads\\",
                "\\desktop\\",
                "\\documents\\",
                "\\wechat files\\",
                "\\temp\\",
                "/downloads/",
                "/desktop/",
                "/documents/",
                "/tmp/",
            ]
        )
        if not suspicious_source:
            return False, "source_not_suspicious"
        if not self.config.available:
            return False, "llm_not_configured"
        return True, "ready"

    def analyze(self, suspicious_blocks: Sequence[Dict], source_path: str) -> Dict:
        selected = list(suspicious_blocks[: self.config.max_blocks_per_call])
        trimmed_blocks: List[Dict] = []
        used_chars = 0
        for block in selected:
            text = str(block.get("text") or "").strip()
            if not text:
                continue
            remaining = self.config.max_input_chars - used_chars
            if remaining <= 0:
                break
            clipped = text[:remaining]
            used_chars += len(clipped)
            trimmed_blocks.append({
                "location": block.get("location") or "unknown",
                "text": clipped,
                "source_type": block.get("source_type") or "text",
            })

        payload = {
            "source_path": source_path,
            "blocks": trimmed_blocks,
        }
        try:
            result = self.client.chat_json(
                [
                    {"role": "system", "content": PROMPT_SYSTEM},
                    {"role": "user", "content": _build_user_prompt(payload)},
                ]
            )
        except LLMClientError as exc:
            return {
                "llm_used": True,
                "llm_error": str(exc),
                "llm_findings": [],
                "llm_summary": "",
                "llm_confidence": 0.0,
            }

        findings = []
        for item in result.get("findings") or []:
            if not isinstance(item, dict):
                continue
            confidence = _clamp_confidence(item.get("confidence"))
            findings.append(
                {
                    "category": str(item.get("category") or "unknown"),
                    "sensitivity": str(item.get("sensitivity") or "MEDIUM").upper(),
                    "reason": str(item.get("reason") or ""),
                    "location": str(item.get("location") or "unknown"),
                    "matched_text": str(item.get("matched_text") or ""),
                    "confidence": confidence,
                    "source": "llm",
                    "rule_id": f"LLM_{str(item.get('category') or 'UNKNOWN').upper()}",
                }
            )

        return {
            "llm_used": True,
            "llm_error": "",
            "llm_findings": findings,
            "llm_summary": str(result.get("summary") or ""),
            "llm_confidence": _clamp_confidence(result.get("confidence")),
            "llm_has_sensitive": bool(result.get("has_sensitive") or findings),
        }


def _build_user_prompt(payload: Dict) -> str:
    lines = [f"Source path: {payload.get('source_path') or '-'}", "Review these suspicious text blocks:"]
    for idx, block in enumerate(payload.get("blocks") or [], start=1):
        lines.append(f"[{idx}] location={block.get('location')} source={block.get('source_type')}")
        lines.append(block.get("text") or "")
    return "\n".join(lines)


def _clamp_confidence(value) -> float:
    try:
        val = float(value)
    except Exception:
        return 0.5
    if math.isnan(val):
        return 0.5
    return max(0.0, min(1.0, val))
