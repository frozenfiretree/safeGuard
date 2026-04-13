import hashlib
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from llm_module import LLMConfig, LLMDetector
from path_utils import remote_path_name

from .ocr import OCRUnavailableError, extract_text_from_image_bytes
from .parsers import SUPPORTED_EXTENSIONS, extract_file_content
from .rules import (
    build_managed_rule_findings,
    build_rule_findings,
    detect_suspicious_blocks,
    get_enabled_rules,
    load_rules_from_file,
    merge_unique_rules,
)


LLM_DETECTOR = LLMDetector(LLMConfig.from_env())


def sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def collect_ocr_findings(image_blocks: Sequence[Dict], rules: Sequence[Dict], file_extension: str = "") -> Dict:
    ocr_findings: List[Dict] = []
    ocr_blocks: List[Dict] = []
    ocr_error: Optional[str] = None
    for image in image_blocks:
        try:
            rows = extract_text_from_image_bytes(image["bytes"], image["location"])
        except OCRUnavailableError as exc:
            ocr_error = str(exc)
            break

        for row_idx, row in enumerate(rows, start=1):
            location = f"{row['location']}:ocr:{row_idx}"
            text = row["text"]
            ocr_blocks.append(
                {
                    "text": text,
                    "location": location,
                    "source_type": image["source_type"],
                    "bbox": row.get("bbox"),
                }
            )
            for finding in build_managed_rule_findings(text, location, rules, "ocr"):
                finding["bbox"] = row.get("bbox")
                ocr_findings.append(finding)

    return {"ocr_findings": dedupe_findings(ocr_findings), "ocr_blocks": ocr_blocks, "ocr_error": ocr_error}


def collect_rule_findings(text_blocks: Sequence[Dict], rules: Sequence[Dict]) -> Dict:
    findings: List[Dict] = []
    for block in text_blocks:
        findings.extend(
            build_managed_rule_findings(
                content=block.get("text", ""),
                location=block.get("location", ""),
                rules=rules,
                source="text",
            )
        )
    return {"rule_findings": dedupe_findings(findings), "suspicious_blocks": detect_suspicious_blocks(text_blocks)}


def dedupe_findings(findings: Sequence[Dict]) -> List[Dict]:
    deduped = []
    seen = set()
    for item in findings:
        key = (
            item.get("source"),
            item.get("matched_text"),
            item.get("location"),
            item.get("category"),
            item.get("reason"),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def should_run_llm(
    file_meta: Dict,
    parse_result: Dict,
    rule_result: Dict,
    ocr_result: Dict,
) -> tuple[bool, str, List[Dict]]:
    combined_findings = (rule_result.get("rule_findings") or []) + (ocr_result.get("ocr_findings") or [])
    suspicious_blocks = detect_suspicious_blocks((parse_result.get("text_blocks") or []) + (ocr_result.get("ocr_blocks") or []))
    total_text_chars = sum(len(str(block.get("text") or "")) for block in suspicious_blocks)
    llm_rules = get_enabled_rules("llm")
    if not llm_rules:
        return False, "llm_rules_disabled", suspicious_blocks
    allowed, reason = LLM_DETECTOR.should_analyze(
        suspicious_blocks=suspicious_blocks,
        total_text_chars=total_text_chars,
        source_path=str(file_meta.get("path") or ""),
        existing_findings_count=len(combined_findings),
    )
    return allowed, reason, suspicious_blocks


def collect_llm_findings(file_meta: Dict, suspicious_blocks: Sequence[Dict]) -> Dict:
    result = LLM_DETECTOR.analyze(suspicious_blocks, str(file_meta.get("path") or ""))
    rules = get_enabled_rules("llm")
    if rules:
        threshold = min(float((rule.get("config") or {}).get("threshold", 0.8)) for rule in rules)
        result["llm_rules"] = [{"rule_id": rule.get("rule_id"), "rule_name": rule.get("rule_name"), "config": rule.get("config") or {}} for rule in rules]
        if float(result.get("llm_confidence") or 0.0) < threshold:
            result["llm_findings"] = []
            result["llm_has_sensitive"] = False
            result["llm_gate_threshold"] = threshold
    return result


def calculate_risk_level(
    rule_findings: Sequence[Dict],
    ocr_findings: Sequence[Dict],
    llm_findings: Sequence[Dict],
    needs_ocr: bool,
    ocr_error: Optional[str],
) -> str:
    all_findings = list(rule_findings) + list(ocr_findings) + list(llm_findings)
    if any(str(item.get("sensitivity", "")).upper() == "CRITICAL" for item in llm_findings):
        return "CRITICAL"
    if any(str(item.get("sensitivity", "")).upper() == "HIGH" for item in llm_findings):
        return "HIGH"
    matched_names = {str(x.get("matched_text", "")) for x in all_findings}
    if any(len(s) in {16, 17, 18, 19} and s.isdigit() for s in matched_names):
        return "HIGH"
    if len(all_findings) >= 3:
        return "HIGH"
    if all_findings:
        return "MEDIUM"
    if needs_ocr and ocr_error:
        return "REVIEW"
    if needs_ocr:
        return "REVIEW"
    return "LOW"


def build_final_decision(
    rule_findings: Sequence[Dict],
    ocr_findings: Sequence[Dict],
    llm_findings: Sequence[Dict],
    risk_level: str,
    llm_result: Dict,
) -> Dict:
    if rule_findings:
        return {"source": "rule", "is_sensitive": True, "confidence": 0.98, "reason": "rule_layer_hit"}
    if ocr_findings:
        return {"source": "ocr", "is_sensitive": True, "confidence": 0.92, "reason": "ocr_then_rule_hit"}
    if llm_findings:
        llm_confidence = float(llm_result.get("llm_confidence") or 0.7)
        return {"source": "llm", "is_sensitive": True, "confidence": llm_confidence, "reason": "llm_semantic_hit"}
    return {"source": "fusion", "is_sensitive": False, "confidence": 0.85 if risk_level == "LOW" else 0.6, "reason": "no_sensitive_findings"}


def build_detection_result(
    agent_id: str,
    scan_id: str,
    file_meta: Dict,
    parse_result: Dict,
    rule_result: Dict,
    ocr_result: Dict,
    llm_result: Dict,
    llm_gate_reason: str,
) -> Dict:
    rule_findings = rule_result.get("rule_findings", [])
    ocr_findings = ocr_result.get("ocr_findings", [])
    llm_findings = llm_result.get("llm_findings", [])
    needs_ocr = bool(parse_result.get("needs_ocr", False))
    ocr_error = ocr_result.get("ocr_error")
    risk_level = calculate_risk_level(rule_findings, ocr_findings, llm_findings, needs_ocr, ocr_error)
    final_decision = build_final_decision(rule_findings, ocr_findings, llm_findings, risk_level, llm_result)
    per_block_locations = []
    for block in parse_result.get("text_blocks", []):
        per_block_locations.append(
            {
                "location": block.get("location"),
                "source_type": block.get("source_type"),
                "preview": str(block.get("text") or "")[:240],
            }
        )
    for block in ocr_result.get("ocr_blocks", []):
        per_block_locations.append(
            {
                "location": block.get("location"),
                "source_type": block.get("source_type"),
                "preview": str(block.get("text") or "")[:240],
                "bbox": block.get("bbox"),
            }
        )

    if rule_findings or ocr_findings:
        explanation_summary = f"规则/OCR 共命中 {len(rule_findings) + len(ocr_findings)} 处，整体风险等级为 {risk_level}。"
    elif llm_findings:
        explanation_summary = llm_result.get("llm_summary") or f"LLM 语义复判发现 {len(llm_findings)} 处敏感内容，整体风险等级为 {risk_level}。"
    elif needs_ocr and ocr_error:
        explanation_summary = f"文件需要 OCR 复核，但 OCR 服务当前不可用：{ocr_error}"
    elif needs_ocr:
        explanation_summary = "文件包含扫描页或嵌入图片，已执行 OCR，但当前未命中规则，也未触发 LLM 敏感判定。"
    else:
        explanation_summary = "当前未命中文本规则、OCR 规则，也未触发或命中 LLM 语义敏感判定。"

    return {
        "agent_id": agent_id,
        "scan_id": scan_id,
        "file_path": file_meta.get("path"),
        "file_name": remote_path_name(file_meta.get("path")),
        "file_hash": file_meta.get("sha256"),
        "file_size": file_meta.get("size"),
        "file_extension": (file_meta.get("extension") or "").lower(),
        "parse_status": parse_result.get("parse_status"),
        "needs_ocr": needs_ocr,
        "ocr_available": ocr_error is None,
        "ocr_error": ocr_error,
        "risk_level": risk_level,
        "explanation_summary": explanation_summary,
        "rule_findings": rule_findings,
        "ocr_findings": ocr_findings,
        "llm_findings": llm_findings,
        "llm_summary": llm_result.get("llm_summary") or "",
        "llm_used": bool(llm_result.get("llm_used")),
        "llm_error": llm_result.get("llm_error") or "",
        "llm_gate_reason": llm_gate_reason,
        "suspicious_blocks": rule_result.get("suspicious_blocks", []),
        "final_decision": final_decision,
        "confidence": final_decision.get("confidence"),
        "final_confidence": final_decision.get("confidence"),
        "per_block_locations": per_block_locations,
        "parsed_block_count": len(parse_result.get("text_blocks", [])),
        "image_block_count": len(parse_result.get("image_blocks", [])),
        "generated_at": int(time.time()),
    }


def detect_file(
    path: Path,
    *,
    agent_id: str,
    scan_id: str,
    file_meta: Dict,
    keywords_file: Optional[str] = None,
    regex_file: Optional[str] = None,
) -> Dict:
    keyword_rules = get_enabled_rules("keyword")
    ocr_rules = [
        rule
        for rule in get_enabled_rules("ocr")
        if _ocr_rule_applies(rule, file_meta.get("extension") or Path(file_meta.get("path") or "").suffix)
    ]
    extra_keywords = load_rules_from_file(keywords_file)
    extra_regex = load_rules_from_file(regex_file)
    if extra_keywords or extra_regex:
        keyword_rules.append(
            {
                "rule_id": "legacy_external_keyword_file",
                "rule_name": "外部关键字/正则文件",
                "rule_type": "keyword",
                "config": {"keywords": extra_keywords, "match_mode": "contains", "regex_patterns": extra_regex},
            }
        )

    parse_result = extract_file_content(path)
    rule_result = collect_rule_findings(parse_result.get("text_blocks", []), keyword_rules)
    ocr_result = collect_ocr_findings(parse_result.get("image_blocks", []), ocr_rules, file_meta.get("extension") or "")

    llm_allowed, llm_gate_reason, suspicious_blocks = should_run_llm(file_meta, parse_result, rule_result, ocr_result)
    llm_result = {
        "llm_used": False,
        "llm_error": "",
        "llm_findings": [],
        "llm_summary": "",
        "llm_confidence": 0.0,
    }
    if llm_allowed:
        llm_result = collect_llm_findings(file_meta, suspicious_blocks)

    return build_detection_result(agent_id, scan_id, file_meta, parse_result, rule_result, ocr_result, llm_result, llm_gate_reason)


def _ocr_rule_applies(rule: Dict, file_extension: str) -> bool:
    allowed = [str(item).lower().lstrip(".") for item in (rule.get("config") or {}).get("apply_file_types") or []]
    if not allowed:
        return True
    return str(file_extension or "").lower().lstrip(".") in allowed


def write_detection_result(result_dir: Path, result: Dict) -> Path:
    result_dir.mkdir(parents=True, exist_ok=True)
    result_path = result_dir / f"{result['file_hash']}.json"
    with open(result_path, "w", encoding="utf-8") as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2)
    return result_path
