import re
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from models import DetectionRule
from storage import db_session


DEFAULT_KEYWORDS = [
    "绝密",
    "机密",
    "秘密",
    "内部",
    "限制分发",
    "工资表",
    "财务",
    "报表",
    "账户",
    "账号",
    "名单",
    "投标",
    "报价",
    "地址",
    "员工名单",
    "客户名单",
    "项目代号",
    "行动代号",
    "密码",
    "口令",
    "token",
    "api_key",
    "private key",
    "help me",
]

DEFAULT_REGEX_PATTERNS = [
    r"\b[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b",
    r"\b[1-9]\d{7}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}\b",
    r"\b1[3-9]\d{9}\b",
    r"\b\d{3,4}-\d{7,8}\b",
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    r"\b\d{16,19}\b",
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
    r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b",
]

DEFAULT_SUSPICIOUS_HINTS = [
    "账号",
    "账户",
    "证件",
    "工资",
    "薪资",
    "银行卡",
    "身份证",
    "邮箱",
    "登录",
    "客户",
    "花名册",
    "项目",
    "拓扑",
    "内网",
    "代号",
    "预算",
    "招标",
    "投标",
    "报价",
    "token",
    "secret",
    "apikey",
    "private key",
    "internal",
    "project",
    "budget",
    "customer",
    "quote",
    "bid",
    "pricing",
    "topology",
    "confidential",
]

RULE_TYPES = {"keyword", "ocr", "llm"}
MATCH_MODES = {"contains", "exact", "regex"}


def _now() -> float:
    return time.time()


def _serialize_rule(row: DetectionRule) -> Dict[str, Any]:
    return {
        "rule_id": row.rule_id,
        "rule_name": row.rule_name,
        "rule_type": row.rule_type,
        "enabled": bool(row.enabled),
        "description": row.description or "",
        "priority": int(row.priority or 100),
        "created_at": row.created_at,
        "updated_at": row.updated_at,
        "config": row.config or {},
    }


def _clean_string_list(value: Any, field_name: str) -> List[str]:
    if not isinstance(value, list):
        raise ValueError(f"{field_name} must be a string array")
    items = []
    for item in value:
        text = str(item or "").strip()
        if text:
            items.append(text)
    if not items:
        raise ValueError(f"{field_name} cannot be empty")
    return items


def validate_rule_payload(payload: Dict[str, Any], partial: bool = False) -> Dict[str, Any]:
    data = dict(payload or {})
    if not partial or "rule_name" in data:
        name = str(data.get("rule_name") or "").strip()
        if not name:
            raise ValueError("rule_name cannot be empty")
        data["rule_name"] = name
    if not partial or "rule_type" in data:
        rule_type = str(data.get("rule_type") or "").strip().lower()
        if rule_type not in RULE_TYPES:
            raise ValueError("rule_type must be one of keyword, ocr, llm")
        data["rule_type"] = rule_type
    if "priority" in data and data.get("priority") is not None:
        try:
            data["priority"] = int(data["priority"])
        except Exception:
            raise ValueError("priority must be an integer")
    if "config" in data and data.get("config") is not None:
        config = dict(data.get("config") or {})
        rule_type = str(data.get("rule_type") or "").strip().lower()
        if not rule_type and partial:
            rule_type = ""
        if rule_type == "keyword":
            keywords = [str(item or "").strip() for item in config.get("keywords") or [] if str(item or "").strip()]
            regex_patterns = [str(item or "").strip() for item in config.get("regex_patterns") or [] if str(item or "").strip()]
            if not keywords and not regex_patterns:
                raise ValueError("config.keywords or config.regex_patterns cannot both be empty")
            config["keywords"] = keywords
            config["regex_patterns"] = regex_patterns
            match_mode = str(config.get("match_mode") or "contains").strip().lower()
            if match_mode not in MATCH_MODES:
                raise ValueError("config.match_mode must be one of contains, exact, regex")
            config["match_mode"] = match_mode
        elif rule_type == "ocr":
            config["keywords"] = _clean_string_list(config.get("keywords"), "config.keywords")
            apply_file_types = config.get("apply_file_types") or ["png", "jpg", "jpeg", "pdf"]
            config["apply_file_types"] = [str(item).strip().lower().lstrip(".") for item in apply_file_types if str(item or "").strip()]
            if not config["apply_file_types"]:
                raise ValueError("config.apply_file_types cannot be empty")
            config["case_sensitive"] = bool(config.get("case_sensitive", False))
        elif rule_type == "llm":
            prompt = str(config.get("prompt_template") or "").strip()
            if not prompt:
                raise ValueError("config.prompt_template cannot be empty")
            config["prompt_template"] = prompt
            config["label_if_matched"] = str(config.get("label_if_matched") or "sensitive").strip() or "sensitive"
            try:
                threshold = float(config.get("threshold", 0.8))
            except Exception:
                raise ValueError("config.threshold must be a number")
            config["threshold"] = max(0.0, min(1.0, threshold))
        data["config"] = config
    return data


def ensure_default_detection_rules() -> None:
    with db_session() as session:
        if session.query(DetectionRule).count() > 0:
            return
        now = _now()
        session.add_all(
            [
                DetectionRule(
                    rule_id="builtin_keyword_defaults",
                    rule_name="内置关键字与正则规则",
                    rule_type="keyword",
                    enabled=True,
                    description="兼容旧版文本规则：内置关键字和常用正则。",
                    priority=10,
                    config={"keywords": DEFAULT_KEYWORDS, "match_mode": "contains", "regex_patterns": DEFAULT_REGEX_PATTERNS},
                    created_at=now,
                    updated_at=now,
                ),
                DetectionRule(
                    rule_id="builtin_ocr_defaults",
                    rule_name="内置 OCR 关键字规则",
                    rule_type="ocr",
                    enabled=True,
                    description="用于图片、PDF 扫描页和嵌入图片 OCR 文本的关键字规则。",
                    priority=20,
                    config={"keywords": DEFAULT_KEYWORDS, "apply_file_types": ["png", "jpg", "jpeg", "bmp", "pdf", "docx", "xlsx", "pptx"], "case_sensitive": False},
                    created_at=now,
                    updated_at=now,
                ),
                DetectionRule(
                    rule_id="builtin_llm_defaults",
                    rule_name="内置 LLM 语义复判规则",
                    rule_type="llm",
                    enabled=True,
                    description="保留 LLM prompt、标签和阈值配置，供语义复判流程读取。",
                    priority=30,
                    config={
                        "prompt_template": "请判断该文件是否包含敏感信息，并说明原因。",
                        "label_if_matched": "sensitive",
                        "threshold": 0.8,
                    },
                    created_at=now,
                    updated_at=now,
                ),
            ]
        )


def list_detection_rules(rule_type: Optional[str] = None, enabled: Optional[bool] = None, keyword: Optional[str] = None) -> List[Dict[str, Any]]:
    ensure_default_detection_rules()
    with db_session() as session:
        query = session.query(DetectionRule)
        if rule_type:
            query = query.filter(DetectionRule.rule_type == str(rule_type).strip().lower())
        if enabled is not None:
            query = query.filter(DetectionRule.enabled.is_(bool(enabled)))
        rows = query.order_by(DetectionRule.priority.asc(), DetectionRule.updated_at.desc()).all()
        if keyword:
            needle = str(keyword).strip().lower()
            rows = [row for row in rows if needle in (row.rule_name or "").lower()]
        return [_serialize_rule(row) for row in rows]


def get_detection_rule(rule_id: str) -> Dict[str, Any]:
    ensure_default_detection_rules()
    with db_session() as session:
        row = session.get(DetectionRule, rule_id)
        if not row:
            raise ValueError("rule not found")
        return _serialize_rule(row)


def create_detection_rule(payload: Dict[str, Any]) -> Dict[str, Any]:
    data = validate_rule_payload(payload, partial=False)
    now = _now()
    with db_session() as session:
        row = DetectionRule(
            rule_id=str(uuid.uuid4()),
            rule_name=data["rule_name"],
            rule_type=data["rule_type"],
            enabled=bool(data.get("enabled", True)),
            description=data.get("description") or "",
            priority=int(data.get("priority", 100)),
            config=data.get("config") or {},
            created_at=now,
            updated_at=now,
        )
        session.add(row)
        session.flush()
        return _serialize_rule(row)


def update_detection_rule(rule_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    allowed = {"rule_name", "rule_type", "enabled", "description", "priority", "config"}
    unknown = set(payload.keys()) - allowed
    if unknown:
        raise ValueError(f"unsupported fields: {', '.join(sorted(unknown))}")
    with db_session() as session:
        row = session.get(DetectionRule, rule_id)
        if not row:
            raise LookupError("rule not found")
        merged = _serialize_rule(row)
        merged.update({key: value for key, value in payload.items() if value is not None})
        data = validate_rule_payload(merged, partial=False)
        row.rule_name = data["rule_name"]
        row.rule_type = data["rule_type"]
        row.enabled = bool(data.get("enabled", True))
        row.description = data.get("description") or ""
        row.priority = int(data.get("priority", 100))
        row.config = data.get("config") or {}
        row.updated_at = _now()
        session.add(row)
        session.flush()
        return _serialize_rule(row)


def delete_detection_rule(rule_id: str) -> Dict[str, Any]:
    with db_session() as session:
        row = session.get(DetectionRule, rule_id)
        if not row:
            raise LookupError("rule not found")
        session.delete(row)
    return {"status": "deleted", "rule_id": rule_id}


def get_enabled_rules(rule_type: Optional[str] = None) -> List[Dict[str, Any]]:
    return list_detection_rules(rule_type=rule_type, enabled=True)


def _file_type_matches(rule: Dict[str, Any], file_extension: str) -> bool:
    config = rule.get("config") or {}
    allowed = [str(item).lower().lstrip(".") for item in config.get("apply_file_types") or []]
    if not allowed:
        return True
    current = str(file_extension or "").lower().lstrip(".")
    return current in allowed


def load_rules_from_file(file_path: Optional[str]) -> List[str]:
    if not file_path:
        return []
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"rule file not found: {path}")

    last_error: Optional[Exception] = None
    for encoding in ["utf-8-sig", "utf-8", "gbk"]:
        try:
            items = []
            with open(path, "r", encoding=encoding) as handle:
                for line in handle:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    items.append(line)
            return items
        except Exception as exc:
            last_error = exc
    raise RuntimeError(f"failed to load rule file: {path}, error={last_error}")


def merge_unique_rules(default_rules: Sequence[str], extra_rules: Sequence[str]) -> List[str]:
    merged = list(default_rules)
    for rule in extra_rules:
        if rule not in merged:
            merged.append(rule)
    return merged


def find_matches_in_content(content: str, keywords: Sequence[str], regex_patterns: Sequence[str]) -> List[Tuple[str, str, int, int]]:
    matches: List[Tuple[str, str, int, int]] = []
    if not isinstance(content, str):
        return matches

    lowered = content.lower()
    for keyword in keywords:
        start = 0
        needle = keyword.lower()
        while True:
            idx = lowered.find(needle, start)
            if idx == -1:
                break
            matches.append(("keyword", content[idx : idx + len(keyword)], idx, idx + len(keyword)))
            start = idx + len(keyword)

    for pattern in regex_patterns:
        for match in re.finditer(pattern, content):
            matches.append(("regex", match.group(0), match.start(), match.end()))

    return matches


def build_rule_findings(
    content: str,
    location: str,
    keywords: Sequence[str],
    regex_patterns: Sequence[str],
    source: str,
) -> List[Dict]:
    findings = []
    for match_type, matched_text, start, end in find_matches_in_content(content, keywords, regex_patterns):
        findings.append(
            {
                "rule_id": f"{match_type.upper()}_{hash((matched_text, location)) & 0xfffffff:x}",
                "rule_name": matched_text,
                "source": match_type if source == "text" else f"{source}_{match_type}",
                "matched_text": matched_text,
                "location": location,
                "confidence": 0.92 if match_type == "regex" else 0.78,
                "char_range": [start, end],
            }
        )
    return findings


def build_managed_rule_findings(
    content: str,
    location: str,
    rules: Sequence[Dict[str, Any]],
    source: str,
) -> List[Dict]:
    findings = []
    if not isinstance(content, str):
        return findings
    for rule in rules:
        config = rule.get("config") or {}
        rule_type = str(rule.get("rule_type") or "")
        match_mode = str(config.get("match_mode") or "contains").lower()
        keywords = [str(item) for item in config.get("keywords") or [] if str(item or "").strip()]
        regex_patterns = [str(item) for item in config.get("regex_patterns") or [] if str(item or "").strip()]
        if rule_type == "ocr" and not bool(config.get("case_sensitive", False)):
            lowered = content.lower()
        else:
            lowered = content
        for keyword in keywords:
            if match_mode == "regex":
                for match in re.finditer(keyword, content, flags=0 if config.get("case_sensitive", False) else re.IGNORECASE):
                    findings.append(_managed_finding(rule, source, "regex", match.group(0), location, match.start(), match.end()))
                continue
            haystack = lowered if rule_type == "ocr" and not config.get("case_sensitive", False) else content
            needle = keyword if haystack is content else keyword.lower()
            if match_mode == "exact":
                if haystack == needle:
                    findings.append(_managed_finding(rule, source, "exact", content, location, 0, len(content)))
                continue
            start = 0
            while True:
                idx = haystack.find(needle, start)
                if idx == -1:
                    break
                findings.append(_managed_finding(rule, source, "keyword", content[idx : idx + len(keyword)], location, idx, idx + len(keyword)))
                start = idx + max(1, len(keyword))
        for pattern in regex_patterns:
            for match in re.finditer(pattern, content):
                findings.append(_managed_finding(rule, source, "regex", match.group(0), location, match.start(), match.end()))
    return findings


def _managed_finding(rule: Dict[str, Any], source: str, match_type: str, matched_text: str, location: str, start: int, end: int) -> Dict:
    return {
        "rule_id": rule.get("rule_id"),
        "rule_name": rule.get("rule_name"),
        "rule_type": rule.get("rule_type"),
        "source": match_type if source == "text" else f"{source}_{match_type}",
        "matched_text": matched_text,
        "location": location,
        "confidence": 0.92 if match_type == "regex" else 0.78,
        "char_range": [start, end],
    }


def detect_suspicious_blocks(blocks: Sequence[Dict], hints: Optional[Sequence[str]] = None) -> List[Dict]:
    hints = [str(item).lower() for item in (hints or DEFAULT_SUSPICIOUS_HINTS)]
    out = []
    for block in blocks:
        text = str(block.get("text") or "").lower()
        if any(hint in text for hint in hints):
            out.append(block)
    return out[:50]
