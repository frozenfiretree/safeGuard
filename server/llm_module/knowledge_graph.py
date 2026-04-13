"""
敏感信息知识图谱构建模块。

本模块负责将上游检测到的敏感信息（SensitiveFinding）构建为结构化的知识图谱，
揭示敏感信息之间的关联关系，评估整体风险等级，并为前端可视化提供数据支持。

支持两种构建模式：
1. 规则化构建（RULE_BASED）：基于共现、距离、类型推断关系——快速、无外部依赖
2. LLM 增强构建（LLM_ENHANCED）：调用 LLM 分析更深层语义关联——更智能但更慢

增强功能（v2）：
3. 解释性节点/边属性：为每条敏感发现生成通俗易懂的敏感原因、泄露风险、处理建议
4. 企业自定义分类集成：支持企业特有的敏感信息分类（项目代号、客户名单等）
5. 用户交互式自定义：用户可标记新敏感类型、确认/拒绝检测结果，操作可审计追踪
6. 风险放大规则：多类信息组合后风险等级自动升级

数据流位置：
  资产发现 → 文件发现+下载 → 内容提取 → 规则检测 → LLM语义检测 → **知识图谱构建** → 联合决策
"""

from __future__ import annotations

import logging
import re
import threading
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from itertools import combinations
from typing import Any

from .config import LLMConfig
from .api_client import BaseLLMClient, LLMResponse, LLMAPIError, create_llm_client
from .prompts import PromptManager
from .chunker import SensitiveFinding, ContentLocation

logger = logging.getLogger(__name__)

# ======================================================================
# 内置解释模板
# ======================================================================

_BUILTIN_EXPLANATIONS: dict[str, dict[str, str]] = {
    "个人身份信息 (PII)": {
        "why_sensitive": "身份证号、护照号等可直接定位到自然人身份，属于法律明确保护的个人信息。",
        "risk_if_leaked": "泄露后可能导致身份冒用、精准诈骗、非法开户等。当与联系方式、金融信息组合时风险倍增。",
        "recommended_action": "建议脱敏处理（仅保留前3后4位），或限制文档传播范围至最小必要人员。",
    },
    "联系方式": {
        "why_sensitive": "手机号、邮箱等可直接联系到个人，是社会工程攻击的入口信息。",
        "risk_if_leaked": "可被用于电信诈骗、垃圾营销、钓鱼攻击。与姓名组合时可精准定位目标。",
        "recommended_action": "建议对手机号中间4位进行脱敏，邮箱可保留域名部分。",
    },
    "金融信息": {
        "why_sensitive": "银行卡号、薪资数据、财务报表等涉及资金安全和商业利益。",
        "risk_if_leaked": "银行卡号泄露可能导致盗刷；薪资数据泄露违反劳动法规；财务数据泄露影响企业竞争力。",
        "recommended_action": "银行卡号仅保留后4位；薪资数据严格限制访问；财务报表标记密级。",
    },
    "企业核心机密": {
        "why_sensitive": "未公开的项目信息、技术方案、客户名单等是企业核心竞争力所在。",
        "risk_if_leaked": "竞争对手可提前获知产品布局、挖走客户、抢占技术先机，造成巨大商业损失。",
        "recommended_action": "文档标记'机密'或'内部'等级，限制传播范围，启用文档水印追踪。",
    },
    "密级与合规": {
        "why_sensitive": "明确标注密级的文档有法律和行政法规的保密义务。",
        "risk_if_leaked": "可能违反保密法、商业秘密保护法等，面临法律追责和经济赔偿。",
        "recommended_action": "按标注密级执行对应保密措施，不得降低密级处理。",
    },
    "账号凭证": {
        "why_sensitive": "密码、API密钥、数据库连接串等可直接用于非法访问系统。",
        "risk_if_leaked": "攻击者可直接利用凭证入侵系统、窃取数据、植入后门。",
        "recommended_action": "立即轮换泄露的凭证；使用密钥管理服务；禁止在文档中明文存储密码。",
    },
    "网络与基础设施": {
        "why_sensitive": "内网IP、网络拓扑、安全策略等是攻击者进行内网渗透的关键情报。",
        "risk_if_leaked": "攻击者可绘制网络地图、定位关键资产、绕过安全策略进行定向攻击。",
        "recommended_action": "从文档中移除内网地址信息；网络拓扑图标记为机密；安全策略严格管控。",
    },
}

# ======================================================================
# 风险放大规则
# ======================================================================

_RISK_AMPLIFICATION_RULES: list[dict] = [
    {
        "source_types": {"PII", "CONTACT"},
        "description": "个人身份+联系方式组合构成可精准定位的个人画像",
        "amplification": "CRITICAL",
    },
    {
        "source_types": {"PII", "FINANCIAL"},
        "description": "个人身份+金融信息组合可直接导致财产损失",
        "amplification": "CRITICAL",
    },
    {
        "source_types": {"CREDENTIAL", "INFRASTRUCTURE"},
        "description": "账号凭证+基础设施信息组合可直接入侵系统",
        "amplification": "CRITICAL",
    },
    {
        "source_types": {"ENTERPRISE_SECRET", "FINANCIAL"},
        "description": "项目机密+财务数据组合可推算企业真实商业价值",
        "amplification": "HIGH",
    },
    {
        "source_types": {"PII", "CREDENTIAL"},
        "description": "个人身份+账号凭证组合可实施精准账户接管",
        "amplification": "CRITICAL",
    },
    {
        "source_types": {"CONTACT", "CREDENTIAL"},
        "description": "联系方式+账号凭证组合构成完整登录信息",
        "amplification": "CRITICAL",
    },
    {
        "source_types": {"ENTERPRISE_SECRET", "INFRASTRUCTURE"},
        "description": "商业机密+基础设施信息组合可实现针对性攻击",
        "amplification": "CRITICAL",
    },
    {
        "source_types": {"PII", "CONTACT", "FINANCIAL"},
        "description": "个人身份+联系方式+金融信息构成完整个人画像，风险极高",
        "amplification": "CRITICAL",
    },
    {
        "source_types": {"COMPLIANCE", "ENTERPRISE_SECRET"},
        "description": "密级文档+企业机密组合涉及合规与商业双重风险",
        "amplification": "HIGH",
    },
]


# ======================================================================
# 数据结构定义
# ======================================================================


@dataclass
class GraphNode:
    """知识图谱节点——代表一条敏感发现。"""

    id: str
    """唯一 ID，格式如 "node_a1b2c3d4"。"""

    label: str
    """显示标签（脱敏后的摘要，如 "身份证***1234"）。"""

    entity_type: str
    """实体类型：PII / FINANCIAL / CREDENTIAL / ENTERPRISE_SECRET / COMPLIANCE / INFRASTRUCTURE / CONTACT / OTHER。"""

    sensitivity_level: str
    """敏感级别：LOW / MEDIUM / HIGH / CRITICAL。"""

    category: str
    """来自 SensitiveFinding.category 的细分类别。"""

    original_text: str
    """原文（管理员视角可见）。"""

    finding_id: str | None = None
    """关联的 SensitiveFinding.finding_id。"""

    metadata: dict = field(default_factory=dict)
    """扩展字段（location 摘要等）。"""

    # ── 新增：解释性字段 ──

    why_sensitive: str = ""
    """通俗易懂的敏感原因说明（面向业务人员）。
    例如："该身份证号可直接定位到个人身份，如泄露可能导致身份盗用或精准诈骗。"
    """

    risk_if_leaked: str = ""
    """泄露风险的具体场景描述。
    例如："攻击者可利用身份证号+手机号组合进行电信诈骗或开通账户。"
    """

    recommended_action: str = ""
    """建议的处理措施。
    例如："建议对身份证号进行脱敏处理（仅保留前3后4位），或限制文档传播范围。"
    """

    is_custom_defined: bool = False
    """是否为企业自定义的敏感分类。"""

    custom_category_name: str = ""
    """如果是企业自定义分类，记录分类名称。"""

    user_confirmed: bool | None = None
    """用户确认状态：True=确认敏感，False=标记为误报，None=未确认。"""

    user_note: str = ""
    """用户的备注说明。"""


@dataclass
class GraphEdge:
    """知识图谱边——代表两个敏感发现之间的关联关系。"""

    source: str
    """源节点 ID。"""

    target: str
    """目标节点 ID。"""

    relation: str
    """关系类型（如 "同一人信息链" / "共现于同一位置" / "构成登录凭证"）。"""

    description: str
    """关系的自然语言描述。"""

    weight: float
    """关联强度 0.0-1.0。"""

    inferred_by: str
    """推断来源："RULE" 或 "LLM"。"""

    # ── 新增：解释性字段 ──

    risk_amplification: str = ""
    """关联导致的风险放大说明。
    例如："身份证号与银行卡号同时出现，构成完整金融身份信息，泄露可直接导致财产损失。"
    """

    combined_risk_level: str = ""
    """组合后的风险等级（可能高于任一单独节点）。
    例如：身份证(HIGH) + 手机号(MEDIUM) → 组合后 CRITICAL
    """


@dataclass
class RiskAssessment:
    """整体风险评估。"""

    risk_score: float
    """风险评分 0.0-10.0。"""

    risk_level: str
    """风险等级：LOW / MEDIUM / HIGH / CRITICAL。"""

    explanation: str
    """风险解释。"""

    key_risk_factors: list[str] = field(default_factory=list)
    """主要风险因素列表。"""


@dataclass
class SensitiveKnowledgeGraph:
    """敏感信息知识图谱——最终输出的完整图谱对象。"""

    nodes: list[GraphNode] = field(default_factory=list)
    """图谱中的所有节点。"""

    edges: list[GraphEdge] = field(default_factory=list)
    """图谱中的所有边。"""

    risk_assessment: RiskAssessment = field(
        default_factory=lambda: RiskAssessment(
            risk_score=0.0, risk_level="LOW", explanation="无敏感信息发现。", key_risk_factors=[]
        )
    )
    """整体风险评估。"""

    clusters: list[dict] = field(default_factory=list)
    """聚类信息列表。"""

    build_mode: str = "RULE_BASED"
    """构建模式："RULE_BASED" 或 "LLM_ENHANCED"。"""

    metadata: dict = field(default_factory=dict)
    """构建元数据（耗时、节点/边数量等）。"""

    # ── 新增：用户交互与解释性字段 ──

    user_modifications: list[dict] = field(default_factory=list)
    """用户的修改记录列表，用于审计追踪。
    每条记录：{"action": "confirm/reject/add", "node_id": "...", "timestamp": "...", "note": "..."}
    """

    explanation_summary: str = ""
    """整体风险的通俗易懂总结（面向非技术人员）。"""

    def to_dict(self) -> dict:
        """转为可 JSON 序列化的 dict（递归展开所有 dataclass）。"""
        return {
            "nodes": [asdict(n) for n in self.nodes],
            "edges": [asdict(e) for e in self.edges],
            "risk_assessment": asdict(self.risk_assessment),
            "clusters": self.clusters,
            "build_mode": self.build_mode,
            "metadata": self.metadata,
            "user_modifications": self.user_modifications,
            "explanation_summary": self.explanation_summary,
        }

    def to_vis_data(self) -> dict:
        """增强版：包含解释性数据供前端展示。

        返回格式同时包含 vis.js 风格的 from/to 和 D3.js 风格的 source/target，
        前端可根据自身框架选取所需字段。

        Returns:
            包含 nodes、edges、risk、clusters、legend 五个顶层键的 dict。
        """
        # 节点大小映射
        size_map = {"CRITICAL": 30, "HIGH": 24, "MEDIUM": 18, "LOW": 12}
        # 节点颜色映射
        color_map = {
            "PII": "#e74c3c",
            "CONTACT": "#e67e22",
            "FINANCIAL": "#f1c40f",
            "CREDENTIAL": "#9b59b6",
            "ENTERPRISE_SECRET": "#1abc9c",
            "COMPLIANCE": "#3498db",
            "INFRASTRUCTURE": "#95a5a6",
            "OTHER": "#bdc3c7",
        }

        vis_nodes = []
        for node in self.nodes:
            vis_nodes.append({
                "id": node.id,
                "label": node.label,
                "group": node.entity_type,
                "level": node.sensitivity_level,
                "size": size_map.get(node.sensitivity_level, 16),
                "color": color_map.get(node.entity_type, "#bdc3c7"),
                "title": f"{node.category} ({node.sensitivity_level})",
                "category": node.category,
                "finding_id": node.finding_id,
                # 新增解释性字段
                "why_sensitive": node.why_sensitive,
                "risk_if_leaked": node.risk_if_leaked,
                "recommended_action": node.recommended_action,
                "is_custom_defined": node.is_custom_defined,
                "custom_category_name": node.custom_category_name,
                "user_confirmed": node.user_confirmed,
                "user_note": node.user_note,
            })

        vis_edges = []
        for edge in self.edges:
            width = max(1, int(edge.weight * 5))
            vis_edges.append({
                # vis.js 风格
                "from": edge.source,
                "to": edge.target,
                # D3.js 风格
                "source": edge.source,
                "target": edge.target,
                # 通用属性
                "label": edge.relation,
                "title": edge.description,
                "width": width,
                "weight": edge.weight,
                "arrows": "to",
                "dashes": edge.inferred_by == "LLM",
                "inferred_by": edge.inferred_by,
                # 新增解释性字段
                "risk_amplification": edge.risk_amplification,
                "combined_risk_level": edge.combined_risk_level,
            })

        # 新增图例数据
        legend = {
            "entity_type_colors": {
                etype: {"color": color, "label": etype}
                for etype, color in color_map.items()
            },
            "sensitivity_level_sizes": {
                level: {"size": size, "label": level}
                for level, size in size_map.items()
            },
            "edge_styles": {
                "solid": "规则推断（RULE）——基于共现、距离、类型等规则自动推断",
                "dashed": "LLM推断（LLM）——由大语言模型分析语义关联得出",
            },
        }

        return {
            "nodes": vis_nodes,
            "edges": vis_edges,
            "risk": {
                "score": self.risk_assessment.risk_score,
                "level": self.risk_assessment.risk_level,
                "explanation": self.risk_assessment.explanation,
            },
            "clusters": self.clusters,
            "explanation_summary": self.explanation_summary,
            "user_modifications": self.user_modifications,
            "legend": legend,
        }


# ======================================================================
# 辅助函数
# ======================================================================

# category → entity_type 映射表
_CATEGORY_TYPE_MAP: dict[str, str] = {
    "个人身份信息 (PII)": "PII",
    "联系方式": "CONTACT",
    "金融信息": "FINANCIAL",
    "企业核心机密": "ENTERPRISE_SECRET",
    "密级与合规": "COMPLIANCE",
    "账号凭证": "CREDENTIAL",
    "网络与基础设施": "INFRASTRUCTURE",
}

# sensitivity_level → 基础分
_LEVEL_SCORE_MAP: dict[str, float] = {
    "CRITICAL": 8.0,
    "HIGH": 6.0,
    "MEDIUM": 4.0,
    "LOW": 2.0,
}

# sensitivity_level 排序权重（用于比较）
_LEVEL_ORDER: dict[str, int] = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3,
}


def _normalize_finding(finding) -> SensitiveFinding:
    """将 dict 或 SensitiveFinding 统一转换为 SensitiveFinding 对象。

    兼容层：上游可能传入 SensitiveFinding 对象（正常流程）或 dict（如直接
    从 JSON 反序列化得到的结果）。本函数确保下游代码始终拿到 SensitiveFinding
    实例，避免 ``'dict' object has no attribute 'category'`` 之类的异常。

    Args:
        finding: SensitiveFinding 实例或等价的 dict。

    Returns:
        SensitiveFinding 对象。如果输入已经是 SensitiveFinding 则原样返回。

    Raises:
        TypeError: 输入既不是 SensitiveFinding 也不是 dict 时抛出。
    """
    if isinstance(finding, SensitiveFinding):
        return finding

    if isinstance(finding, dict):
        # 处理 location 字段：可能是 ContentLocation 对象、dict 或 None
        raw_location = finding.get("location")
        if isinstance(raw_location, ContentLocation):
            location = raw_location
        elif isinstance(raw_location, dict):
            location = ContentLocation(
                block_index=raw_location.get("block_index", 0),
                char_offset_start=raw_location.get("char_offset_start", 0),
                char_offset_end=raw_location.get("char_offset_end", 0),
                line_number=raw_location.get("line_number"),
                page_number=raw_location.get("page_number"),
                sheet_name=raw_location.get("sheet_name"),
                row_number=raw_location.get("row_number"),
                column_number=raw_location.get("column_number"),
                cell_address=raw_location.get("cell_address"),
                paragraph_index=raw_location.get("paragraph_index"),
                slide_number=raw_location.get("slide_number"),
                shape_name=raw_location.get("shape_name"),
                email_part=raw_location.get("email_part"),
                attachment_name=raw_location.get("attachment_name"),
                archive_inner_path=raw_location.get("archive_inner_path"),
            )
        else:
            location = ContentLocation(block_index=0, char_offset_start=0, char_offset_end=0)

        return SensitiveFinding(
            finding_id=finding.get("finding_id", ""),
            rule_id=finding.get("rule_id", ""),
            rule_name=finding.get("rule_name", ""),
            category=finding.get("category", ""),
            sensitivity_level=finding.get("sensitivity_level", "MEDIUM"),
            confidence=float(finding.get("confidence", 0.0)),
            source=finding.get("source", ""),
            matched_text=finding.get("matched_text", ""),
            context_before=finding.get("context_before", ""),
            context_after=finding.get("context_after", ""),
            location=location,
            description=finding.get("description", ""),
        )

    raise TypeError(
        f"_normalize_finding 期望 SensitiveFinding 或 dict，"
        f"实际收到 {type(finding).__name__}"
    )


def _normalize_findings(findings: list) -> list[SensitiveFinding]:
    """批量将 findings 列表中的元素规范化为 SensitiveFinding 对象。

    Args:
        findings: SensitiveFinding 实例或 dict 的混合列表。

    Returns:
        全部为 SensitiveFinding 实例的列表。
    """
    return [_normalize_finding(f) for f in findings]


def _category_to_entity_type(category: str) -> str:
    """将 SensitiveFinding.category 映射为 GraphNode.entity_type。

    Args:
        category: SensitiveFinding 中的 category 字段。

    Returns:
        对应的 entity_type 字符串，未匹配时返回 "OTHER"。
    """
    return _CATEGORY_TYPE_MAP.get(category, "OTHER")


def desensitize_text(text: str, category: str) -> str:
    """对敏感文本进行脱敏处理，用于节点 label 显示。

    脱敏策略：
    - 身份证号（18位）→ 前3位 + "***" + 后4位
    - 手机号（11位）→ 前3位 + "****" + 后4位
    - 银行卡号（16-19位纯数字）→ "卡号****" + 后4位
    - 邮箱 → 用户名首字母 + "***@" + 域名
    - 密码/密钥/token → "[已脱敏]"
    - 其他长文本 → 前15字符 + "..."

    Args:
        text: 原始敏感文本。
        category: 所属类别，用于选择脱敏策略。

    Returns:
        脱敏后的显示文本。
    """
    text = text.strip()
    if not text:
        return "[空]"

    entity_type = _category_to_entity_type(category)

    # 密码 / 密钥 / token 直接脱敏
    if entity_type == "CREDENTIAL":
        # 检查是否包含密码/密钥相关关键词
        lower = text.lower()
        if any(kw in lower for kw in ("password", "passwd", "密码", "secret", "token", "api_key", "apikey", "key=")):
            return "密码[已脱敏]"

    # 身份证号：18位数字（最后一位可能是X）
    id_match = re.search(r'\d{17}[\dXx]', text)
    if id_match and entity_type in ("PII", "OTHER"):
        id_num = id_match.group()
        return f"身份证{id_num[:3]}***{id_num[-4:]}"

    # 手机号：11位数字，1开头
    phone_match = re.search(r'1[3-9]\d{9}', text)
    if phone_match and entity_type in ("CONTACT", "PII", "OTHER"):
        phone = phone_match.group()
        return f"{phone[:3]}****{phone[-4:]}"

    # 银行卡号：16-19位纯数字
    card_match = re.search(r'\d{16,19}', text)
    if card_match and entity_type in ("FINANCIAL", "OTHER"):
        card = card_match.group()
        return f"卡号****{card[-4:]}"

    # 邮箱
    email_match = re.search(r'([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', text)
    if email_match:
        username = email_match.group(1)
        domain = email_match.group(2)
        return f"{username[0]}***@{domain}"

    # 其他：截取前15字符
    if len(text) > 15:
        return text[:15] + "..."

    return text


def _finding_to_node(finding: SensitiveFinding) -> GraphNode:
    """将 SensitiveFinding 转换为 GraphNode。

    Args:
        finding: 上游的敏感发现对象。

    Returns:
        对应的 GraphNode 实例。
    """
    node_id = f"node_{uuid.uuid4().hex[:8]}"
    entity_type = _category_to_entity_type(finding.category)
    label = desensitize_text(finding.matched_text, finding.category)

    # 构建 location 摘要元数据
    loc_meta: dict[str, Any] = {}
    if finding.location:
        loc = finding.location
        loc_meta["block_index"] = loc.block_index
        if loc.line_number is not None:
            loc_meta["line_number"] = loc.line_number
        if loc.page_number is not None:
            loc_meta["page_number"] = loc.page_number
        if loc.sheet_name is not None:
            loc_meta["sheet_name"] = loc.sheet_name
        if loc.cell_address is not None:
            loc_meta["cell_address"] = loc.cell_address

    return GraphNode(
        id=node_id,
        label=label,
        entity_type=entity_type,
        sensitivity_level=finding.sensitivity_level,
        category=finding.category,
        original_text=finding.matched_text,
        finding_id=finding.finding_id,
        metadata={"location": loc_meta, "confidence": finding.confidence, "source": finding.source},
    )


def _build_risk_explanation(risk_factors: list[str], findings_count: int) -> str:
    """根据风险因素列表生成自然语言的风险解释。

    Args:
        risk_factors: 关键风险因素描述列表。
        findings_count: 敏感发现总数。

    Returns:
        自然语言的风险解释字符串。
    """
    if not risk_factors:
        if findings_count == 0:
            return "未发现敏感信息。"
        return f"发现{findings_count}处敏感信息，暂未检测到高风险关联。"

    parts = [f"发现{findings_count}处敏感信息"]
    parts.append("，".join(risk_factors))
    return "，".join(parts) + "。"


def _get_combined_risk_level(type_a: str, type_b: str) -> tuple[str, str]:
    """根据两个节点的 entity_type 查找风险放大规则。

    Args:
        type_a: 第一个节点的 entity_type。
        type_b: 第二个节点的 entity_type。

    Returns:
        (risk_amplification_description, combined_risk_level) 元组。
        未匹配到规则时返回 ("", "")。
    """
    pair = {type_a, type_b}
    for rule in _RISK_AMPLIFICATION_RULES:
        # 规则匹配条件：pair 是规则 source_types 的子集（允许两类型相同时规则含2个不同类型则不匹配）
        if pair.issubset(rule["source_types"]) and len(pair) >= 2:
            return rule["description"], rule["amplification"]
    return "", ""


def _generate_explanation_summary(
    nodes: list[GraphNode],
    edges: list[GraphEdge],
    risk_assessment: RiskAssessment,
    clusters: list[dict],
) -> str:
    """生成面向非技术人员的整体风险通俗总结。

    Args:
        nodes: 图谱所有节点。
        edges: 图谱所有边。
        risk_assessment: 风险评估结果。
        clusters: 聚类信息。

    Returns:
        通俗易懂的总结文本。
    """
    if not nodes:
        return "本文档未发现敏感信息，风险等级为低。"

    total = len(nodes)
    # 按类型统计
    type_counts: dict[str, int] = defaultdict(int)
    for node in nodes:
        type_counts[node.entity_type] += 1

    # 按级别统计
    level_counts: dict[str, int] = defaultdict(int)
    for node in nodes:
        level_counts[node.sensitivity_level] += 1

    # 生成类型描述
    type_names = {
        "PII": "个人身份信息",
        "CONTACT": "联系方式",
        "FINANCIAL": "金融信息",
        "CREDENTIAL": "账号凭证",
        "ENTERPRISE_SECRET": "企业核心机密",
        "COMPLIANCE": "密级合规信息",
        "INFRASTRUCTURE": "网络基础设施信息",
        "OTHER": "其他敏感信息",
    }

    parts = [f"本文档共发现{total}处敏感信息"]

    type_desc_items = []
    for etype, count in sorted(type_counts.items(), key=lambda x: -x[1]):
        name = type_names.get(etype, etype)
        type_desc_items.append(f"{name}{count}处")
    if type_desc_items:
        parts.append("，包括" + "、".join(type_desc_items))

    parts.append(f"。整体风险等级为{risk_assessment.risk_level}")

    critical_count = level_counts.get("CRITICAL", 0)
    high_count = level_counts.get("HIGH", 0)
    if critical_count > 0:
        parts.append(f"，其中{critical_count}处为极高风险")
    if high_count > 0:
        parts.append(f"，{high_count}处为高风险")

    # 高风险关联描述
    amplified_edges = [e for e in edges if e.combined_risk_level in ("CRITICAL", "HIGH")]
    if amplified_edges:
        parts.append(f"。检测到{len(amplified_edges)}组高风险信息组合关联，多种敏感信息关联后风险显著放大")

    if clusters:
        parts.append(f"。发现{len(clusters)}个敏感信息聚类")

    parts.append("。建议相关人员及时审阅并采取相应的保护措施。")

    return "".join(parts)


# ======================================================================
# 核心类：知识图谱构建器
# ======================================================================


class KnowledgeGraphBuilder:
    """敏感信息知识图谱构建器。

    支持两种构建模式：
    1. 规则化构建（RULE_BASED）：基于共现、距离、类型推断关系——快速、无外部依赖
    2. LLM 增强构建（LLM_ENHANCED）：调用 LLM 分析更深层语义关联——更智能但更慢

    增强功能：
    3. 企业自定义分类集成：支持从 config 中加载企业特有的敏感信息分类
    4. 用户交互式自定义：支持用户标记、确认/拒绝敏感信息
    5. 解释性节点/边属性：自动生成通俗易懂的说明文本

    设计原则：
    - 规则化构建是基线保证，即使 LLM 不可用也能工作
    - LLM 增强是锦上添花，在规则化图谱基础上叠加 LLM 发现的语义关联
    - 两种模式的输出结构完全一致（SensitiveKnowledgeGraph）
    - 所有用户交互操作记录到 user_modifications 供审计追踪
    """

    def __init__(self, config: LLMConfig) -> None:
        """初始化图谱构建器。

        Args:
            config: LLM 配置对象，用于创建 LLM 客户端（仅 LLM 增强模式需要）。
        """
        self.config = config
        self._client: BaseLLMClient | None = None
        self._prompt_manager: PromptManager | None = None

        # 线程锁，保障用户交互操作的线程安全
        self._lock = threading.Lock()

        # 新增：从 config 中提取企业自定义信息
        self._custom_categories: list[dict] = []
        self._custom_explanations: dict[str, str] = {}
        # 企业自定义 category → entity_type 的扩展映射
        self._custom_category_type_map: dict[str, str] = {}

        if config:
            self._custom_categories = getattr(config, "custom_sensitive_categories", []) or []
            self._custom_explanations = getattr(config, "custom_explanation_templates", {}) or {}
            # 为企业自定义分类建立映射
            for cat_def in self._custom_categories:
                cat_name = cat_def.get("name", "")
                if cat_name:
                    # 自定义分类统一映射为 ENTERPRISE_SECRET，除非有明确指定
                    etype = cat_def.get("entity_type", "ENTERPRISE_SECRET")
                    self._custom_category_type_map[cat_name] = etype

    # ------------------------------------------------------------------
    # 私有方法：延迟初始化
    # ------------------------------------------------------------------

    def _ensure_client(self) -> BaseLLMClient:
        """延迟创建 LLM 客户端，仅在 LLM 增强模式下调用。

        Returns:
            已初始化的 BaseLLMClient 实例。

        Raises:
            LLMAPIError: 客户端创建失败时抛出。
        """
        if self._client is None:
            self._client = create_llm_client(self.config)
        return self._client

    def _ensure_prompt_manager(self) -> PromptManager:
        """延迟创建 PromptManager。

        Returns:
            已初始化的 PromptManager 实例。
        """
        if self._prompt_manager is None:
            self._prompt_manager = PromptManager(self.config)
        return self._prompt_manager

    def _parse_llm_kg_response(self, response_text: str) -> dict:
        """解析 LLM 返回的知识图谱 JSON 响应。

        使用 detector.py 中已有的多层容错解析函数。

        Args:
            response_text: LLM 返回的原始文本。

        Returns:
            解析后的 dict，解析失败时返回空 dict。
        """
        from .detector import parse_llm_response  # 延迟导入避免循环引用

        try:
            return parse_llm_response(response_text)
        except Exception as e:
            logger.warning("解析 LLM 知识图谱响应失败: %s", e)
            return {}

    # ------------------------------------------------------------------
    # 解释性文本填充
    # ------------------------------------------------------------------

    def _fill_node_explanations(self, node: GraphNode, finding: SensitiveFinding) -> GraphNode:
        """为节点填充解释性文本。

        优先级：
        1. 企业自定义分类的 explanation 模板
        2. 内置分类的通用 explanation（_BUILTIN_EXPLANATIONS）
        3. 基于分类和级别的自动生成（兜底）

        Args:
            node: 待填充的节点。
            finding: 对应的敏感发现。

        Returns:
            填充后的节点（就地修改并返回）。
        """
        category = finding.category

        # 检查是否命中企业自定义分类
        custom_match = self._find_custom_category_match(finding)
        if custom_match:
            node.is_custom_defined = True
            node.custom_category_name = custom_match.get("name", "")
            # 企业自定义分类的解释
            explanation = custom_match.get("explanation", "")
            if isinstance(explanation, dict):
                node.why_sensitive = explanation.get("why_sensitive", "")
                node.risk_if_leaked = explanation.get("risk_if_leaked", "")
                node.recommended_action = explanation.get("recommended_action", "")
            elif isinstance(explanation, str) and explanation:
                node.why_sensitive = explanation
            # 如果自定义分类提供了模板，也检查 _custom_explanations
            cat_name = custom_match.get("name", "")
            if cat_name in self._custom_explanations:
                tmpl = self._custom_explanations[cat_name]
                if isinstance(tmpl, dict):
                    if not node.why_sensitive:
                        node.why_sensitive = tmpl.get("why_sensitive", "")
                    if not node.risk_if_leaked:
                        node.risk_if_leaked = tmpl.get("risk_if_leaked", "")
                    if not node.recommended_action:
                        node.recommended_action = tmpl.get("recommended_action", "")
                elif isinstance(tmpl, str) and not node.why_sensitive:
                    node.why_sensitive = tmpl

        # 内置分类解释（仅填充尚未填充的字段）
        builtin = _BUILTIN_EXPLANATIONS.get(category, {})
        if builtin:
            if not node.why_sensitive:
                node.why_sensitive = builtin.get("why_sensitive", "")
            if not node.risk_if_leaked:
                node.risk_if_leaked = builtin.get("risk_if_leaked", "")
            if not node.recommended_action:
                node.recommended_action = builtin.get("recommended_action", "")

        # 兜底自动生成（如果仍为空）
        if not node.why_sensitive:
            node.why_sensitive = (
                f"该信息属于「{category}」类别（敏感级别：{node.sensitivity_level}），"
                f"可能涉及隐私保护或企业安全合规要求。"
            )
        if not node.risk_if_leaked:
            level_desc = {
                "CRITICAL": "极高风险",
                "HIGH": "高风险",
                "MEDIUM": "中等风险",
                "LOW": "低风险",
            }.get(node.sensitivity_level, "未知风险")
            node.risk_if_leaked = (
                f"该信息泄露属于{level_desc}事件，可能对个人隐私或企业安全造成不利影响。"
            )
        if not node.recommended_action:
            node.recommended_action = "建议对该信息进行脱敏处理或限制文档传播范围，并联系安全管理员评估。"

        return node

    def _find_custom_category_match(self, finding: SensitiveFinding) -> dict | None:
        """检查一个 finding 是否匹配企业自定义分类。

        匹配逻辑：
        1. finding.category 与自定义分类名称完全匹配
        2. finding.matched_text 包含自定义分类的 keywords

        Args:
            finding: 敏感发现。

        Returns:
            匹配到的自定义分类 dict，未匹配返回 None。
        """
        for cat_def in self._custom_categories:
            cat_name = cat_def.get("name", "")
            # 名称匹配
            if cat_name and cat_name == finding.category:
                return cat_def
            # 关键词匹配
            keywords = cat_def.get("keywords", [])
            if keywords and isinstance(keywords, list):
                text_lower = finding.matched_text.lower()
                for kw in keywords:
                    if isinstance(kw, str) and kw.lower() in text_lower:
                        return cat_def
        return None

    def _fill_edge_explanations(
        self,
        edge: GraphEdge,
        source_node: GraphNode,
        target_node: GraphNode,
    ) -> GraphEdge:
        """为边填充风险放大说明和组合风险等级。

        Args:
            edge: 待填充的边。
            source_node: 源节点。
            target_node: 目标节点。

        Returns:
            填充后的边（就地修改并返回）。
        """
        amplification_desc, combined_level = _get_combined_risk_level(
            source_node.entity_type, target_node.entity_type
        )
        if amplification_desc:
            edge.risk_amplification = amplification_desc
            edge.combined_risk_level = combined_level
        else:
            # 无特定放大规则时，取两端节点的较高级别
            src_order = _LEVEL_ORDER.get(source_node.sensitivity_level, 0)
            tgt_order = _LEVEL_ORDER.get(target_node.sensitivity_level, 0)
            higher_level = source_node.sensitivity_level if src_order >= tgt_order else target_node.sensitivity_level
            edge.combined_risk_level = higher_level
            edge.risk_amplification = (
                f"{source_node.entity_type}与{target_node.entity_type}类信息关联出现，"
                f"组合风险等级为{higher_level}。"
            )
        return edge

    # ------------------------------------------------------------------
    # 主入口
    # ------------------------------------------------------------------

    def build(
        self,
        text_content: str,
        findings: list[SensitiveFinding],
        use_llm: bool = True,
    ) -> SensitiveKnowledgeGraph:
        """构建知识图谱（主入口）。

        策略：
        1. 始终先执行规则化构建
        2. 如果 use_llm=True 且 LLM 可用，再执行 LLM 增强
        3. 合并两者结果（去重边、取高权重）
        4. 如果 LLM 调用失败，降级返回纯规则结果（不崩溃）

        Args:
            text_content: 原始文本（多个 TextBlock 拼接后的完整文本）。
            findings: 所有已确认的 SensitiveFinding 列表。
            use_llm: 是否尝试使用 LLM 增强。

        Returns:
            SensitiveKnowledgeGraph 对象。
        """
        start_time = time.monotonic()
        logger.info("开始构建知识图谱，共 %d 条敏感发现，use_llm=%s", len(findings), use_llm)

        # 1. 规则化构建（始终执行）
        rule_graph = self.build_rule_based(findings)

        # 2. LLM 增强（可选）
        if use_llm and findings:
            try:
                client = self._ensure_client()
                if client.is_available():
                    graph = self.build_llm_enhanced(text_content, findings, rule_graph)
                    graph.build_mode = "LLM_ENHANCED"
                    elapsed_ms = int((time.monotonic() - start_time) * 1000)
                    graph.metadata["build_time_ms"] = elapsed_ms
                    graph.metadata["node_count"] = len(graph.nodes)
                    graph.metadata["edge_count"] = len(graph.edges)
                    logger.info(
                        "知识图谱构建完成（LLM增强），%d 节点，%d 边，耗时 %d ms",
                        len(graph.nodes), len(graph.edges), elapsed_ms,
                    )
                    return graph
                else:
                    logger.warning("LLM 客户端不可用，降级为纯规则构建")
                    rule_graph.metadata["llm_enhancement_skipped"] = True
                    rule_graph.metadata["llm_skip_reason"] = "client_unavailable"
            except Exception as e:
                logger.warning("LLM 增强失败，降级为纯规则构建: %s", e)
                rule_graph.metadata["llm_enhancement_failed"] = True
                rule_graph.metadata["llm_error"] = str(e)

        # 3. 返回纯规则图谱
        elapsed_ms = int((time.monotonic() - start_time) * 1000)
        rule_graph.metadata["build_time_ms"] = elapsed_ms
        rule_graph.metadata["node_count"] = len(rule_graph.nodes)
        rule_graph.metadata["edge_count"] = len(rule_graph.edges)
        logger.info(
            "知识图谱构建完成（纯规则），%d 节点，%d 边，耗时 %d ms",
            len(rule_graph.nodes), len(rule_graph.edges), elapsed_ms,
        )
        return rule_graph

    # ------------------------------------------------------------------
    # 规则化构建
    # ------------------------------------------------------------------

    def build_rule_based(self, findings: list[SensitiveFinding]) -> SensitiveKnowledgeGraph:
        """纯规则的图谱构建（不调用 LLM 的降级方案）。

        按以下步骤构建：
        1. 将每个 SensitiveFinding 转为 GraphNode
        2. 填充解释性字段
        3. 按规则推断节点间的 GraphEdge
        4. 填充边的解释性字段
        5. 基于高权重边做连通分量聚类
        6. 计算整体风险评分
        7. 生成通俗总结

        Args:
            findings: 所有已确认的 SensitiveFinding 列表。

        Returns:
            规则化构建的 SensitiveKnowledgeGraph 对象。
        """
        # 兼容层：支持传入 dict 列表，统一转换为 SensitiveFinding
        findings = _normalize_findings(findings)

        # 空 findings 快速返回
        if not findings:
            return SensitiveKnowledgeGraph(
                nodes=[],
                edges=[],
                risk_assessment=RiskAssessment(
                    risk_score=0.0,
                    risk_level="LOW",
                    explanation="未发现敏感信息。",
                    key_risk_factors=[],
                ),
                clusters=[],
                build_mode="RULE_BASED",
                metadata={},
                explanation_summary="本文档未发现敏感信息，风险等级为低。",
            )

        # 1. 构建节点
        nodes: list[GraphNode] = []
        finding_to_node_id: dict[str, str] = {}  # finding_id → node_id
        node_id_to_finding: dict[str, SensitiveFinding] = {}  # node_id → finding

        for finding in findings:
            node = _finding_to_node(finding)
            # 2. 填充解释性字段
            self._fill_node_explanations(node, finding)
            nodes.append(node)
            if finding.finding_id:
                finding_to_node_id[finding.finding_id] = node.id
            node_id_to_finding[node.id] = finding

        # 3. 推断边
        edges = self._infer_edges_by_rules(nodes, node_id_to_finding)

        # 4. 填充边的解释性字段
        node_map: dict[str, GraphNode] = {nd.id: nd for nd in nodes}
        for edge in edges:
            src = node_map.get(edge.source)
            tgt = node_map.get(edge.target)
            if src and tgt:
                self._fill_edge_explanations(edge, src, tgt)

        # 5. 聚类
        clusters = self._build_clusters(nodes, edges)

        # 6. 风险评估
        risk_assessment = self._compute_risk_assessment(findings, edges, clusters)

        # 7. 生成通俗总结
        explanation_summary = _generate_explanation_summary(nodes, edges, risk_assessment, clusters)

        return SensitiveKnowledgeGraph(
            nodes=nodes,
            edges=edges,
            risk_assessment=risk_assessment,
            clusters=clusters,
            build_mode="RULE_BASED",
            metadata={"finding_to_node_id": finding_to_node_id},
            explanation_summary=explanation_summary,
        )

    def _infer_edges_by_rules(
        self,
        nodes: list[GraphNode],
        node_id_to_finding: dict[str, SensitiveFinding],
    ) -> list[GraphEdge]:
        """按规则推断节点间的边。

        按优先级依次应用 7 条规则，同一对节点取权重最高的边。
        对于大量 findings（> 100），只保留权重 ≥ 0.5 的边。

        Args:
            nodes: 所有图谱节点。
            node_id_to_finding: 节点 ID 到原始 finding 的映射。

        Returns:
            推断得到的边列表。
        """
        # 用于去重：(min_id, max_id) → GraphEdge（保留最高权重）
        best_edges: dict[tuple[str, str], GraphEdge] = {}

        def _edge_key(id_a: str, id_b: str) -> tuple[str, str]:
            return (min(id_a, id_b), max(id_a, id_b))

        def _add_edge(source: str, target: str, relation: str, description: str, weight: float) -> None:
            key = _edge_key(source, target)
            if key not in best_edges or best_edges[key].weight < weight:
                best_edges[key] = GraphEdge(
                    source=key[0],
                    target=key[1],
                    relation=relation,
                    description=description,
                    weight=weight,
                    inferred_by="RULE",
                )

        # 构建辅助索引
        node_list = list(nodes)
        n = len(node_list)

        # 按 block_index 分组
        block_groups: dict[int, list[GraphNode]] = defaultdict(list)
        for node in node_list:
            finding = node_id_to_finding.get(node.id)
            if finding and finding.location:
                block_groups[finding.location.block_index].append(node)

        # ---- 规则 1：同位置共现（权重 0.9）----
        covered_by_rule1: set[tuple[str, str]] = set()
        for block_idx, group in block_groups.items():
            if len(group) < 2:
                continue
            for a, b in combinations(group, 2):
                key = _edge_key(a.id, b.id)
                covered_by_rule1.add(key)
                _add_edge(
                    a.id, b.id,
                    relation="共现于同一位置",
                    description=f"在同一文本块（block {block_idx}）中同时出现",
                    weight=0.9,
                )

        # ---- 规则 2：相邻出现（权重 0.6）----
        for i in range(n):
            for j in range(i + 1, n):
                a, b = node_list[i], node_list[j]
                key = _edge_key(a.id, b.id)
                if key in covered_by_rule1:
                    continue
                fa = node_id_to_finding.get(a.id)
                fb = node_id_to_finding.get(b.id)
                if fa and fb and fa.location and fb.location:
                    dist = abs(fa.location.block_index - fb.location.block_index)
                    if dist <= 2:
                        _add_edge(
                            a.id, b.id,
                            relation="相邻出现",
                            description=f"在相邻文本块中出现（距离 {dist}）",
                            weight=0.6,
                        )

        # 位置邻近集合（规则1或规则2覆盖的节点对），供后续规则使用
        proximity_pairs: set[tuple[str, str]] = set()
        for key, edge in best_edges.items():
            if edge.relation in ("共现于同一位置", "相邻出现"):
                proximity_pairs.add(key)

        # ---- 规则 3：同一人信息链（权重 0.95）----
        # PII + CONTACT 或 PII + FINANCIAL 且位置邻近
        pii_nodes = [nd for nd in node_list if nd.entity_type == "PII"]
        contact_nodes = [nd for nd in node_list if nd.entity_type == "CONTACT"]
        financial_nodes = [nd for nd in node_list if nd.entity_type == "FINANCIAL"]

        for pii in pii_nodes:
            for other in contact_nodes + financial_nodes:
                key = _edge_key(pii.id, other.id)
                if key in proximity_pairs:
                    _add_edge(
                        pii.id, other.id,
                        relation="可能属于同一人",
                        description=f"个人身份信息与{other.entity_type}类信息在邻近位置出现，可能属于同一人",
                        weight=0.95,
                    )

        # ---- 规则 4：完整金融信息（权重 0.9）----
        for fin in financial_nodes:
            for other in pii_nodes + contact_nodes:
                key = _edge_key(fin.id, other.id)
                if key in proximity_pairs:
                    # 仅当未被规则3以更高权重覆盖时添加
                    if key not in best_edges or best_edges[key].weight < 0.9:
                        _add_edge(
                            fin.id, other.id,
                            relation="构成完整金融信息",
                            description="金融信息与个人/联系信息关联，构成完整金融信息",
                            weight=0.9,
                        )

        # ---- 规则 5：登录凭证组合（权重 0.95）----
        credential_nodes = [nd for nd in node_list if nd.entity_type == "CREDENTIAL"]
        if len(credential_nodes) >= 2:
            for a, b in combinations(credential_nodes, 2):
                fa = node_id_to_finding.get(a.id)
                fb = node_id_to_finding.get(b.id)
                if fa and fb and fa.location and fb.location:
                    dist = abs(fa.location.block_index - fb.location.block_index)
                    if dist <= 3:
                        _add_edge(
                            a.id, b.id,
                            relation="构成登录凭证",
                            description="用户名/邮箱与密码/密钥在邻近位置出现，构成登录凭证组合",
                            weight=0.95,
                        )

        # 也检查 CREDENTIAL + CONTACT（如邮箱 + 密码）
        for cred in credential_nodes:
            for contact in contact_nodes:
                fc = node_id_to_finding.get(cred.id)
                fcon = node_id_to_finding.get(contact.id)
                if fc and fcon and fc.location and fcon.location:
                    dist = abs(fc.location.block_index - fcon.location.block_index)
                    if dist <= 3:
                        _add_edge(
                            cred.id, contact.id,
                            relation="构成登录凭证",
                            description="凭证信息与联系方式在邻近位置出现，可能构成登录凭证",
                            weight=0.95,
                        )

        # ---- 规则 6：批量数据检测（权重 0.7）----
        type_groups: dict[str, list[GraphNode]] = defaultdict(list)
        for nd in node_list:
            type_groups[nd.entity_type].append(nd)

        for etype, group in type_groups.items():
            if len(group) >= 5:
                # 在批量组内两两连接（限制连接数：只连接组内前20个节点以控制边数）
                limited_group = group[:20]
                for a, b in combinations(limited_group, 2):
                    key = _edge_key(a.id, b.id)
                    if key not in best_edges:  # 仅在无更高优先级边时添加
                        _add_edge(
                            a.id, b.id,
                            relation="批量敏感数据",
                            description=f"同类型（{etype}）敏感信息批量出现，可能是批量数据",
                            weight=0.7,
                        )

        # ---- 规则 7：同类聚合（权重 0.5）----
        cat_groups: dict[str, list[GraphNode]] = defaultdict(list)
        for nd in node_list:
            cat_groups[nd.category].append(nd)

        for cat, group in cat_groups.items():
            if len(group) < 2:
                continue
            limited_group = group[:15]
            for a, b in combinations(limited_group, 2):
                key = _edge_key(a.id, b.id)
                if key not in best_edges:
                    _add_edge(
                        a.id, b.id,
                        relation="同类型敏感信息",
                        description=f"属于相同类别（{cat}）的敏感信息",
                        weight=0.5,
                    )

        # 对于大量 findings，过滤低权重边
        min_weight = 0.5 if n > 100 else 0.0
        result = [e for e in best_edges.values() if e.weight >= min_weight]

        logger.debug("规则推断得到 %d 条边（过滤前 %d 条）", len(result), len(best_edges))
        return result

    def _build_clusters(
        self,
        nodes: list[GraphNode],
        edges: list[GraphEdge],
    ) -> list[dict]:
        """基于连通分量的简单聚类。

        仅使用权重 ≥ 0.6 的边构建邻接表，通过 BFS 找连通分量。
        单节点不形成 cluster，除非是 CRITICAL 级别。

        Args:
            nodes: 所有图谱节点。
            edges: 所有图谱边。

        Returns:
            聚类信息列表。
        """
        if not nodes:
            return []

        # 构建邻接表（仅权重 ≥ 0.6 的边）
        adj: dict[str, set[str]] = defaultdict(set)
        for edge in edges:
            if edge.weight >= 0.6:
                adj[edge.source].add(edge.target)
                adj[edge.target].add(edge.source)

        # BFS 找连通分量
        visited: set[str] = set()
        components: list[list[str]] = []

        for node in nodes:
            if node.id in visited:
                continue
            # BFS
            component: list[str] = []
            queue: deque[str] = deque([node.id])
            visited.add(node.id)
            while queue:
                current = queue.popleft()
                component.append(current)
                for neighbor in adj.get(current, set()):
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append(neighbor)
            components.append(component)

        # 构建节点索引
        node_map: dict[str, GraphNode] = {nd.id: nd for nd in nodes}

        # 生成聚类信息
        clusters: list[dict] = []
        cluster_idx = 0
        for component in components:
            # 单节点不形成 cluster，除非是 CRITICAL
            if len(component) == 1:
                nd = node_map.get(component[0])
                if nd and nd.sensitivity_level == "CRITICAL":
                    pass  # 允许 CRITICAL 单节点 cluster
                else:
                    continue

            cluster_idx += 1
            entity_types = {node_map[nid].entity_type for nid in component if nid in node_map}

            # 自动生成 label
            label = self._generate_cluster_label(entity_types, cluster_idx)
            risk_factor = self._generate_cluster_risk_factor(entity_types)

            clusters.append({
                "cluster_id": f"c{cluster_idx}",
                "node_ids": component,
                "label": label,
                "risk_factor": risk_factor,
                "size": len(component),
                "entity_types": sorted(entity_types),
            })

        return clusters

    @staticmethod
    def _generate_cluster_label(entity_types: set[str], idx: int) -> str:
        """根据聚类包含的实体类型自动生成 label。

        Args:
            entity_types: 聚类中包含的实体类型集合。
            idx: 聚类序号。

        Returns:
            聚类标签字符串。
        """
        has_pii = "PII" in entity_types
        has_contact = "CONTACT" in entity_types
        has_financial = "FINANCIAL" in entity_types
        has_credential = "CREDENTIAL" in entity_types
        has_secret = "ENTERPRISE_SECRET" in entity_types

        if has_pii and (has_contact or has_financial):
            return "完整个人画像"
        if has_credential:
            return "凭证组合"
        if has_secret:
            return "商业机密组"
        if has_financial:
            return "金融信息组"
        return f"敏感信息组 #{idx}"

    @staticmethod
    def _generate_cluster_risk_factor(entity_types: set[str]) -> str:
        """根据聚类包含的实体类型生成风险因素描述。

        Args:
            entity_types: 聚类中包含的实体类型集合。

        Returns:
            风险因素描述字符串。
        """
        has_pii = "PII" in entity_types
        has_contact = "CONTACT" in entity_types
        has_financial = "FINANCIAL" in entity_types
        has_credential = "CREDENTIAL" in entity_types

        if has_pii and (has_contact or has_financial):
            return "完整隐私链"
        if has_credential:
            return "凭证泄露风险"
        if has_financial:
            return "金融信息关联"
        return "多项敏感信息关联"

    def _compute_risk_assessment(
        self,
        findings: list[SensitiveFinding],
        edges: list[GraphEdge],
        clusters: list[dict],
    ) -> RiskAssessment:
        """计算整体风险评估。

        评分模型：
        - 基础分 = max(所有 findings 的 sensitivity_level 对应分数)
        - 关联加分（累加），上限 10.0
        - risk_level 由最终分数映射

        Args:
            findings: 所有敏感发现。
            edges: 所有图谱边。
            clusters: 聚类信息。

        Returns:
            RiskAssessment 对象。
        """
        if not findings:
            return RiskAssessment(
                risk_score=0.0,
                risk_level="LOW",
                explanation="未发现敏感信息。",
                key_risk_factors=[],
            )

        # 基础分
        base_score = max(_LEVEL_SCORE_MAP.get(f.sensitivity_level, 2.0) for f in findings)
        score = base_score
        risk_factors: list[str] = []

        # 收集边的关系类型
        relation_set = {e.relation for e in edges}

        # 关联加分
        if "可能属于同一人" in relation_set:
            score += 1.0
            risk_factors.append("存在同一人信息链（身份信息与联系/金融信息关联）")

        if "构成登录凭证" in relation_set:
            score += 1.0
            risk_factors.append("存在登录凭证组合（用户名/邮箱+密码）")

        if "构成完整金融信息" in relation_set:
            score += 0.5
            risk_factors.append("存在完整金融信息关联")

        # 新增：风险放大边的加分
        critical_amplified = sum(1 for e in edges if e.combined_risk_level == "CRITICAL")
        if critical_amplified > 0:
            score += min(critical_amplified * 0.3, 1.5)
            risk_factors.append(f"存在{critical_amplified}组极高风险信息组合关联")

        count = len(findings)
        if count > 50:
            score += 1.5
            risk_factors.append(f"敏感信息数量较多（{count}处，>50）")
        elif count > 10:
            score += 0.5
            risk_factors.append(f"敏感信息数量较多（{count}处，>10）")

        if clusters:
            max_cluster_size = max(c.get("size", 0) for c in clusters)
            if max_cluster_size >= 5:
                score += 0.5
                risk_factors.append(f"最大关联聚类包含{max_cluster_size}个节点")

        # 上限
        score = min(score, 10.0)

        # risk_level 映射
        if score >= 7.5:
            risk_level = "CRITICAL"
        elif score >= 5.0:
            risk_level = "HIGH"
        elif score >= 3.0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        explanation = _build_risk_explanation(risk_factors, count)

        return RiskAssessment(
            risk_score=round(score, 1),
            risk_level=risk_level,
            explanation=explanation,
            key_risk_factors=risk_factors,
        )

    # ------------------------------------------------------------------
    # LLM 增强构建
    # ------------------------------------------------------------------

    def build_llm_enhanced(
        self,
        text_content: str,
        findings: list[SensitiveFinding],
        rule_graph: SensitiveKnowledgeGraph,
    ) -> SensitiveKnowledgeGraph:
        """LLM 增强的图谱构建。在规则图谱基础上叠加 LLM 发现的语义关联。

        流程：
        1. 准备输入（截断文本、精简 findings）
        2. 通过 PromptManager 构建消息
        3. 调用 LLM
        4. 解析响应并合并到规则图谱

        Args:
            text_content: 原始文本。
            findings: 所有敏感发现。
            rule_graph: 已构建好的规则化图谱。

        Returns:
            增强后的 SensitiveKnowledgeGraph 对象。
        """
        logger.info("开始 LLM 增强图谱构建")

        # 兼容层：支持传入 dict 列表，统一转换为 SensitiveFinding
        findings = _normalize_findings(findings)

        # 1. 准备输入
        max_chars = self.config.max_input_tokens * 2  # 粗略估计：1 token ≈ 2 字符（中文）
        truncated_text = text_content[:max_chars] if len(text_content) > max_chars else text_content

        findings_dicts = [
            {
                "finding_id": f.finding_id,
                "category": f.category,
                "matched_text": f.matched_text,
                "sensitivity_level": f.sensitivity_level,
                "confidence": f.confidence,
                "block_index": f.location.block_index if f.location else None,
            }
            for f in findings
        ]

        # 2. 构建消息
        prompt_manager = self._ensure_prompt_manager()
        messages = prompt_manager.build_knowledge_graph_messages(truncated_text, findings_dicts)

        # 3. 调用 LLM
        client = self._ensure_client()
        try:
            response: LLMResponse = client.chat_completion(
                messages=messages,
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
                response_format={"type": "json_object"},
            )
        except Exception as e:
            logger.warning("LLM 调用失败: %s，降级返回纯规则图谱", e)
            rule_graph.metadata["llm_enhancement_failed"] = True
            rule_graph.metadata["llm_error"] = str(e)
            return rule_graph

        # 4. 解析响应
        llm_result = self._parse_llm_kg_response(response.content)
        if not llm_result:
            logger.warning("LLM 响应解析为空，降级返回纯规则图谱")
            rule_graph.metadata["llm_enhancement_failed"] = True
            rule_graph.metadata["llm_error"] = "empty_parse_result"
            return rule_graph

        # 5. 合并结果
        merged_graph = self._merge_llm_into_rule_graph(rule_graph, llm_result, findings)

        # 记录 LLM 使用信息
        merged_graph.metadata["llm_model"] = response.model
        merged_graph.metadata["llm_provider"] = response.provider
        merged_graph.metadata["llm_tokens"] = {
            "prompt": response.usage.prompt_tokens,
            "completion": response.usage.completion_tokens,
            "total": response.usage.total_tokens,
        }
        merged_graph.metadata["llm_latency_ms"] = response.latency_ms

        return merged_graph

    def _merge_llm_into_rule_graph(
        self,
        rule_graph: SensitiveKnowledgeGraph,
        llm_result: dict,
        findings: list[SensitiveFinding],
    ) -> SensitiveKnowledgeGraph:
        """将 LLM 分析结果合并到规则图谱中。

        合并策略：
        - LLM 发现的新边 → 添加，inferred_by="LLM"
        - LLM 对已有边的补充描述 → 更新 description
        - LLM 的 risk_assessment → 与规则评分取较高者
        - 匹配不上的内容 → 跳过

        Args:
            rule_graph: 规则化构建的图谱。
            llm_result: LLM 返回的解析结果（dict）。
            findings: 原始 findings 列表。

        Returns:
            合并后的 SensitiveKnowledgeGraph 对象。
        """
        # 深拷贝规则图谱的关键数据
        merged_nodes = list(rule_graph.nodes)
        merged_edges = list(rule_graph.edges)
        merged_clusters = list(rule_graph.clusters)
        merged_risk = rule_graph.risk_assessment
        merged_metadata = dict(rule_graph.metadata)

        # 构建查找索引
        finding_id_to_node: dict[str, GraphNode] = {}
        text_to_node: dict[str, GraphNode] = {}
        node_map: dict[str, GraphNode] = {}
        for node in merged_nodes:
            if node.finding_id:
                finding_id_to_node[node.finding_id] = node
            text_to_node[node.original_text] = node
            node_map[node.id] = node

        existing_edge_keys: set[tuple[str, str]] = set()
        for edge in merged_edges:
            key = (min(edge.source, edge.target), max(edge.source, edge.target))
            existing_edge_keys.add(key)

        # 解析 LLM 返回的边
        llm_edges = llm_result.get("edges", llm_result.get("relationships", []))
        llm_new_edges_count = 0

        for llm_edge_data in llm_edges:
            if not isinstance(llm_edge_data, dict):
                continue

            try:
                # 尝试匹配源节点和目标节点
                source_node = self._resolve_llm_node_ref(
                    llm_edge_data.get("source", llm_edge_data.get("source_id", "")),
                    finding_id_to_node,
                    text_to_node,
                )
                target_node = self._resolve_llm_node_ref(
                    llm_edge_data.get("target", llm_edge_data.get("target_id", "")),
                    finding_id_to_node,
                    text_to_node,
                )

                if not source_node or not target_node or source_node.id == target_node.id:
                    continue

                edge_key = (min(source_node.id, target_node.id), max(source_node.id, target_node.id))
                relation = str(llm_edge_data.get("relation", llm_edge_data.get("relationship", "语义关联")))
                description = str(llm_edge_data.get("description", relation))
                weight = float(llm_edge_data.get("weight", 0.7))
                weight = max(0.0, min(1.0, weight))

                if edge_key in existing_edge_keys:
                    # 已有边 → 补充描述
                    for existing_edge in merged_edges:
                        ek = (min(existing_edge.source, existing_edge.target),
                              max(existing_edge.source, existing_edge.target))
                        if ek == edge_key:
                            if description and description != existing_edge.description:
                                existing_edge.description += f"；LLM补充：{description}"
                            break
                else:
                    # 新边
                    new_edge = GraphEdge(
                        source=edge_key[0],
                        target=edge_key[1],
                        relation=relation,
                        description=description,
                        weight=weight,
                        inferred_by="LLM",
                    )
                    # 填充解释性字段
                    src = node_map.get(edge_key[0])
                    tgt = node_map.get(edge_key[1])
                    if src and tgt:
                        self._fill_edge_explanations(new_edge, src, tgt)
                    merged_edges.append(new_edge)
                    existing_edge_keys.add(edge_key)
                    llm_new_edges_count += 1
            except Exception as e:
                logger.debug("解析 LLM 边数据失败，跳过: %s", e)
                continue

        logger.info("LLM 增强添加了 %d 条新边", llm_new_edges_count)

        # 合并风险评估（取较高者）
        llm_risk = llm_result.get("risk_assessment", {})
        if isinstance(llm_risk, dict):
            try:
                llm_score = float(llm_risk.get("risk_score", 0))
                if llm_score > merged_risk.risk_score:
                    llm_level = str(llm_risk.get("risk_level", merged_risk.risk_level))
                    llm_explanation = str(llm_risk.get("explanation", merged_risk.explanation))
                    llm_factors = llm_risk.get("key_risk_factors", [])
                    if not isinstance(llm_factors, list):
                        llm_factors = []

                    merged_risk = RiskAssessment(
                        risk_score=min(llm_score, 10.0),
                        risk_level=llm_level if llm_level in ("LOW", "MEDIUM", "HIGH", "CRITICAL") else merged_risk.risk_level,
                        explanation=llm_explanation or merged_risk.explanation,
                        key_risk_factors=list(merged_risk.key_risk_factors) + [f"[LLM] {f}" for f in llm_factors if isinstance(f, str)],
                    )
            except (ValueError, TypeError) as e:
                logger.debug("解析 LLM 风险评估失败: %s", e)

        # 如果有新边，重新聚类
        if llm_new_edges_count > 0:
            merged_clusters = self._build_clusters(merged_nodes, merged_edges)

        merged_metadata["llm_new_edges"] = llm_new_edges_count

        # 重新生成通俗总结
        explanation_summary = _generate_explanation_summary(
            merged_nodes, merged_edges, merged_risk, merged_clusters
        )

        return SensitiveKnowledgeGraph(
            nodes=merged_nodes,
            edges=merged_edges,
            risk_assessment=merged_risk,
            clusters=merged_clusters,
            build_mode="LLM_ENHANCED",
            metadata=merged_metadata,
            user_modifications=list(rule_graph.user_modifications),
            explanation_summary=explanation_summary,
        )

    @staticmethod
    def _resolve_llm_node_ref(
        ref: str,
        finding_id_map: dict[str, GraphNode],
        text_map: dict[str, GraphNode],
    ) -> GraphNode | None:
        """尝试将 LLM 返回的节点引用解析为已有的 GraphNode。

        优先按 finding_id 精确匹配，其次按 matched_text 模糊匹配。

        Args:
            ref: LLM 返回的节点引用（可能是 finding_id 或 matched_text）。
            finding_id_map: finding_id → GraphNode 映射。
            text_map: original_text → GraphNode 映射。

        Returns:
            匹配到的 GraphNode，未匹配返回 None。
        """
        if not ref:
            return None

        ref = str(ref).strip()

        # 精确匹配 finding_id
        if ref in finding_id_map:
            return finding_id_map[ref]

        # 精确匹配 original_text
        if ref in text_map:
            return text_map[ref]

        # 模糊匹配：ref 是否是某个 original_text 的子串或反过来
        for text, node in text_map.items():
            if ref in text or text in ref:
                return node

        return None

    # ------------------------------------------------------------------
    # 用户交互式自定义
    # ------------------------------------------------------------------

    def add_user_custom_finding(
        self,
        graph: SensitiveKnowledgeGraph,
        user_finding: dict,
    ) -> SensitiveKnowledgeGraph:
        """用户手动标记一条新的敏感信息，更新图谱。

        当自动检测未发现但用户认为某内容是敏感的时，调用此方法。
        操作线程安全，会记录审计日志。

        Args:
            graph: 现有图谱。
            user_finding: 用户标记信息字典，包含以下字段：
                - "matched_text": str — 用户标记的文本（必填）
                - "category": str — 用户选择的分类，可以是内置或企业自定义（必填）
                - "sensitivity_level": str — 用户判定的级别（默认 "MEDIUM"）
                - "user_note": str — 用户的补充说明（可选）

        Returns:
            更新后的图谱。
        """
        with self._lock:
            matched_text = user_finding.get("matched_text", "").strip()
            category = user_finding.get("category", "其他")
            sensitivity_level = user_finding.get("sensitivity_level", "MEDIUM")
            user_note = user_finding.get("user_note", "")

            if not matched_text:
                logger.warning("用户自定义 finding 的 matched_text 为空，跳过")
                return graph

            # 创建节点
            node_id = f"node_{uuid.uuid4().hex[:8]}"
            entity_type = _category_to_entity_type(category)
            # 也检查企业自定义映射
            if entity_type == "OTHER" and category in self._custom_category_type_map:
                entity_type = self._custom_category_type_map[category]

            label = desensitize_text(matched_text, category)

            node = GraphNode(
                id=node_id,
                label=label,
                entity_type=entity_type,
                sensitivity_level=sensitivity_level,
                category=category,
                original_text=matched_text,
                finding_id=f"user_{uuid.uuid4().hex[:8]}",
                metadata={"source": "user_custom"},
                user_confirmed=True,
                user_note=user_note,
            )

            # 检查是否命中企业自定义分类
            is_custom = any(
                cat_def.get("name", "") == category
                for cat_def in self._custom_categories
            )
            if is_custom:
                node.is_custom_defined = True
                node.custom_category_name = category

            # 填充解释性文本（使用虚拟 SensitiveFinding）
            dummy_finding = SensitiveFinding(
                finding_id=node.finding_id or "",
                rule_id="user_custom",
                rule_name="用户自定义",
                category=category,
                sensitivity_level=sensitivity_level,
                confidence=1.0,
                source="user_custom",
                matched_text=matched_text,
                context_before="",
                context_after="",
                location=ContentLocation(block_index=-1, char_offset_start=0, char_offset_end=0),
                description=user_note or f"用户手动标记的{category}类敏感信息",
            )
            self._fill_node_explanations(node, dummy_finding)

            graph.nodes.append(node)

            # 尝试与现有节点建立边（基于类型匹配）
            node_map = {nd.id: nd for nd in graph.nodes}
            for existing_node in graph.nodes:
                if existing_node.id == node_id:
                    continue
                # 简单规则：如果新节点和已有节点类型不同且都是高敏感度，建立关联
                if (
                    existing_node.entity_type != node.entity_type
                    and _LEVEL_ORDER.get(existing_node.sensitivity_level, 0) >= 2
                    and _LEVEL_ORDER.get(node.sensitivity_level, 0) >= 2
                ):
                    amp_desc, amp_level = _get_combined_risk_level(
                        node.entity_type, existing_node.entity_type
                    )
                    if amp_desc:
                        new_edge = GraphEdge(
                            source=min(node.id, existing_node.id),
                            target=max(node.id, existing_node.id),
                            relation="用户标记关联",
                            description=f"用户标记的敏感信息与已有{existing_node.entity_type}类信息存在风险组合",
                            weight=0.8,
                            inferred_by="RULE",
                            risk_amplification=amp_desc,
                            combined_risk_level=amp_level,
                        )
                        graph.edges.append(new_edge)

            # 记录审计日志
            modification_record = {
                "action": "add",
                "node_id": node_id,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "note": user_note,
                "category": category,
                "matched_text_preview": matched_text[:30] + ("..." if len(matched_text) > 30 else ""),
            }
            graph.user_modifications.append(modification_record)

            # 重新生成总结
            graph.explanation_summary = _generate_explanation_summary(
                graph.nodes, graph.edges, graph.risk_assessment, graph.clusters
            )

            logger.info("用户添加了自定义敏感信息节点: %s (category=%s)", node_id, category)
            return graph

    def confirm_finding(
        self,
        graph: SensitiveKnowledgeGraph,
        node_id: str,
        confirmed: bool,
        user_note: str = "",
    ) -> SensitiveKnowledgeGraph:
        """用户确认或拒绝一条自动检测结果。

        操作线程安全，会记录审计日志。

        Args:
            graph: 现有图谱。
            node_id: 要确认/拒绝的节点 ID。
            confirmed: True=确认敏感，False=标记为误报。
            user_note: 用户备注。

        Returns:
            更新后的图谱。
        """
        with self._lock:
            target_node: GraphNode | None = None
            for node in graph.nodes:
                if node.id == node_id:
                    target_node = node
                    break

            if target_node is None:
                logger.warning("确认/拒绝操作失败：未找到节点 %s", node_id)
                return graph

            target_node.user_confirmed = confirmed
            if user_note:
                target_node.user_note = user_note

            action = "confirm" if confirmed else "reject"
            modification_record = {
                "action": action,
                "node_id": node_id,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "note": user_note,
                "previous_level": target_node.sensitivity_level,
            }
            graph.user_modifications.append(modification_record)

            logger.info("用户%s了节点: %s (confirmed=%s)", action, node_id, confirmed)
            return graph

    def update_custom_categories_in_graph(
        self,
        graph: SensitiveKnowledgeGraph,
        custom_categories: list[dict],
    ) -> SensitiveKnowledgeGraph:
        """当企业自定义分类更新时，重新评估图谱中的节点。

        新增的企业分类可能匹配到之前未识别的节点。
        操作线程安全。

        Args:
            graph: 现有图谱。
            custom_categories: 新的企业自定义分类列表，每个 dict 包含：
                - "name": str — 分类名称
                - "description": str — 分类描述
                - "sensitivity_level": str — 敏感级别
                - "keywords": list[str] — 关键词列表
                - "explanation": dict | str — 解释信息

        Returns:
            更新后的图谱。
        """
        with self._lock:
            # 更新内部自定义分类
            self._custom_categories = custom_categories
            self._custom_category_type_map.clear()
            for cat_def in self._custom_categories:
                cat_name = cat_def.get("name", "")
                if cat_name:
                    etype = cat_def.get("entity_type", "ENTERPRISE_SECRET")
                    self._custom_category_type_map[cat_name] = etype

            updated_count = 0
            for node in graph.nodes:
                # 对每个节点检查是否新匹配了企业自定义分类
                for cat_def in custom_categories:
                    cat_name = cat_def.get("name", "")
                    keywords = cat_def.get("keywords", [])
                    if not keywords or not isinstance(keywords, list):
                        continue

                    text_lower = node.original_text.lower()
                    matched = any(
                        isinstance(kw, str) and kw.lower() in text_lower
                        for kw in keywords
                    )

                    if matched and not node.is_custom_defined:
                        node.is_custom_defined = True
                        node.custom_category_name = cat_name
                        # 更新 entity_type
                        new_etype = cat_def.get("entity_type", "ENTERPRISE_SECRET")
                        node.entity_type = new_etype
                        # 更新解释文本
                        explanation = cat_def.get("explanation", "")
                        if isinstance(explanation, dict):
                            node.why_sensitive = explanation.get("why_sensitive", node.why_sensitive)
                            node.risk_if_leaked = explanation.get("risk_if_leaked", node.risk_if_leaked)
                            node.recommended_action = explanation.get("recommended_action", node.recommended_action)
                        elif isinstance(explanation, str) and explanation:
                            node.why_sensitive = explanation
                        # 更新敏感级别（如果自定义分类指定了更高级别）
                        custom_level = cat_def.get("sensitivity_level", "")
                        if custom_level and _LEVEL_ORDER.get(custom_level, 0) > _LEVEL_ORDER.get(node.sensitivity_level, 0):
                            node.sensitivity_level = custom_level
                        updated_count += 1
                        break  # 一个节点只匹配一个自定义分类

            if updated_count > 0:
                # 重新填充边的解释性字段
                node_map = {nd.id: nd for nd in graph.nodes}
                for edge in graph.edges:
                    src = node_map.get(edge.source)
                    tgt = node_map.get(edge.target)
                    if src and tgt:
                        self._fill_edge_explanations(edge, src, tgt)

                # 重新生成总结
                graph.explanation_summary = _generate_explanation_summary(
                    graph.nodes, graph.edges, graph.risk_assessment, graph.clusters
                )

            logger.info("企业自定义分类更新完成，%d 个节点受到影响", updated_count)
            return graph


# ======================================================================
# 导出列表
# ======================================================================

__all__ = [
    # 数据结构
    "GraphNode",
    "GraphEdge",
    "RiskAssessment",
    "SensitiveKnowledgeGraph",
    # 核心类
    "KnowledgeGraphBuilder",
    # 辅助函数
    "desensitize_text",
    "_normalize_finding",
    "_normalize_findings",
    # 内置常量（供外部扩展使用）
    "_BUILTIN_EXPLANATIONS",
    "_RISK_AMPLIFICATION_RULES",
    "_CATEGORY_TYPE_MAP",
    "_LEVEL_SCORE_MAP",
    "_LEVEL_ORDER",
]
