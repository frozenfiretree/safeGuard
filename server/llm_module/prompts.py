"""LLM 语义检测模块 —— Prompt 模板管理。

本模块是敏感信息检测与溯源系统中 LLM 检测模块的核心组件，
负责管理所有 Prompt 模板的定义、版本控制、组装和模型适配。

增强版：新增 explanation 字段、企业自定义解释注入、解释性 Prompt 模板。

Version: 2.0.0
Author: llm_module team
"""
from __future__ import annotations

import copy
import json
import logging
from pathlib import Path

from .config import LLMConfig, PROVIDER_QWEN, PROVIDER_DEEPSEEK, PROVIDER_LOCAL

logger = logging.getLogger(__name__)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 版本常量
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DETECTION_PROMPT_VERSION: str = "2.0.0"
KG_PROMPT_VERSION: str = "1.0.0"
EXPLANATION_PROMPT_VERSION: str = "1.0.0"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 3.1 敏感信息分类体系（增强版：含 explanation 字段）
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SENSITIVITY_CATEGORIES: list[dict] = [
    {
        "category": "个人身份信息 (PII)",
        "sub_categories": [
            "身份证号/护照号/军官证号",
            "姓名+证件/手机/地址组合",
            "生物特征信息",
        ],
        "description": "可直接或组合识别自然人身份的信息",
        "examples": ["身份证号: 310101199001011234", "指纹模板数据"],
        "explanation": (
            "身份证号、护照号等可直接定位到特定自然人，泄露后可能导致身份盗用、"
            "精准诈骗、冒名开户等严重后果。当姓名+证件号+手机号组合出现时，风险"
            "指数倍增——攻击者可构建完整的个人画像，实施更精密的社会工程攻击。"
        ),
    },
    {
        "category": "联系方式",
        "sub_categories": [
            "手机号/固话",
            "电子邮箱",
            "详细地址(精确到门牌号)",
        ],
        "description": "可直接联系到个人的通信信息",
        "examples": ["13800138000", "zhangsan@corp.com", "XX路100号3栋502"],
        "explanation": (
            "手机号、邮箱和详细地址可用于精准骚扰、钓鱼攻击和人肉搜索。单独的"
            "手机号风险为中等，但当手机号与姓名、身份证号或住址组合时，可被用于"
            "SIM卡克隆攻击、精准诈骗电话以及线下跟踪。大量联系方式泄露还会导致"
            "企业面临违反《个人信息保护法》的合规风险。"
        ),
    },
    {
        "category": "金融信息",
        "sub_categories": [
            "银行卡号/账户信息",
            "工资/薪酬数据",
            "财务报表(利润/营收/成本)",
            "投资/融资/并购信息",
            "报价单/竞标价格",
        ],
        "description": "涉及资金、财务和商业交易的敏感数据",
        "examples": ["卡号6222021234567890123", "月薪25000元", "Q3营收2.3亿"],
        "explanation": (
            "银行卡号等可直接用于金融欺诈或盗刷；个人薪资泄露会引发内部矛盾和"
            "人才流失；企业财务报表（尤其是未公开的营收、利润数据）泄露可能构成"
            "证券违规（内幕信息外泄），给企业带来监管处罚。当银行卡号+持卡人姓名"
            "+手机号组合出现时，可直接发起资金盗取攻击。"
        ),
    },
    {
        "category": "企业核心机密",
        "sub_categories": [
            "未公开产品/项目信息(代号/计划/进度)",
            "技术方案/专利草案/核心算法",
            "客户名单/供应商清单/合作伙伴",
            "商业策略/市场计划/竞争分析",
            "组织架构调整/人事变动计划",
        ],
        "description": "企业未公开的核心业务与战略信息",
        "examples": ["项目代号'凤凰'预计Q4上线", "与XX公司独家供货协议"],
        "explanation": (
            "项目代号和产品计划泄露使竞争对手可提前布局，专利草案泄露可能丧失"
            "知识产权优先权；客户名单和供应商清单是核心商业资产，泄露将直接导致"
            "客户被挖角和供应链被干扰。当项目信息+预算+合作方+时间节点同时出现时，"
            "构成完整的商业机密链条，泄露后损失可能达数千万甚至更高。"
        ),
    },
    {
        "category": "密级与合规",
        "sub_categories": [
            "明确标注的密级文档(绝密/机密/秘密/内部)",
            "法律合同关键条款",
            "审计报告/合规检查结果",
        ],
        "description": "带有明确保密等级或合规约束的内容",
        "examples": ["【机密】本文件限内部传阅", "违约金条款: 不低于合同额30%"],
        "explanation": (
            "明确标注密级的文档受法律法规严格保护，泄露可能触犯《保密法》并招致"
            "刑事追责；法律合同条款泄露将严重削弱企业谈判地位；审计报告中的合规"
            "漏洞一旦曝光，可能引发监管调查和声誉危机。密级标记+具体内容组合出现"
            "时，说明机密信息已实质性泄露，风险从'标记泄露'升级为'内容泄露'。"
        ),
    },
    {
        "category": "账号凭证",
        "sub_categories": [
            "密码/API密钥/Token",
            "数据库连接串/服务器地址+端口",
            "私钥/证书",
        ],
        "description": "可用于身份验证或系统访问的凭证信息",
        "examples": ["password=Admin@123", "mongodb://root:pass@10.0.1.5:27017"],
        "explanation": (
            "密码和API密钥泄露可导致系统被未授权访问，数据库连接串泄露则可能"
            "导致整个数据库被拖取。一个管理员密码的泄露可能波及整个IT基础设施。"
            "当凭证+对应的服务地址/端口组合出现时，攻击者无需任何额外侦查即可"
            "直接发起入侵——这是最高优先级的安全事件。"
        ),
    },
    {
        "category": "网络与基础设施",
        "sub_categories": [
            "内网IP段/网络拓扑",
            "服务器配置/部署架构",
            "安全策略/防火墙规则",
        ],
        "description": "内部网络架构和安全配置信息",
        "examples": ["核心交换机10.0.0.0/8网段", "防火墙放行规则: 允许3306入站"],
        "explanation": (
            "内网IP段和网络拓扑泄露为攻击者提供内网渗透的地图；防火墙规则泄露"
            "等于公开了安全防线的薄弱环节。单独的IP地址风险有限，但当IP段+端口+"
            "防火墙规则+部署架构组合出现时，攻击者可精确绘制攻击路径，将渗透测试"
            "难度从'黑盒'降为'白盒'，企业面临的入侵风险呈指数级上升。"
        ),
    },
]


def _build_categories_text() -> str:
    """将分类体系格式化为紧凑文本，供 Prompt 嵌入。"""
    lines: list[str] = []
    for i, cat in enumerate(SENSITIVITY_CATEGORIES, 1):
        lines.append(f"{i}. {cat['category']}：{cat['description']}")
        for sc in cat["sub_categories"]:
            lines.append(f"   - {sc}")
        lines.append(f"   示例：{'；'.join(cat['examples'])}")
        # 新增：嵌入 explanation 为检测提供上下文参考
        if cat.get("explanation"):
            lines.append(f"   敏感原因：{cat['explanation']}")
    return "\n".join(lines)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 3.2 敏感信息检测 System Prompt
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SENSITIVE_DETECTION_SYSTEM_PROMPT: str = f"""\
你是一位资深信息安全审计专家，专精于敏感信息识别与分类。你的任务是：分析用户提供的文本，识别其中所有敏感信息，并以 JSON 格式返回结构化的分析结果。

## 敏感信息分类体系

{_build_categories_text()}

## 输出 JSON Schema

你必须严格按以下 JSON 结构返回结果，不要增减字段：
```json
{{
  "has_sensitive": true,
  "findings": [
    {{
      "category": "分类名（7大类之一）",
      "sub_category": "对应子类名",
      "sensitivity_level": "LOW|MEDIUM|HIGH|CRITICAL",
      "confidence": 0.85,
      "matched_text": "原文精确片段",
      "start_pos": 0,
      "end_pos": 10,
      "reasoning": "1-2句判断依据",
      "related_entities": ["相关实体"]
    }}
  ],
  "summary": "整体分析摘要，1-2句话"
}}
```

### 字段约束
- has_sensitive (bool): 是否存在敏感信息。
- findings (array): 敏感项列表，无则为空数组 []。
- category (string): 必须是上述7大类之一的类名。
- sub_category (string): 该大类下的子类名。
- sensitivity_level (string): 仅允许 "LOW" / "MEDIUM" / "HIGH" / "CRITICAL"。
- confidence (float): 范围 [0.0, 1.0]，精确到两位小数。
- matched_text (string): 必须是输入原文中的精确子串，不可改写。
- start_pos (int): 匹配文本在输入中的起始字符偏移（从0开始）。
- end_pos (int): 匹配文本的结束字符偏移（不含该位置）。
- reasoning (string): 1-2句话解释判断依据。
- related_entities (array[string]): 相关实体名（人名/组织/项目等），可为空数组。
- summary (string): 整体摘要。

## 置信度评分标准
- 0.9-1.0: 确定性极高——明文密码、完整身份证号、密级标记等。
- 0.7-0.89: 高度疑似——疑似项目代号+时间、部分脱敏证件号+姓名等。
- 0.5-0.69: 可能敏感——需更多上下文确认，如模糊金额数据。
- 0.3-0.49: 轻微嫌疑——可能是公开信息。

## 分析规则
1. 逐段扫描输入文本，不要遗漏任何段落。
2. 同一段文本中的多个敏感项必须分别报告，每个 finding 对应一个敏感项。
3. matched_text 必须是输入原文的精确子串，可通过 start_pos/end_pos 定位。
4. 无敏感信息时返回 has_sensitive=false 和空 findings 数组。
5. 避免过度报告：已公开的公司名、产品名不算敏感。
6. 注意组合敏感性：单独姓名不算高敏感，但姓名+身份证+手机的组合属于高敏感。
7. 若提供了规则引擎预筛结果(rule_hints)，请重点验证并补充 LLM 独立发现的语义层敏感信息。
8. 规则引擎擅长结构化模式（如身份证、手机号），LLM 应侧重语义理解层面（如项目代号、商业策略）。

## 重要约束
※ 你只能输出合法 JSON，不要输出任何 JSON 以外的文字或 Markdown 标记。
※ 直接以 {{ 开头，以 }} 结尾。
"""

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 3.3 知识图谱构建 System Prompt
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
KNOWLEDGE_GRAPH_SYSTEM_PROMPT: str = """\
你是一位信息安全分析师，擅长分析敏感数据之间的关联关系与风险评估。你的任务是：根据已检测到的敏感信息及其原始文本，构建一个关系图谱并给出风险评估，以 JSON 格式返回结果。

## 输出 JSON Schema

```json
{
  "nodes": [
    {
      "id": "node_1",
      "label": "节点描述",
      "type": "分类名",
      "sensitivity_level": "HIGH"
    }
  ],
  "edges": [
    {
      "source": "node_1",
      "target": "node_2",
      "relation": "关系类型",
      "description": "关系说明"
    }
  ],
  "risk_assessment": {
    "overall_risk_score": 8.5,
    "risk_level": "LOW|MEDIUM|HIGH|CRITICAL",
    "explanation": "综合风险说明",
    "key_risk_factors": ["风险因素1", "风险因素2"]
  }
}
```

### 字段约束
- nodes: 每个敏感发现对应一个节点，id 格式为 node_N。
- edges: 节点之间的关联关系。source/target 引用节点 id。
- risk_assessment.overall_risk_score: 0.0-10.0 的综合风险评分。
- risk_assessment.risk_level: 仅允许 "LOW"/"MEDIUM"/"HIGH"/"CRITICAL"。

## 关系推断指引
1. 同一人信息链：PII + 联系方式 + 金融信息 → 高风险（完整个人画像泄露）。
2. 凭证组合：用户名 + 密码 → 极高风险（可直接利用）。
3. 批量数据：大量同类敏感项 → 数据泄露风险。
4. 业务关联：项目代号 + 报价 + 竞标方 → 商业机密泄露风险。

## 重要约束
※ 你只能输出合法 JSON，不要输出任何 JSON 以外的文字或 Markdown 标记。
※ 直接以 { 开头，以 } 结尾。
"""

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 3.3b 敏感信息解释 System Prompt（新增）
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EXPLANATION_SYSTEM_PROMPT: str = """\
你是一位信息安全顾问，擅长用通俗易懂的语言向企业管理人员解释敏感信息检测结果。

## 你的任务
根据提供的敏感信息检测结果和原始文本上下文，为每一条敏感发现生成面向业务人员的解释文本。

## 输出 JSON Schema
```json
{
  "explanations": [
    {
      "finding_id": "对应的发现ID",
      "why_sensitive": "为什么这条信息是敏感的（1-2句，通俗易懂）",
      "risk_if_leaked": "如果泄露会带来什么风险（1-2句，具体场景）",
      "related_context": "该信息与文档中其他信息的关联说明",
      "recommended_action": "建议的处理措施（如脱敏/加密/限制传播等）"
    }
  ],
  "overall_explanation": "整体风险的通俗说明（2-3句话）"
}
```

## 解释规则
1. 使用非技术语言，假设读者是不了解信息安全的业务人员。
2. 解释必须具体，不要用"可能造成损失"这种笼统说法，要说明具体场景。
3. 关注信息之间的组合风险——多条信息组合可能比单条更危险。
4. 如果有企业自定义分类的解释模板，优先使用模板内容并适当补充。

※ 你只能输出合法 JSON，直接以 { 开头，以 } 结尾。
"""

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 3.4 企业自定义补充模板（增强版）
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ENTERPRISE_SUPPLEMENT_TEMPLATE: str = """\

## 企业自定义敏感分类（优先级高于通用分类）

{enterprise_categories}

## 企业自定义敏感关键词

以下关键词出现时应重点关注：{enterprise_keywords}

## 企业自定义分类的敏感原因说明

{enterprise_explanations}

## 企业附加检测指令

{enterprise_additional_instructions}
"""

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 3.5 Few-Shot 示例
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FEW_SHOT_EXAMPLES: list[dict] = [
    # ── 示例 1：员工花名册（PII + 金融） ──
    {
        "input": (
            "员工花名册-技术部（2024Q3）\n"
            "张三, 身份证: 310101199003071234, 手机: 13812345678\n"
            "岗位: 高级工程师, 月薪: 35000元, 工行卡号: 6222021234567890123\n"
            "李四, 身份证: 440305198811223456, 手机: 13698765432\n"
            "岗位: 测试主管, 月薪: 28000元"
        ),
        "expected_output": json.dumps(
            {
                "has_sensitive": True,
                "findings": [
                    {
                        "category": "个人身份信息 (PII)",
                        "sub_category": "身份证号/护照号/军官证号",
                        "sensitivity_level": "CRITICAL",
                        "confidence": 0.98,
                        "matched_text": "身份证: 310101199003071234",
                        "start_pos": 21,
                        "end_pos": 45,
                        "reasoning": "完整18位身份证号，可直接识别个人身份",
                        "related_entities": ["张三", "技术部"],
                    },
                    {
                        "category": "联系方式",
                        "sub_category": "手机号/固话",
                        "sensitivity_level": "MEDIUM",
                        "confidence": 0.95,
                        "matched_text": "手机: 13812345678",
                        "start_pos": 47,
                        "end_pos": 62,
                        "reasoning": "完整11位手机号，与姓名和身份证关联，构成个人信息组合",
                        "related_entities": ["张三"],
                    },
                    {
                        "category": "金融信息",
                        "sub_category": "工资/薪酬数据",
                        "sensitivity_level": "HIGH",
                        "confidence": 0.96,
                        "matched_text": "月薪: 35000元",
                        "start_pos": 78,
                        "end_pos": 90,
                        "reasoning": "明确的个人薪资数据，属于高度敏感的金融隐私",
                        "related_entities": ["张三", "技术部"],
                    },
                    {
                        "category": "金融信息",
                        "sub_category": "银行卡号/账户信息",
                        "sensitivity_level": "CRITICAL",
                        "confidence": 0.97,
                        "matched_text": "工行卡号: 6222021234567890123",
                        "start_pos": 92,
                        "end_pos": 117,
                        "reasoning": "完整银行卡号，可用于金融欺诈",
                        "related_entities": ["张三"],
                    },
                    {
                        "category": "个人身份信息 (PII)",
                        "sub_category": "身份证号/护照号/军官证号",
                        "sensitivity_level": "CRITICAL",
                        "confidence": 0.98,
                        "matched_text": "身份证: 440305198811223456",
                        "start_pos": 122,
                        "end_pos": 146,
                        "reasoning": "完整18位身份证号",
                        "related_entities": ["李四", "技术部"],
                    },
                    {
                        "category": "金融信息",
                        "sub_category": "工资/薪酬数据",
                        "sensitivity_level": "HIGH",
                        "confidence": 0.96,
                        "matched_text": "月薪: 28000元",
                        "start_pos": 178,
                        "end_pos": 190,
                        "reasoning": "明确的个人薪资数据",
                        "related_entities": ["李四", "技术部"],
                    },
                ],
                "summary": "该文本为员工花名册，包含6条敏感信息：2条身份证号(CRITICAL)、1条手机号(MEDIUM)、2条薪资数据(HIGH)、1条银行卡号(CRITICAL)，整体风险极高。",
            },
            ensure_ascii=False,
        ),
    },
    # ── 示例 2：企业机密项目计划 ──
    {
        "input": (
            "【内部】项目代号\u201c凤凰计划\u201d启动会纪要\n"
            "预算: 1500万元，与华芯科技独家合作，Q4完成一期交付\n"
            "竞标对手分析: 蓝海系统报价约1200万，技术方案弱于我方\n"
            "附: 核心算法架构图见附件（限研发部传阅）"
        ),
        "expected_output": json.dumps(
            {
                "has_sensitive": True,
                "findings": [
                    {
                        "category": "密级与合规",
                        "sub_category": "明确标注的密级文档(绝密/机密/秘密/内部)",
                        "sensitivity_level": "HIGH",
                        "confidence": 0.92,
                        "matched_text": "【内部】",
                        "start_pos": 0,
                        "end_pos": 4,
                        "reasoning": "文档明确标注'内部'密级",
                        "related_entities": [],
                    },
                    {
                        "category": "企业核心机密",
                        "sub_category": "未公开产品/项目信息(代号/计划/进度)",
                        "sensitivity_level": "HIGH",
                        "confidence": 0.90,
                        "matched_text": "项目代号\u201c凤凰计划\u201d启动会纪要",
                        "start_pos": 4,
                        "end_pos": 19,
                        "reasoning": "未公开项目代号与计划节点",
                        "related_entities": ["凤凰计划"],
                    },
                    {
                        "category": "金融信息",
                        "sub_category": "投资/融资/并购信息",
                        "sensitivity_level": "HIGH",
                        "confidence": 0.88,
                        "matched_text": "预算: 1500万元",
                        "start_pos": 20,
                        "end_pos": 31,
                        "reasoning": "未公开的项目预算金额",
                        "related_entities": ["凤凰计划"],
                    },
                    {
                        "category": "企业核心机密",
                        "sub_category": "客户名单/供应商清单/合作伙伴",
                        "sensitivity_level": "HIGH",
                        "confidence": 0.85,
                        "matched_text": "与华芯科技独家合作",
                        "start_pos": 32,
                        "end_pos": 41,
                        "reasoning": "未公开的独家合作关系",
                        "related_entities": ["华芯科技", "凤凰计划"],
                    },
                    {
                        "category": "企业核心机密",
                        "sub_category": "商业策略/市场计划/竞争分析",
                        "sensitivity_level": "HIGH",
                        "confidence": 0.88,
                        "matched_text": "竞标对手分析: 蓝海系统报价约1200万，技术方案弱于我方",
                        "start_pos": 53,
                        "end_pos": 82,
                        "reasoning": "包含竞争对手报价和技术评估的竞争情报",
                        "related_entities": ["蓝海系统"],
                    },
                    {
                        "category": "企业核心机密",
                        "sub_category": "技术方案/专利草案/核心算法",
                        "sensitivity_level": "HIGH",
                        "confidence": 0.85,
                        "matched_text": "核心算法架构图见附件（限研发部传阅）",
                        "start_pos": 86,
                        "end_pos": 104,
                        "reasoning": "提及核心算法且限定传阅范围",
                        "related_entities": ["研发部"],
                    },
                ],
                "summary": "该文本为内部项目启动会纪要，包含6条敏感信息：1条密级标注、3条企业核心机密、1条金融信息、1条竞争分析，整体风险高。",
            },
            ensure_ascii=False,
        ),
    },
    # ── 示例 3：无敏感信息的普通公文 ──
    {
        "input": (
            "关于组织2024年秋季团建活动的通知\n"
            "各部门同事：公司定于10月15日（周六）举办秋季团建活动。\n"
            "地点：市郊阳光农庄，活动内容包括拓展训练与烧烤晚会。\n"
            "请各部门于10月10日前统计参加人数，报行政部汇总。"
        ),
        "expected_output": json.dumps(
            {
                "has_sensitive": False,
                "findings": [],
                "summary": "该文本为普通团建活动通知，不包含任何敏感信息。",
            },
            ensure_ascii=False,
        ),
    },
]

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DeepSeek-reasoner 专用 JSON 强化约束（追加到 system prompt 末尾）
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
_REASONER_JSON_CONSTRAINT: str = """\

【关键约束】你必须且只能输出一个合法的 JSON 对象。不要输出任何 JSON 以外的文字、解释或 Markdown 标记（包括 ```json 代码块标记）。你的完整回复必须直接以 { 开头，以 } 结尾。不要在 JSON 之前或之后添加任何内容。请再次确认：仅输出 JSON。"""

# Qwen3 关闭思考模式的前缀
_QWEN_NO_THINK_PREFIX: str = "/no_think\n"

# ── 解释 Prompt 最大原始文本截断长度（字符数） ──
_EXPLANATION_MAX_TEXT_CHARS: int = 6000


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 3.6 Prompt 组装函数
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def build_detection_prompt(
    text_content: str,
    rule_hints: list[dict] | None = None,
    enterprise_config: dict | None = None,
) -> list[dict]:
    """组装敏感信息检测的完整 messages 列表（OpenAI 格式）。

    按 system → few-shot (user/assistant 交替) → user 顺序组装。
    企业自定义配置和规则提示会被注入到对应位置。
    """
    # 1. 构建 system message
    system_content = SENSITIVE_DETECTION_SYSTEM_PROMPT

    if enterprise_config:
        categories_text = enterprise_config.get("categories", "无")
        keywords_text = enterprise_config.get("keywords", "无")
        supplement_text = enterprise_config.get("supplement", "无")
        explanations_text = enterprise_config.get("explanations", "无")
        system_content += ENTERPRISE_SUPPLEMENT_TEMPLATE.format(
            enterprise_categories=categories_text,
            enterprise_keywords=keywords_text,
            enterprise_explanations=explanations_text,
            enterprise_additional_instructions=supplement_text,
        )

    messages: list[dict] = [{"role": "system", "content": system_content}]

    # 2. 注入 few-shot 示例（user/assistant 交替）
    for example in FEW_SHOT_EXAMPLES:
        messages.append({"role": "user", "content": example["input"]})
        messages.append({"role": "assistant", "content": example["expected_output"]})

    # 3. 构建最终 user message
    user_content = f"请分析以下文本中的敏感信息，以 JSON 格式返回结果：\n\n{text_content}"

    if rule_hints:
        hints_json = json.dumps(rule_hints, ensure_ascii=False, indent=None)
        user_content += (
            f"\n\n[规则引擎预筛结果(rule_hints)，请参考验证并补充语义发现]:\n{hints_json}"
        )

    messages.append({"role": "user", "content": user_content})

    return messages


def build_knowledge_graph_prompt(
    text_content: str,
    findings: list[dict],
) -> list[dict]:
    """组装知识图谱构建的 messages 列表。

    将原始文本和检测阶段的 findings 一起提供给 LLM，
    让其分析关联关系并构建图谱。
    """
    messages: list[dict] = [
        {"role": "system", "content": KNOWLEDGE_GRAPH_SYSTEM_PROMPT}
    ]

    findings_json = json.dumps(findings, ensure_ascii=False, indent=2)
    user_content = (
        f"请根据以下原始文本和已检测到的敏感信息，构建关系图谱并给出风险评估，以 JSON 格式返回。\n\n"
        f"## 原始文本\n{text_content}\n\n"
        f"## 已检测到的敏感信息\n{findings_json}"
    )

    messages.append({"role": "user", "content": user_content})

    return messages


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 3.7 PromptManager 类（增强版）
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class PromptManager:
    """Prompt 模板统一管理器。

    管理所有 Prompt 模板的版本、模型适配、企业自定义和热更新。
    是外部调用方的统一入口。

    增强功能：
    - 企业自定义分类的 explanation 注入
    - 解释性 Prompt 构建（build_explanation_messages）
    """

    def __init__(self, config: LLMConfig) -> None:
        """初始化 PromptManager。

        Args:
            config: LLM 配置对象，决定模型适配策略。
        """
        self.config = config
        self._is_reasoner: bool = (
            config.provider == PROVIDER_DEEPSEEK
            and config.model == "deepseek-reasoner"
        )
        self._is_qwen: bool = config.provider == PROVIDER_QWEN
        self._enterprise_config: dict | None = self._build_enterprise_config()

        # 可热更新的自定义模板（优先级高于内置模板）
        self._custom_detection_prompt: str | None = None
        self._custom_kg_prompt: str | None = None
        self._custom_explanation_prompt: str | None = None

        logger.info(
            "PromptManager 初始化完成 | provider=%s model=%s is_reasoner=%s",
            config.provider,
            config.model,
            self._is_reasoner,
        )

    def build_detection_messages(
        self,
        text_content: str,
        rule_hints: list[dict] | None = None,
    ) -> list[dict]:
        """构建敏感检测的 messages（对外主入口）。

        自动处理模型适配（Qwen3 /no_think、DeepSeek-reasoner JSON 强化）
        和企业自定义配置的注入。
        """
        # 确定 system prompt 内容
        base_prompt = (
            self._custom_detection_prompt
            if self._custom_detection_prompt is not None
            else SENSITIVE_DETECTION_SYSTEM_PROMPT
        )

        system_content = self._apply_model_adaptations(base_prompt)

        # 注入企业自定义
        if self._enterprise_config:
            system_content += ENTERPRISE_SUPPLEMENT_TEMPLATE.format(
                enterprise_categories=self._enterprise_config.get("categories", "无"),
                enterprise_keywords=self._enterprise_config.get("keywords", "无"),
                enterprise_explanations=self._enterprise_config.get("explanations", "无"),
                enterprise_additional_instructions=self._enterprise_config.get(
                    "supplement", "无"
                ),
            )

        messages: list[dict] = [{"role": "system", "content": system_content}]

        # few-shot 示例（reasoner 模型减少示例数量以节省 token）
        examples = FEW_SHOT_EXAMPLES if not self._is_reasoner else FEW_SHOT_EXAMPLES[:2]
        for example in examples:
            messages.append({"role": "user", "content": example["input"]})
            messages.append({"role": "assistant", "content": example["expected_output"]})

        # 最终 user message
        user_content = f"请分析以下文本中的敏感信息，以 JSON 格式返回结果：\n\n{text_content}"
        if rule_hints:
            hints_json = json.dumps(rule_hints, ensure_ascii=False, indent=None)
            user_content += (
                f"\n\n[规则引擎预筛结果(rule_hints)，请参考验证并补充语义发现]:\n{hints_json}"
            )
        messages.append({"role": "user", "content": user_content})

        return messages

    def build_knowledge_graph_messages(
        self,
        text_content: str,
        findings: list[dict],
    ) -> list[dict]:
        """构建知识图谱的 messages。

        自动适配模型差异并注入已检测的 findings。
        """
        base_prompt = (
            self._custom_kg_prompt
            if self._custom_kg_prompt is not None
            else KNOWLEDGE_GRAPH_SYSTEM_PROMPT
        )

        system_content = self._apply_model_adaptations(base_prompt)

        messages: list[dict] = [{"role": "system", "content": system_content}]

        findings_json = json.dumps(findings, ensure_ascii=False, indent=2)
        user_content = (
            f"请根据以下原始文本和已检测到的敏感信息，构建关系图谱并给出风险评估，以 JSON 格式返回。\n\n"
            f"## 原始文本\n{text_content}\n\n"
            f"## 已检测到的敏感信息\n{findings_json}"
        )
        messages.append({"role": "user", "content": user_content})

        return messages

    def build_explanation_messages(
        self,
        text_content: str,
        findings: list[dict],
        custom_explanations: dict | None = None,
    ) -> list[dict]:
        """构建敏感信息解释的 messages。

        为已检测到的敏感信息生成面向业务人员的通俗解释。

        Args:
            text_content: 原始文本（会截断到合理长度以节省 token）。
            findings: 检测阶段的发现列表。
            custom_explanations: 企业自定义的解释模板（可选），
                                 key 为分类名，value 为解释模板字符串。
                                 如果为 None，则尝试从 config 中读取。
        """
        # 确定 system prompt
        base_prompt = (
            self._custom_explanation_prompt
            if self._custom_explanation_prompt is not None
            else EXPLANATION_SYSTEM_PROMPT
        )

        system_content = self._apply_model_adaptations(base_prompt)
        messages: list[dict] = [{"role": "system", "content": system_content}]

        # 截断原始文本
        truncated_text = text_content[:_EXPLANATION_MAX_TEXT_CHARS]
        if len(text_content) > _EXPLANATION_MAX_TEXT_CHARS:
            truncated_text += "\n...(文本已截断)..."

        # 构建 findings 摘要（为每个 finding 添加 id 以便 LLM 引用）
        findings_for_explain: list[dict] = []
        for idx, f in enumerate(findings):
            item = copy.deepcopy(f)
            item["finding_id"] = f"finding_{idx + 1}"
            findings_for_explain.append(item)
        findings_json = json.dumps(findings_for_explain, ensure_ascii=False, indent=2)

        # 构建企业自定义解释提示
        explanation_hints = ""
        merged_explanations = dict(custom_explanations or {})
        # 合并 config 中的解释模板（custom_explanations 参数优先级更高）
        if self.config.custom_explanation_templates:
            for k, v in self.config.custom_explanation_templates.items():
                if k not in merged_explanations:
                    merged_explanations[k] = v
        if merged_explanations:
            lines = [f"- {name}：{tpl}" for name, tpl in merged_explanations.items()]
            explanation_hints = (
                "\n\n## 企业自定义解释模板（优先使用）\n" + "\n".join(lines)
            )

        user_content = (
            f"请为以下检测结果生成面向业务人员的通俗解释，以 JSON 格式返回。\n\n"
            f"## 原始文本\n{truncated_text}\n\n"
            f"## 检测结果\n{findings_json}"
            f"{explanation_hints}"
        )
        messages.append({"role": "user", "content": user_content})

        return messages

    def get_prompt_metadata(self) -> dict:
        """返回当前 Prompt 配置的版本和元数据信息。"""
        return {
            "detection_prompt_version": DETECTION_PROMPT_VERSION,
            "kg_prompt_version": KG_PROMPT_VERSION,
            "explanation_prompt_version": EXPLANATION_PROMPT_VERSION,
            "provider": self.config.provider,
            "model": self.config.model,
            "is_reasoner": self._is_reasoner,
            "is_qwen": self._is_qwen,
            "has_enterprise_config": self._enterprise_config is not None,
            "has_custom_detection_prompt": self._custom_detection_prompt is not None,
            "has_custom_kg_prompt": self._custom_kg_prompt is not None,
            "has_custom_explanation_prompt": self._custom_explanation_prompt is not None,
            "categories_count": len(SENSITIVITY_CATEGORIES),
            "few_shot_count": len(FEW_SHOT_EXAMPLES),
        }

    def load_custom_prompt(self, prompt_type: str, file_path: str) -> None:
        """从外部文件加载自定义 Prompt 模板（热更新）。

        Args:
            prompt_type: "detection"、"knowledge_graph" 或 "explanation"。
            file_path: 模板文件路径。

        Raises:
            ValueError: prompt_type 不合法时抛出。
            FileNotFoundError: 文件不存在时抛出。
        """
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Prompt 模板文件不存在: {file_path}")

        content = path.read_text(encoding="utf-8")

        if "json" not in content.lower():
            logger.warning(
                "自定义 Prompt 模板中未包含 'json' 关键词，"
                "可能导致 response_format=json_object 模式下返回空内容: %s",
                file_path,
            )

        if prompt_type == "detection":
            self._custom_detection_prompt = content
            logger.info("已加载自定义检测 Prompt 模板: %s", file_path)
        elif prompt_type == "knowledge_graph":
            self._custom_kg_prompt = content
            logger.info("已加载自定义知识图谱 Prompt 模板: %s", file_path)
        elif prompt_type == "explanation":
            self._custom_explanation_prompt = content
            logger.info("已加载自定义解释 Prompt 模板: %s", file_path)
        else:
            raise ValueError(
                f"不支持的 prompt_type: '{prompt_type}'，"
                f"仅支持 'detection' / 'knowledge_graph' / 'explanation'"
            )

    def refresh_enterprise_config(self) -> None:
        """手动刷新企业自定义配置。

        当运行时通过 config 的 CRUD 方法修改了企业自定义分类/关键词后，
        调用此方法可使 PromptManager 重新解析最新配置。
        """
        self._enterprise_config = self._build_enterprise_config()
        logger.info("企业自定义配置已刷新")

    def _build_enterprise_config(self) -> dict | None:
        """从 LLMConfig 中提取并格式化企业自定义配置。

        将 config 中的 custom_sensitive_categories、custom_keywords、
        custom_prompt_supplement、custom_explanation_templates 整合为统一的 dict。
        """
        cfg = self.config
        has_custom = (
            cfg.custom_sensitive_categories
            or cfg.custom_keywords
            or cfg.custom_prompt_supplement
            or cfg.custom_explanation_templates
        )
        if not has_custom:
            return None

        # 格式化自定义分类
        categories_lines: list[str] = []
        for cat in cfg.custom_sensitive_categories:
            name = cat.get("name", "未命名")
            desc = cat.get("description", "")
            level = cat.get("sensitivity_level", "HIGH")
            keywords = cat.get("keywords", [])
            patterns = cat.get("patterns", [])
            examples = cat.get("examples", [])

            line = f"- {name}（{desc}），默认级别: {level}"
            if keywords:
                line += f"\n  关键词: {'、'.join(keywords)}"
            if patterns:
                line += f"\n  正则模式: {'、'.join(patterns)}"
            if examples:
                line += f"\n  示例: {'；'.join(examples)}"
            categories_lines.append(line)
        categories_text = "\n".join(categories_lines) if categories_lines else "无"

        # 格式化关键词
        keywords_text = "、".join(cfg.custom_keywords) if cfg.custom_keywords else "无"

        # 格式化 explanation（从自定义分类和解释模板中提取）
        explanation_lines: list[str] = []
        for cat in cfg.custom_sensitive_categories:
            name = cat.get("name", "未命名")
            explanation = cat.get("explanation", "")
            if explanation:
                explanation_lines.append(f"- {name}：{explanation}")
        # 合并 custom_explanation_templates
        for tpl_name, tpl_text in cfg.custom_explanation_templates.items():
            # 避免与自定义分类中的 explanation 重复
            if not any(line.startswith(f"- {tpl_name}：") for line in explanation_lines):
                explanation_lines.append(f"- {tpl_name}：{tpl_text}")
        explanations_text = "\n".join(explanation_lines) if explanation_lines else "无"

        return {
            "categories": categories_text,
            "keywords": keywords_text,
            "explanations": explanations_text,
            "supplement": cfg.custom_prompt_supplement or "无",
        }

    def _adapt_for_reasoner(self, system_prompt: str) -> str:
        """针对 DeepSeek-reasoner 强化 JSON 约束。

        reasoner 不支持 response_format 参数，
        因此需要在 Prompt 文本中更严格地约束输出格式。
        """
        return system_prompt + _REASONER_JSON_CONSTRAINT

    def _apply_model_adaptations(self, system_prompt: str) -> str:
        """根据当前模型自动应用所有适配策略。

        包括 Qwen3 /no_think 和 DeepSeek-reasoner JSON 强化。
        """
        result = system_prompt

        # Qwen3: 在开头加入 /no_think 关闭思考模式，提升结构化输出稳定性
        if self._is_qwen:
            result = _QWEN_NO_THINK_PREFIX + result

        # DeepSeek-reasoner: 追加 JSON 强化约束
        if self._is_reasoner:
            result = self._adapt_for_reasoner(result)

        return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 导出列表
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
__all__: list[str] = [
    # 版本常量
    "DETECTION_PROMPT_VERSION",
    "KG_PROMPT_VERSION",
    "EXPLANATION_PROMPT_VERSION",
    # 分类体系
    "SENSITIVITY_CATEGORIES",
    # Prompt 模板
    "SENSITIVE_DETECTION_SYSTEM_PROMPT",
    "KNOWLEDGE_GRAPH_SYSTEM_PROMPT",
    "EXPLANATION_SYSTEM_PROMPT",
    "ENTERPRISE_SUPPLEMENT_TEMPLATE",
    # Few-Shot
    "FEW_SHOT_EXAMPLES",
    # 组装函数
    "build_detection_prompt",
    "build_knowledge_graph_prompt",
    # 管理器
    "PromptManager",
]
