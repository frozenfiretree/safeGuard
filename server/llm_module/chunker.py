"""LLM 语义检测模块 —— 文本分块与规则预筛优化。

本模块是检测流水线的关键中间层，负责：
1. 规则预筛（RulePreFilter）：决定哪些 TextBlock 需要送 LLM 分析
2. 文本分块（TextChunker）：将保留的 TextBlock 合并为 LLM 可处理的 TextChunk
3. 分块管道（ChunkPipeline）：组合预筛 + 分块的一站式入口

分块策略采用递归层次分块（Recursive/Hierarchical Chunking），尊重 TextBlock
的自然边界，并通过 overlap 机制确保块间信息连续。
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field

from .api_client import estimate_tokens
from .config import LLMConfig

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 上游数据结构（与上游 extractor 模块保持一致，待联调时替换为统一 import）
# ---------------------------------------------------------------------------


@dataclass
class ContentLocation:
    """文本块在原始文档中的精确位置。"""

    block_index: int
    char_offset_start: int
    char_offset_end: int
    line_number: int | None = None
    page_number: int | None = None
    sheet_name: str | None = None
    row_number: int | None = None
    column_number: int | None = None
    cell_address: str | None = None
    paragraph_index: int | None = None
    slide_number: int | None = None
    shape_name: str | None = None
    email_part: str | None = None
    attachment_name: str | None = None
    archive_inner_path: str | None = None


@dataclass
class TextBlock:
    """上游内容提取模块产出的文本块。"""

    content: str
    source_type: str  # paragraph / cell / slide_shape / page / email_body
    location: ContentLocation


@dataclass
class SensitiveFinding:
    """规则引擎或 LLM 产出的敏感发现。"""

    finding_id: str
    rule_id: str
    rule_name: str
    category: str
    sensitivity_level: str  # LOW / MEDIUM / HIGH / CRITICAL
    confidence: float
    source: str  # RULE / LLM / COMBINED
    matched_text: str
    context_before: str
    context_after: str
    location: ContentLocation
    description: str


# ---------------------------------------------------------------------------
# 分块输出数据结构
# ---------------------------------------------------------------------------


@dataclass
class TextChunk:
    """合并后的文本块，是送入 LLM 的最小处理单元。"""

    chunk_id: int
    content: str
    token_count: int
    block_indices: list[int]
    block_locations: list[ContentLocation]
    overlap_prefix: str
    overlap_prefix_token_count: int
    source_info: str
    metadata: dict = field(default_factory=dict)


@dataclass
class PreFilterResult:
    """单个 TextBlock 的预筛决策结果。"""

    block_index: int
    action: str  # MUST_ANALYZE / SHOULD_ANALYZE / SKIP
    reason: str
    rule_findings: list[SensitiveFinding] = field(default_factory=list)
    keyword_hits: list[str] = field(default_factory=list)


@dataclass
class ChunkingStats:
    """分块过程的统计信息，用于日志和性能分析。"""

    total_blocks: int = 0
    skipped_blocks: int = 0
    empty_blocks: int = 0
    must_analyze_blocks: int = 0
    should_analyze_blocks: int = 0
    oversized_blocks: int = 0
    output_chunks: int = 0
    total_tokens: int = 0
    avg_chunk_tokens: float = 0.0
    processing_time_ms: int = 0


# ---------------------------------------------------------------------------
# 内置敏感关键词表
# ---------------------------------------------------------------------------

_CLASSIFICATION_KEYWORDS = [
    "绝密", "机密", "秘密", "内部", "限制", "保密", "涉密",
    "confidential", "secret", "classified", "internal", "restricted",
    "top secret", "sensitive",
]

_BUSINESS_KEYWORDS = [
    "合同", "协议", "报价", "竞标", "投标", "薪资", "工资", "薪酬",
    "绩效", "考核", "预算", "营收", "利润", "成本", "融资",
    "并购", "收购", "上市", "股权", "期权", "分红",
]

_CREDENTIAL_KEYWORDS = [
    "密码", "口令", "password", "passwd", "secret", "token",
    "api_key", "apikey", "api-key", "private_key", "privatekey",
    "证书", "certificate", "ssh_key", "access_key",
    "connection_string", "连接串", "jdbc:",
    "mongodb://", "mysql://", "redis://", "postgres://",
]

_PII_INDICATOR_KEYWORDS = [
    "身份证", "护照", "手机号", "银行卡", "社保号", "驾照",
    "花名册", "通讯录", "员工名单", "客户名单",
]

_INFRA_KEYWORDS = [
    "防火墙", "firewall", "内网", "vpn", "网段",
    "服务器", "root@", "sudo", "admin",
    "拓扑", "架构图", "部署图",
]

_ALL_BUILTIN_KEYWORDS: list[str] = (
    _CLASSIFICATION_KEYWORDS
    + _BUSINESS_KEYWORDS
    + _CREDENTIAL_KEYWORDS
    + _PII_INDICATOR_KEYWORDS
    + _INFRA_KEYWORDS
)

# 中文 + 英文句子终止符后的切分点
_SENTENCE_BOUNDARY_PATTERN = re.compile(
    r"(?<=[。！？；…\.\!\?\;])"
    r"[\s]*"
    r"(?=\S)"
)


# ---------------------------------------------------------------------------
# RulePreFilter —— 规则预筛器
# ---------------------------------------------------------------------------


class RulePreFilter:
    """规则预筛器：基于规则引擎结果和内置关键词决定 TextBlock 是否需要 LLM 分析。

    设计原理：
    - 规则引擎擅长结构化模式（身份证号、手机号等固定格式），LLM 擅长语义理解
    - 规则已命中的块必须送 LLM 做交叉验证和语义深挖
    - 含敏感关键词但规则未命中的块，可能包含规则无法识别的语义敏感信息
    - 两者均不命中的块，大概率不含敏感信息，可安全跳过
    """

    def __init__(self, custom_keywords: list[str] | None = None) -> None:
        """初始化预筛器。

        Args:
            custom_keywords: 企业自定义关键词列表，与内置关键词合并使用。
        """
        extra = list(custom_keywords) if custom_keywords else []
        self._all_keywords: list[str] = _ALL_BUILTIN_KEYWORDS + extra
        # 预计算小写版本用于匹配
        self._keywords_lower: list[tuple[str, str]] = [
            (kw, kw.lower()) for kw in self._all_keywords
        ]

    def filter(
        self,
        text_blocks: list[TextBlock],
        rule_findings: list[SensitiveFinding] | None = None,
    ) -> list[PreFilterResult]:
        """对每个 TextBlock 进行预筛决策。

        Args:
            text_blocks: 上游提取的 TextBlock 列表。
            rule_findings: 规则引擎产出的 SensitiveFinding 列表（可选）。

        Returns:
            与 text_blocks 等长的 PreFilterResult 列表。
        """
        if not text_blocks:
            return []

        finding_index = self._build_finding_index(rule_findings)
        results: list[PreFilterResult] = []

        for idx, block in enumerate(text_blocks):
            # 1. 空白检测
            if self._is_blank(block.content):
                results.append(PreFilterResult(
                    block_index=idx,
                    action="SKIP",
                    reason="空白或极短内容，无分析价值",
                ))
                continue

            # 2. 规则命中检测
            block_findings = finding_index.get(idx, [])
            if block_findings:
                results.append(PreFilterResult(
                    block_index=idx,
                    action="MUST_ANALYZE",
                    reason=f"规则引擎命中 {len(block_findings)} 条发现",
                    rule_findings=block_findings,
                ))
                continue

            # 3. 关键词匹配检测
            hits = self._match_keywords(block.content)
            if hits:
                results.append(PreFilterResult(
                    block_index=idx,
                    action="SHOULD_ANALYZE",
                    reason=f"命中敏感关键词: {', '.join(hits[:5])}",
                    keyword_hits=hits,
                ))
                continue

            # 4. 默认跳过
            results.append(PreFilterResult(
                block_index=idx,
                action="SKIP",
                reason="规则无命中且未匹配敏感关键词",
            ))

        return results

    def _build_finding_index(
        self, rule_findings: list[SensitiveFinding] | None
    ) -> dict[int, list[SensitiveFinding]]:
        """将 rule_findings 按 location.block_index 分组为字典。"""
        index: dict[int, list[SensitiveFinding]] = {}
        if not rule_findings:
            return index
        for finding in rule_findings:
            bi = finding.location.block_index
            index.setdefault(bi, []).append(finding)
        return index

    def _match_keywords(self, text: str) -> list[str]:
        """对文本做大小写不敏感的关键词匹配，返回命中的关键词原文列表。"""
        if not text:
            return []
        text_lower = text.lower()
        return [kw for kw, kw_low in self._keywords_lower if kw_low in text_lower]

    @staticmethod
    def _is_blank(text: str) -> bool:
        """判断文本是否为空白（strip 后为空，或预估 token < 5）。"""
        if not text or not text.strip():
            return True
        stripped = text.strip()
        if estimate_tokens(stripped) < 5:
            return True
        # 仅包含标点/数字且长度 < 10 字符
        if len(stripped) < 10 and re.fullmatch(r"[\d\s\W]+", stripped):
            return True
        return False


# ---------------------------------------------------------------------------
# TextChunker —— 文本分块器
# ---------------------------------------------------------------------------


class TextChunker:
    """文本分块器：将多个 TextBlock 合并为适合 LLM 处理的 TextChunk 列表。

    采用递归层次分块策略（Recursive/Hierarchical Chunking）：
    - 第一层: TextBlock 边界（最大语义单元，绝不打断）
    - 第二层: 句子边界（仅在单个 block 超长时降级使用）
    - 第三层: 字符硬切（极端 fallback，保证不超限）
    """

    def __init__(
        self,
        max_input_tokens: int = 8000,
        overlap_tokens: int = 200,
    ) -> None:
        """初始化分块器。

        Args:
            max_input_tokens: 单个 chunk 的最大 token 数。
            overlap_tokens: 块间重叠 token 数。
        """
        self._max_tokens = max_input_tokens
        self._overlap_tokens = overlap_tokens
        self._oversized_count = 0  # 记录超长切分次数

    @property
    def oversized_count(self) -> int:
        """本次分块过程中超长块切分的次数。"""
        return self._oversized_count

    def chunk(
        self,
        text_blocks: list[TextBlock],
        block_filter_results: list[PreFilterResult] | None = None,
    ) -> list[TextChunk]:
        """将 TextBlock 列表分块为 TextChunk 列表。

        如果提供 block_filter_results，则仅处理 action != 'SKIP' 的 blocks。

        Args:
            text_blocks: 原始 TextBlock 列表。
            block_filter_results: 预筛结果列表（可选，与 text_blocks 等长）。

        Returns:
            TextChunk 列表。
        """
        if not text_blocks:
            return []

        self._oversized_count = 0

        # 筛选需要处理的 blocks，保留原始索引
        blocks_with_indices: list[tuple[int, TextBlock]] = []
        if block_filter_results:
            for fr in block_filter_results:
                if fr.action != "SKIP" and fr.block_index < len(text_blocks):
                    blocks_with_indices.append(
                        (fr.block_index, text_blocks[fr.block_index])
                    )
        else:
            blocks_with_indices = list(enumerate(text_blocks))

        if not blocks_with_indices:
            return []

        return self._merge_blocks_to_chunks(blocks_with_indices)

    def _merge_blocks_to_chunks(
        self, blocks_with_indices: list[tuple[int, TextBlock]]
    ) -> list[TextChunk]:
        """核心分块算法：将 (原始索引, TextBlock) 列表合并为 TextChunk 列表。"""
        # 先展开超长块
        expanded: list[tuple[int, TextBlock]] = []
        for orig_idx, block in blocks_with_indices:
            block_tokens = estimate_tokens(block.content)
            if block_tokens > self._max_tokens:
                expanded.extend(self._split_oversized_block(block, orig_idx))
            else:
                expanded.append((orig_idx, block))

        if not expanded:
            return []

        chunks: list[TextChunk] = []
        current_blocks: list[tuple[int, TextBlock]] = []
        current_tokens = 0
        prev_chunk_text = ""

        def _finalize_chunk() -> None:
            nonlocal prev_chunk_text
            if not current_blocks:
                return

            source_info = self._build_source_info(current_blocks)
            overlap_prefix = ""
            overlap_prefix_tokens = 0
            if chunks:  # 非第一个 chunk
                overlap_prefix = self._extract_overlap(prev_chunk_text)
                overlap_prefix_tokens = estimate_tokens(overlap_prefix) if overlap_prefix else 0

            raw_content = self._join_block_contents(current_blocks)
            content = self._build_chunk_content(
                [b for _, b in current_blocks], source_info, overlap_prefix,
            )
            content_tokens = estimate_tokens(content)

            # 安全检查：总 token 不超过 max_input_tokens * 1.15
            safety_limit = int(self._max_tokens * 1.15)
            if content_tokens > safety_limit:
                # 截断 overlap 以适应
                overshoot = content_tokens - safety_limit
                if overlap_prefix and overlap_prefix_tokens > overshoot:
                    # 缩短 overlap
                    trim_chars = max(1, int(overshoot / 1.2))
                    overlap_prefix = overlap_prefix[trim_chars:]
                    overlap_prefix_tokens = estimate_tokens(overlap_prefix) if overlap_prefix else 0
                    content = self._build_chunk_content(
                        [b for _, b in current_blocks], source_info, overlap_prefix,
                    )
                    content_tokens = estimate_tokens(content)

            indices = [i for i, _ in current_blocks]
            locations = [b.location for _, b in current_blocks]

            chunks.append(TextChunk(
                chunk_id=len(chunks),
                content=content,
                token_count=current_tokens,
                block_indices=indices,
                block_locations=locations,
                overlap_prefix=overlap_prefix,
                overlap_prefix_token_count=overlap_prefix_tokens,
                source_info=source_info,
                metadata=self._build_metadata(current_blocks),
            ))
            prev_chunk_text = raw_content

            logger.debug(
                "Chunk#%d: tokens=%d, blocks=[%s], overlap=%dtokens",
                len(chunks) - 1, current_tokens,
                f"{indices[0]}-{indices[-1]}" if len(indices) > 1 else str(indices[0]),
                overlap_prefix_tokens,
            )

        for orig_idx, block in expanded:
            block_tokens = estimate_tokens(block.content)

            if current_tokens + block_tokens > self._max_tokens and current_blocks:
                _finalize_chunk()
                current_blocks = []
                current_tokens = 0

            current_blocks.append((orig_idx, block))
            current_tokens += block_tokens

        # 封装最后一个 chunk
        _finalize_chunk()
        return chunks

    def _split_oversized_block(
        self, block: TextBlock, block_index: int,
    ) -> list[tuple[int, TextBlock]]:
        """将超长 TextBlock 按句子边界切分为多个子 TextBlock。"""
        self._oversized_count += 1
        sentences = _SENTENCE_BOUNDARY_PATTERN.split(block.content)
        # 过滤空句子
        sentences = [s for s in sentences if s.strip()]

        if not sentences:
            return [(block_index, block)]

        sub_blocks: list[tuple[int, TextBlock]] = []
        current_text = ""
        current_char_start = block.location.char_offset_start

        def _flush(end_offset: int) -> None:
            nonlocal current_text
            if not current_text.strip():
                return
            loc = ContentLocation(
                block_index=block.location.block_index,
                char_offset_start=current_char_start,
                char_offset_end=end_offset,
                line_number=block.location.line_number,
                page_number=block.location.page_number,
                sheet_name=block.location.sheet_name,
                row_number=block.location.row_number,
                column_number=block.location.column_number,
                cell_address=block.location.cell_address,
                paragraph_index=block.location.paragraph_index,
                slide_number=block.location.slide_number,
                shape_name=block.location.shape_name,
                email_part=block.location.email_part,
                attachment_name=block.location.attachment_name,
                archive_inner_path=block.location.archive_inner_path,
            )
            sub_blocks.append((block_index, TextBlock(
                content=current_text,
                source_type=block.source_type,
                location=loc,
            )))

        char_cursor = 0
        for sent in sentences:
            sent_tokens = estimate_tokens(sent)

            # 单个句子超长——字符硬切
            if sent_tokens > self._max_tokens:
                # 先 flush 已有内容
                if current_text.strip():
                    _flush(block.location.char_offset_start + char_cursor)
                    current_text = ""
                    current_char_start = block.location.char_offset_start + char_cursor

                logger.warning(
                    "单个句子超过 max_input_tokens，执行字符硬切: block_index=%d",
                    block_index,
                )
                hard_cut_chars = max(1, int(self._max_tokens * 0.8 / 1.2))
                pos = 0
                while pos < len(sent):
                    piece = sent[pos: pos + hard_cut_chars]
                    piece_start = block.location.char_offset_start + char_cursor + pos
                    piece_end = piece_start + len(piece)
                    loc = ContentLocation(
                        block_index=block.location.block_index,
                        char_offset_start=piece_start,
                        char_offset_end=piece_end,
                        line_number=block.location.line_number,
                        page_number=block.location.page_number,
                        sheet_name=block.location.sheet_name,
                        paragraph_index=block.location.paragraph_index,
                        slide_number=block.location.slide_number,
                        email_part=block.location.email_part,
                    )
                    sub_blocks.append((block_index, TextBlock(
                        content=piece,
                        source_type=block.source_type,
                        location=loc,
                    )))
                    pos += hard_cut_chars
                char_cursor += len(sent)
                current_char_start = block.location.char_offset_start + char_cursor
                continue

            # 正常贪心合并
            merged_tokens = estimate_tokens(current_text + sent) if current_text else sent_tokens
            if merged_tokens > self._max_tokens and current_text.strip():
                _flush(block.location.char_offset_start + char_cursor)
                current_text = sent
                current_char_start = block.location.char_offset_start + char_cursor
            else:
                current_text += sent

            char_cursor += len(sent)

        # flush 尾部
        if current_text.strip():
            _flush(block.location.char_offset_start + char_cursor)

        logger.debug(
            "超长块切分: block_index=%d, 原始tokens=%d, 切分为%d个子块",
            block_index, estimate_tokens(block.content), len(sub_blocks),
        )
        return sub_blocks if sub_blocks else [(block_index, block)]

    def _extract_overlap(self, text: str) -> str:
        """从文本末尾提取不超过 overlap_tokens 的重叠片段。

        策略：从文本末尾向前截取，尽量在句子边界处截断。
        """
        if not text or self._overlap_tokens <= 0:
            return ""

        # 粗略估算需要截取的字符数（中文约 1.2 token/字）
        est_chars = int(self._overlap_tokens / 1.0)  # 偏保守
        tail = text[-est_chars:] if len(text) > est_chars else text

        # 精确调整：如果太长则逐步缩短
        while estimate_tokens(tail) > self._overlap_tokens and len(tail) > 10:
            tail = tail[max(1, len(tail) // 10):]

        # 尝试在句子边界处截断（取最后一个句子开头之后的部分）
        parts = _SENTENCE_BOUNDARY_PATTERN.split(tail)
        if len(parts) > 1:
            # 从第二个 part 开始拼接，确保从句子开头开始
            candidate = "".join(parts[1:])
            if candidate.strip() and estimate_tokens(candidate) >= self._overlap_tokens * 0.3:
                return candidate

        return tail.strip()

    def _build_source_info(
        self, blocks_with_indices: list[tuple[int, TextBlock]],
    ) -> str:
        """根据 blocks 的 source_type 和 location 生成来源摘要。"""
        if not blocks_with_indices:
            return ""

        # 按 source_type 分组
        source_types = set(b.source_type for _, b in blocks_with_indices)

        # 单一 source_type 的情况用专用格式
        if len(source_types) == 1:
            st = next(iter(source_types))
            return self._format_source_for_type(st, blocks_with_indices)

        # 混合类型，给出简要统计
        parts: list[str] = []
        for st in sorted(source_types):
            sub = [(i, b) for i, b in blocks_with_indices if b.source_type == st]
            parts.append(self._format_source_for_type(st, sub))
        return " + ".join(parts)

    @staticmethod
    def _format_source_for_type(
        source_type: str, blocks: list[tuple[int, TextBlock]],
    ) -> str:
        """为特定 source_type 生成来源描述。"""
        if source_type == "paragraph":
            indices = [b.location.paragraph_index for _, b in blocks
                       if b.location.paragraph_index is not None]
            if indices:
                return f"【来源：段落#{min(indices)}-#{max(indices)}】"
            block_ids = [i for i, _ in blocks]
            return f"【来源：段落#{min(block_ids)}-#{max(block_ids)}】"

        if source_type == "cell":
            sheet_names = {b.location.sheet_name for _, b in blocks
                          if b.location.sheet_name}
            addresses = [b.location.cell_address for _, b in blocks
                         if b.location.cell_address]
            sheet_str = next(iter(sheet_names)) if len(sheet_names) == 1 else "多Sheet"
            if addresses:
                return f"【来源：{sheet_str}!{addresses[0]}-{addresses[-1]}】"
            return f"【来源：{sheet_str}】"

        if source_type == "slide_shape":
            slides = sorted({b.location.slide_number for _, b in blocks
                             if b.location.slide_number is not None})
            if slides:
                return f"【来源：幻灯片#{slides[0]}-#{slides[-1]}】"
            return "【来源：幻灯片】"

        if source_type == "page":
            pages = sorted({b.location.page_number for _, b in blocks
                            if b.location.page_number is not None})
            if pages:
                return f"【来源：第{pages[0]}-{pages[-1]}页】"
            return "【来源：PDF 页面】"

        if source_type == "email_body":
            return "【来源：邮件正文】"

        return f"【来源：{source_type}】"

    @staticmethod
    def _join_block_contents(
        blocks_with_indices: list[tuple[int, TextBlock]],
    ) -> str:
        """根据 source_type 选择合适的分隔符拼接 block 内容（纯文本，不含元信息）。"""
        if not blocks_with_indices:
            return ""

        parts: list[str] = []
        prev_slide: int | None = None
        prev_page: int | None = None

        for _, block in blocks_with_indices:
            st = block.source_type

            if st == "cell":
                parts.append(block.content)
            elif st == "slide_shape":
                cur_slide = block.location.slide_number
                if prev_slide is not None and cur_slide != prev_slide:
                    parts.append(f"\n--- 幻灯片 {cur_slide} ---\n")
                parts.append(block.content)
                prev_slide = cur_slide
            elif st == "page":
                cur_page = block.location.page_number
                if prev_page is not None and cur_page != prev_page:
                    parts.append(f"\n--- 第 {cur_page} 页 ---\n")
                parts.append(block.content)
                prev_page = cur_page
            else:
                parts.append(block.content)

        # 选择分隔符
        first_type = blocks_with_indices[0][1].source_type
        if first_type == "cell":
            return " | ".join(parts)
        return "\n".join(parts)

    @staticmethod
    def _build_chunk_content(
        blocks: list[TextBlock],
        source_info: str,
        overlap_prefix: str,
    ) -> str:
        """拼装 chunk 的最终文本内容。

        格式：
        [上文重叠] {overlap_prefix}（如果非空）
        {source_info}
        {block1.content}
        {block2.content}
        ...
        """
        sections: list[str] = []

        if overlap_prefix:
            sections.append(f"[上文重叠] {overlap_prefix}")

        if source_info:
            sections.append(source_info)

        # 拼接 block 内容（使用与 _join_block_contents 一致的逻辑）
        prev_slide: int | None = None
        prev_page: int | None = None
        content_parts: list[str] = []

        for block in blocks:
            st = block.source_type
            if st == "slide_shape":
                cur_slide = block.location.slide_number
                if prev_slide is not None and cur_slide != prev_slide:
                    content_parts.append(f"--- 幻灯片 {cur_slide} ---")
                prev_slide = cur_slide
            elif st == "page":
                cur_page = block.location.page_number
                if prev_page is not None and cur_page != prev_page:
                    content_parts.append(f"--- 第 {cur_page} 页 ---")
                prev_page = cur_page

            content_parts.append(block.content)

        first_type = blocks[0].source_type if blocks else "paragraph"
        if first_type == "cell":
            sections.append(" | ".join(content_parts))
        else:
            sections.append("\n".join(content_parts))

        return "\n".join(sections)

    @staticmethod
    def _build_metadata(
        blocks_with_indices: list[tuple[int, TextBlock]],
    ) -> dict:
        """构建 chunk 扩展元数据。"""
        type_counts: dict[str, int] = {}
        for _, block in blocks_with_indices:
            type_counts[block.source_type] = type_counts.get(block.source_type, 0) + 1
        return {"source_type_distribution": type_counts}


# ---------------------------------------------------------------------------
# ChunkPipeline —— 分块管道
# ---------------------------------------------------------------------------


class ChunkPipeline:
    """分块管道：组合预筛 + 分块的一站式入口。

    这是 detector.py 调用的主入口类，封装了完整的预筛 → 分块流程。
    """

    def __init__(self, config: LLMConfig | None = None) -> None:
        """初始化分块管道。

        Args:
            config: LLM 配置对象（可选）。如果为 None，使用默认参数。
        """
        cfg = config or LLMConfig()
        self._pre_filter = RulePreFilter(
            custom_keywords=cfg.custom_keywords if cfg.custom_keywords else None,
        )
        self._chunker = TextChunker(
            max_input_tokens=cfg.max_input_tokens,
            overlap_tokens=cfg.chunk_overlap_tokens,
        )

    @property
    def pre_filter(self) -> RulePreFilter:
        """暴露预筛器实例，允许外部直接调用或自定义。"""
        return self._pre_filter

    @property
    def chunker(self) -> TextChunker:
        """暴露分块器实例。"""
        return self._chunker

    def process(
        self,
        text_blocks: list[TextBlock],
        rule_findings: list[SensitiveFinding] | None = None,
    ) -> tuple[list[TextChunk], ChunkingStats]:
        """执行完整的预筛 + 分块流程。

        Args:
            text_blocks: 上游 TextBlock 列表。
            rule_findings: 规则引擎发现列表（可选）。

        Returns:
            (TextChunk 列表, ChunkingStats 统计对象) 的元组。
        """
        start_time = time.monotonic()
        stats = ChunkingStats()

        if not text_blocks:
            return [], stats

        stats.total_blocks = len(text_blocks)

        # 1. 预筛
        filter_results = self._pre_filter.filter(text_blocks, rule_findings)

        # 2. 统计预筛结果
        for fr in filter_results:
            if fr.action == "SKIP":
                stats.skipped_blocks += 1
                # 检查是否是空白导致的 skip
                if fr.block_index < len(text_blocks):
                    content = text_blocks[fr.block_index].content
                    if not content or not content.strip():
                        stats.empty_blocks += 1
            elif fr.action == "MUST_ANALYZE":
                stats.must_analyze_blocks += 1
            elif fr.action == "SHOULD_ANALYZE":
                stats.should_analyze_blocks += 1

        logger.info(
            "预筛完成: 总块数=%d, MUST=%d, SHOULD=%d, SKIP=%d, 空白=%d",
            stats.total_blocks,
            stats.must_analyze_blocks,
            stats.should_analyze_blocks,
            stats.skipped_blocks,
            stats.empty_blocks,
        )

        # 3. 分块
        result_chunks = self._chunker.chunk(text_blocks, filter_results)
        stats.oversized_blocks = self._chunker.oversized_count

        # 4. 汇总统计
        stats.output_chunks = len(result_chunks)
        stats.total_tokens = sum(c.token_count for c in result_chunks)
        stats.avg_chunk_tokens = (
            stats.total_tokens / stats.output_chunks if stats.output_chunks else 0.0
        )

        elapsed_ms = int((time.monotonic() - start_time) * 1000)
        stats.processing_time_ms = elapsed_ms

        kept = stats.must_analyze_blocks + stats.should_analyze_blocks
        logger.info(
            "分块完成: 保留块数=%d, 输出chunk数=%d, 总token=%d, 平均token/chunk=%.1f",
            kept, stats.output_chunks, stats.total_tokens, stats.avg_chunk_tokens,
        )

        return result_chunks, stats


# ---------------------------------------------------------------------------
# 模块导出
# ---------------------------------------------------------------------------

__all__ = [
    # 上游数据结构（本地定义，待联调替换）
    "ContentLocation",
    "TextBlock",
    "SensitiveFinding",
    # 分块输出结构
    "TextChunk",
    "PreFilterResult",
    "ChunkingStats",
    # 核心类
    "RulePreFilter",
    "TextChunker",
    "ChunkPipeline",
]
