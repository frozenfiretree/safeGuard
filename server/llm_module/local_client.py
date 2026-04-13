"""本地 Ollama 模型客户端（增强版）。

本模块实现了完整的 Ollama 本地 LLM 客户端，**替换** api_client.py 中的占位 OllamaClient。

设计原则:
    - 推理用 OpenAI SDK（与在线 Qwen/DeepSeek 客户端保持接口一致，工厂模式无缝切换）
    - 管理用 Ollama 原生 REST API（OpenAI SDK 不支持模型管理操作）
    - requests 延迟导入（避免未安装 requests 时影响在线模式）

版本: 1.0.0
作者: LLM Module Team
"""

from __future__ import annotations

import logging
import time

from openai import OpenAI

from .config import LLMConfig, MODEL_REGISTRY, PROVIDER_LOCAL
from .api_client import (
    BaseLLMClient,
    LLMResponse,
    TokenUsage,
    LLMAPIError,
    LLMConnectionError,
    LLMTimeoutError,
    LLMResponseError,
)

__all__ = [
    "OllamaClient",
    "OllamaConnectionHelper",
    "LOCAL_MODEL_PARAMS",
    "MODEL_VRAM_REQUIREMENTS",
    "format_bytes",
    "normalize_model_name",
]

logger = logging.getLogger(__name__)

# ============================================================================
# 辅助常量
# ============================================================================

# 本地模型推荐参数表
LOCAL_MODEL_PARAMS: dict[str, dict] = {
    "qwen3": {
        "temperature": 0.1,
        "top_p": 0.95,
        "repeat_penalty": 1.1,
        "num_ctx": 32768,
        "description": "中文语义理解最优，建议低温度确保输出确定性",
    },
    "deepseek-r1": {
        "temperature": 0.0,
        "top_p": 0.95,
        "repeat_penalty": 1.0,
        "num_ctx": 32768,
        "description": "推理模型，建议零温度；不支持 top_p/temperature 自定义",
    },
    "_default": {
        "temperature": 0.1,
        "top_p": 0.95,
        "repeat_penalty": 1.1,
        "num_ctx": 8192,
        "description": "通用默认参数",
    },
}

# 模型显存需求估算表（单位: GB）
MODEL_VRAM_REQUIREMENTS: dict[str, float] = {
    "qwen3:32b": 20.0,
    "qwen3:8b": 5.0,
    "deepseek-r1:8b": 5.0,
}


# ============================================================================
# 辅助函数
# ============================================================================


def format_bytes(size_bytes: int) -> str:
    """将字节数格式化为人类可读的字符串（KB/MB/GB）。

    Args:
        size_bytes: 字节数。

    Returns:
        格式化后的字符串，如 '4.36 GB'。
    """
    if size_bytes < 0:
        return "0 B"
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 ** 2:
        return f"{size_bytes / 1024:.2f} KB"
    elif size_bytes < 1024 ** 3:
        return f"{size_bytes / (1024 ** 2):.2f} MB"
    else:
        return f"{size_bytes / (1024 ** 3):.2f} GB"


def normalize_model_name(name: str) -> str:
    """标准化模型名：去除 :latest 后缀，统一小写。

    Args:
        name: 原始模型名称。

    Returns:
        标准化后的模型名。

    Examples:
        >>> normalize_model_name('Qwen3:8B:latest')
        'qwen3:8b'
        >>> normalize_model_name('qwen3:8b')
        'qwen3:8b'
    """
    name = name.strip().lower()
    if name.endswith(":latest"):
        name = name[: -len(":latest")]
    return name


# ============================================================================
# OllamaClient — 主客户端类
# ============================================================================


class OllamaClient(BaseLLMClient):
    """本地 Ollama 模型客户端（增强版）。

    通过 Ollama 的 OpenAI 兼容接口（/v1/）进行推理调用，
    通过 Ollama 原生 REST API（/api/）进行模型管理。

    关键特性:
        - 复用 OpenAI SDK 做推理（与在线 API 统一接口）
        - 支持 response_format 结构化 JSON 输出
        - 模型存在性自动检查
        - 运行状态与 GPU 显存查询
        - 模型预热（warm_up）
        - 友好的错误提示
    """

    def __init__(self, config: LLMConfig) -> None:
        """初始化 Ollama 客户端。

        在 __init__ 中一次性创建 OpenAI client 实例并复用，
        避免每次 chat_completion 调用都新建连接的开销。

        Args:
            config: LLM 配置对象。
        """
        super().__init__(config)

        # OpenAI 兼容层地址（推理用）
        self._openai_base_url = config.base_url or "http://localhost:11434/v1"

        # 原生 REST API 地址（管理用）
        # 去掉 /v1 或 /v1/ 后缀得到 Ollama 根地址
        raw_base = self._openai_base_url.rstrip("/")
        if raw_base.endswith("/v1"):
            raw_base = raw_base[: -len("/v1")]
        self._native_base_url = raw_base  # e.g. http://localhost:11434

        # 本地推理超时应更长（磁盘→内存加载 + 推理时间）
        effective_timeout = max(config.timeout or 120, 300)

        # 在 __init__ 中创建并复用 OpenAI client（设计决策 #4）
        self._client = OpenAI(
            api_key="ollama",  # Ollama 不校验 api_key，但 SDK 要求必填
            base_url=self._openai_base_url,
            timeout=float(effective_timeout),
            max_retries=1,  # 本地服务无限流限制，无需多次重试
        )

        self.logger.info(
            "OllamaClient 初始化完成 | model=%s | openai_base=%s | native_base=%s | timeout=%ds",
            config.model,
            self._openai_base_url,
            self._native_base_url,
            effective_timeout,
        )

    # ── 核心推理接口 ─────────────────────────────────────────────

    def chat_completion(
        self,
        messages: list[dict],
        temperature: float | None = None,
        max_tokens: int | None = None,
        response_format: dict | None = None,
    ) -> LLMResponse:
        """通过 OpenAI 兼容接口调用本地 Ollama 模型。

        使用 OpenAI SDK 而非原生 API 进行推理，保持与在线客户端一致的接口，
        使得工厂模式可以无缝切换 provider。

        Args:
            messages: OpenAI 格式的消息列表。
            temperature: 采样温度，None 则使用配置默认值。
            max_tokens: 最大生成 token 数，None 则使用配置默认值。
            response_format: 结构化输出格式，如 {"type": "json_object"}。
                Ollama v0.5+ 支持此参数，对下游 JSON 解析至关重要。

        Returns:
            LLMResponse 对象。

        Raises:
            LLMConnectionError: Ollama 服务未启动时抛出，包含安装/启动指引。
            LLMTimeoutError: 推理超时。
            LLMResponseError: 响应解析失败。
        """
        # 模型存在性软检查（只 WARNING 不阻断，因为 Ollama 可能自动拉取）
        if not self.is_model_downloaded():
            model = self.config.model
            self.logger.warning(
                "目标模型 '%s' 似乎尚未下载。Ollama 可能会自动拉取（耗时较长）。"
                "建议提前手动执行: ollama pull %s",
                model,
                model,
            )

        # 构建请求参数
        kwargs: dict = {
            "model": self.config.model,
            "messages": messages,
            "temperature": temperature if temperature is not None else self.config.temperature,
            "max_tokens": max_tokens or self.config.max_tokens,
        }

        # top_p 支持（Ollama OpenAI 兼容层正常支持）
        if self.config.top_p is not None:
            kwargs["top_p"] = self.config.top_p

        # 结构化输出支持（设计决策 #5）
        # Ollama v0.5+ 的 OpenAI 兼容层支持 response_format={"type": "json_object"}
        if response_format is not None:
            kwargs["response_format"] = response_format

        try:
            return self._call_api(
                client=self._client,
                kwargs=kwargs,
                provider=PROVIDER_LOCAL,
            )
        except LLMConnectionError:
            # 增强错误信息：Ollama 未启动时给出友好提示
            raise LLMConnectionError(
                message=(
                    "无法连接到 Ollama 服务。请确认:\n"
                    f"  1. Ollama 已安装: https://ollama.com/download\n"
                    f"  2. Ollama 服务已启动: 终端运行 'ollama serve'\n"
                    f"  3. 服务地址正确: {self._native_base_url}\n"
                    f"  4. 模型已下载: ollama pull {self.config.model}"
                ),
                provider=PROVIDER_LOCAL,
                model=self.config.model,
            )
        except LLMTimeoutError:
            raise LLMTimeoutError(
                message=(
                    f"Ollama 推理超时。本地模型推理较慢，尤其是首次加载时可能需要 30-120 秒。\n"
                    f"建议: 1) 先调用 warm_up() 预热模型  "
                    f"2) 增大 timeout 配置（当前: {self._client.timeout}s）"
                ),
                provider=PROVIDER_LOCAL,
                model=self.config.model,
            )

    def is_available(self) -> bool:
        """检查 Ollama 服务是否正在运行。

        通过原生 REST API 的 GET /api/tags 端点判断。
        使用 requests 库而非 OpenAI SDK，超时 5 秒。

        Returns:
            True 表示 Ollama 服务可达。
        """
        import requests  # 延迟导入（设计决策 #3）

        try:
            resp = requests.get(
                f"{self._native_base_url}/api/tags",
                timeout=5,
            )
            return resp.status_code == 200
        except Exception:
            return False

    # ── 模型管理接口 ─────────────────────────────────────────────

    def list_local_models(self) -> list[dict]:
        """列出 Ollama 已下载的所有本地模型。

        调用原生 REST API 的 GET /api/tags 端点。

        Returns:
            模型信息列表，每个 dict 包含:
            name, size(字节), parameter_size, quantization_level, family。
            如果接口不可达，返回空列表（管理接口失败不应阻断推理）。
        """
        import requests

        try:
            resp = requests.get(
                f"{self._native_base_url}/api/tags",
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            self.logger.debug("获取本地模型列表失败: %s", e)
            return []

        models = []
        for m in data.get("models", []):
            details = m.get("details", {})
            models.append({
                "name": m.get("name", ""),
                "size": m.get("size", 0),
                "parameter_size": details.get("parameter_size", "unknown"),
                "quantization_level": details.get("quantization_level", "unknown"),
                "family": details.get("family", "unknown"),
            })
        return models

    def is_model_downloaded(self, model_name: str | None = None) -> bool:
        """检查指定模型是否已下载到本地。

        通过 list_local_models() 获取已下载列表并匹配模型名。
        支持不带 :latest 后缀的模糊匹配。

        Args:
            model_name: 要检查的模型名，默认使用 self.config.model。

        Returns:
            True 表示模型已下载。
        """
        target = normalize_model_name(model_name or self.config.model)
        local_models = self.list_local_models()

        for m in local_models:
            if normalize_model_name(m.get("name", "")) == target:
                return True
        return False

    def show_model_info(self, model_name: str | None = None) -> dict:
        """获取模型详细信息：参数量、量化等级、上下文长度、家族等。

        调用 Ollama 原生 REST API 的 POST /api/show 端点。

        Args:
            model_name: 模型名称，默认使用 self.config.model。

        Returns:
            模型详情 dict，包含 details、model_info 等字段。
            如果接口不可达，返回空字典。
        """
        import requests

        name = model_name or self.config.model

        try:
            resp = requests.post(
                f"{self._native_base_url}/api/show",
                json={"model": name},
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            self.logger.debug("获取模型 '%s' 详情失败: %s", name, e)
            return {}

        # 提取关键信息
        details = data.get("details", {})
        model_info = data.get("model_info", {})

        return {
            "name": name,
            "format": details.get("format", "unknown"),
            "family": details.get("family", "unknown"),
            "parameter_size": details.get("parameter_size", "unknown"),
            "quantization_level": details.get("quantization_level", "unknown"),
            "context_length": model_info.get(
                f"{details.get('family', '')}.context_length",
                model_info.get("general.context_length"),
            ),
            "architecture": model_info.get("general.architecture", "unknown"),
            "template": data.get("template", ""),
            "parameters": data.get("parameters", ""),
            "raw": data,
        }

    def get_running_models(self) -> list[dict]:
        """查看当前加载到内存（GPU/CPU）中的模型列表。

        调用 Ollama 原生 REST API 的 GET /api/ps 端点，
        可用于判断模型是否需要冷启动以及 GPU 显存占用情况。

        Returns:
            运行中模型的信息列表，每个 dict 包含:
            name, size, size_vram, expires_at。
            如果接口不可达，返回空列表。
        """
        import requests

        try:
            resp = requests.get(
                f"{self._native_base_url}/api/ps",
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            self.logger.debug("获取运行中模型列表失败: %s", e)
            return []

        models = []
        for m in data.get("models", []):
            size = m.get("size", 0)
            size_vram = m.get("size_vram", 0)
            models.append({
                "name": m.get("name", ""),
                "size": size,
                "size_vram": size_vram,
                "size_human": format_bytes(size),
                "size_vram_human": format_bytes(size_vram),
                "gpu_offload_pct": round(size_vram / size * 100, 1) if size > 0 else 0.0,
                "expires_at": m.get("expires_at", ""),
            })
        return models

    def pull_model(self, model_name: str | None = None) -> bool:
        """（占位实现）提示用户手动拉取模型到本地。

        现阶段不实际执行拉取操作（模型下载可能非常耗时），
        仅通过日志提示用户在命令行手动执行 ollama pull 命令。

        Args:
            model_name: 要拉取的模型名，默认使用 self.config.model。

        Returns:
            始终返回 False，表示未实际执行拉取。
        """
        name = model_name or self.config.model
        cmd = OllamaConnectionHelper.get_model_pull_command(name)
        self.logger.info(
            "请在终端手动拉取模型（自动拉取功能暂未启用）:\n  %s",
            cmd,
        )
        return False

    # ── 预热与状态 ─────────────────────────────────────────────

    def warm_up(self) -> bool:
        """预热模型：发送一条极短的测试请求，触发 Ollama 将模型加载到内存。

        本地模型首次推理需要 30-120 秒的加载时间（从磁盘读入 GPU/CPU 内存），
        在系统初始化阶段调用此方法可以将冷启动延迟提前消化，
        避免首次实际检测请求超时。

        使用 max_tokens=1 最小化资源消耗。

        Returns:
            True 表示预热成功，模型已加载到内存。
        """
        self.logger.info("开始预热本地模型 '%s' ...", self.config.model)
        start = time.time()

        try:
            self._client.chat.completions.create(
                model=self.config.model,
                messages=[{"role": "user", "content": "hi"}],
                max_tokens=1,
                temperature=0.0,
            )
            elapsed = time.time() - start
            self.logger.info(
                "模型 '%s' 预热完成，耗时 %.1f 秒", self.config.model, elapsed
            )
            return True
        except Exception as e:
            elapsed = time.time() - start
            self.logger.warning(
                "模型 '%s' 预热失败（%.1f 秒）: %s", self.config.model, elapsed, e
            )
            return False

    def get_server_status(self) -> dict:
        """获取 Ollama 服务器综合状态。

        Returns:
            包含以下字段的状态字典:
            - is_running: Ollama 服务是否在运行
            - running_models: 当前加载到内存的模型列表
            - available_models: 已下载的模型名称列表
            - target_model_ready: 目标模型是否已下载
        """
        is_running = self.is_available()

        if not is_running:
            return {
                "is_running": False,
                "running_models": [],
                "available_models": [],
                "target_model_ready": False,
            }

        available = self.list_local_models()
        available_names = [m["name"] for m in available]
        target_ready = self.is_model_downloaded()
        running = self.get_running_models()

        return {
            "is_running": True,
            "running_models": running,
            "available_models": available_names,
            "target_model_ready": target_ready,
        }

    # ── 本地推理参数推荐 ─────────────────────────────────────────

    @staticmethod
    def get_recommended_params(model_name: str) -> dict:
        """根据模型名返回推荐的本地推理参数。

        不同模型家族有不同的最优参数配置:
        - qwen3 系列: 低温度 + 高 top_p，中文语义理解最优
        - deepseek-r1 系列: 零温度，推理模型追求确定性

        Args:
            model_name: 模型名称，如 'qwen3:8b'、'deepseek-r1:8b'。

        Returns:
            推荐参数字典，包含 temperature, top_p, repeat_penalty, num_ctx。
        """
        name_lower = model_name.lower()

        for family_prefix, params in LOCAL_MODEL_PARAMS.items():
            if family_prefix == "_default":
                continue
            if name_lower.startswith(family_prefix):
                return {
                    "temperature": params["temperature"],
                    "top_p": params["top_p"],
                    "repeat_penalty": params["repeat_penalty"],
                    "num_ctx": params["num_ctx"],
                }

        # 未匹配到已知家族，返回通用默认参数
        default = LOCAL_MODEL_PARAMS["_default"]
        return {
            "temperature": default["temperature"],
            "top_p": default["top_p"],
            "repeat_penalty": default["repeat_penalty"],
            "num_ctx": default["num_ctx"],
        }

    # ── 预留接口（占位） ─────────────────────────────────────────

    def chat_completion_native(
        self,
        messages: list[dict],
        temperature: float | None = None,
        max_tokens: int | None = None,
        json_schema: dict | None = None,
    ) -> LLMResponse:
        """（占位）通过 Ollama 原生 API 进行推理，支持严格 JSON Schema 约束。

        TODO: 使用 POST /api/chat 的 format 参数实现 GBNF 语法约束的
        结构化输出，比 OpenAI 兼容层的 response_format 更强大。

        当前未实现，请使用 chat_completion() 方法。

        Raises:
            NotImplementedError: 当前版本未实现此方法。
        """
        raise NotImplementedError(
            "原生 API Schema 约束推理尚未实现，请使用 chat_completion() 方法。"
            "如需严格 JSON Schema 约束，可在 chat_completion() 中使用 "
            "response_format={'type': 'json_object'} 并在 prompt 中描述结构。"
        )

    def prepare_finetune(self, **kwargs) -> dict:
        """（占位）预留本地模型微调接口。

        未来将支持:
        - LoRA/QLoRA 微调
        - 训练数据格式转换（SFT 格式 → Ollama Modelfile）
        - 微调参数配置
        - 微调后模型的自动注册

        当前仅返回提示信息字典。

        Returns:
            包含当前状态说明和未来规划的提示字典。
        """
        return {
            "status": "not_implemented",
            "message": "本地模型微调功能尚未实现",
            "planned_features": [
                "LoRA/QLoRA 微调支持",
                "训练数据格式转换",
                "微调参数配置",
                "微调后模型自动注册",
            ],
            "workaround": (
                "当前可通过 Ollama Modelfile 手动创建自定义模型: "
                "https://github.com/ollama/ollama/blob/main/docs/modelfile.md"
            ),
        }


# ============================================================================
# OllamaConnectionHelper — 连接诊断与辅助工具
# ============================================================================


class OllamaConnectionHelper:
    """Ollama 连接诊断与自动修复辅助工具。

    当 Ollama 不可用时，提供详细的诊断信息和修复指引，
    帮助用户快速定位和解决连接问题。
    """

    @staticmethod
    def diagnose(base_url: str = "http://localhost:11434") -> dict:
        """全面诊断 Ollama 连接状态。

        诊断步骤:
            1. 尝试连接 Ollama 服务（GET /api/tags）
            2. 分析失败原因（连接拒绝 / 超时 / 其他错误）
            3. 生成针对性的修复建议

        Args:
            base_url: Ollama 服务根地址，默认 http://localhost:11434。

        Returns:
            诊断结果字典，包含:
            - is_running: 服务是否正常运行
            - can_connect: 是否能建立 TCP 连接
            - error: 错误信息（无错误时为 None）
            - suggestions: 修复建议列表
            - ollama_host: 当前诊断的地址
        """
        import requests

        base_url = base_url.rstrip("/")
        result: dict = {
            "is_running": False,
            "can_connect": False,
            "error": None,
            "suggestions": [],
            "ollama_host": base_url,
        }

        try:
            resp = requests.get(f"{base_url}/api/tags", timeout=5)
            if resp.status_code == 200:
                result["is_running"] = True
                result["can_connect"] = True
                models = resp.json().get("models", [])
                if not models:
                    result["suggestions"].append(
                        "Ollama 服务运行正常，但尚未下载任何模型。"
                        "请执行: ollama pull qwen3:8b"
                    )
                return result
            else:
                result["can_connect"] = True
                result["error"] = f"Ollama 返回异常状态码: {resp.status_code}"
                result["suggestions"].append("Ollama 服务可能存在异常，尝试重启: ollama serve")
        except requests.ConnectionError:
            result["error"] = "无法连接到 Ollama 服务（连接被拒绝）"
            result["suggestions"].extend([
                "确认 Ollama 已安装: https://ollama.com/download",
                "启动 Ollama 服务: 在终端运行 'ollama serve'",
                f"如果 Ollama 运行在非默认地址，请设置环境变量 OLLAMA_HOST 或修改配置中的 base_url（当前: {base_url}）",
            ])
        except requests.Timeout:
            result["can_connect"] = True
            result["error"] = "连接 Ollama 服务超时"
            result["suggestions"].extend([
                "Ollama 可能正在加载模型，请稍后重试",
                "检查系统资源（CPU/内存）是否充足",
            ])
        except Exception as e:
            result["error"] = f"诊断时发生未知错误: {type(e).__name__}: {e}"
            result["suggestions"].append("请检查网络配置和 Ollama 安装状态")

        return result

    @staticmethod
    def get_install_guide() -> str:
        """返回 Ollama 安装指引文本（支持 Linux/macOS/Windows）。

        Returns:
            格式化的多行安装指引字符串。
        """
        return (
            "Ollama 安装指引\n"
            "================\n"
            "\n"
            "官方下载页面: https://ollama.com/download\n"
            "\n"
            "【Linux】\n"
            "  curl -fsSL https://ollama.com/install.sh | sh\n"
            "\n"
            "【macOS】\n"
            "  从 https://ollama.com/download/mac 下载并安装 .dmg 文件\n"
            "  或使用 Homebrew: brew install ollama\n"
            "\n"
            "【Windows】\n"
            "  从 https://ollama.com/download/windows 下载并安装 .exe 文件\n"
            "\n"
            "安装后启动服务:\n"
            "  ollama serve\n"
            "\n"
            "下载模型:\n"
            "  ollama pull qwen3:8b        # 推荐: 8B 中文模型\n"
            "  ollama pull qwen3:32b       # 大模型（需 ≥20GB 显存）\n"
            "  ollama pull deepseek-r1:8b  # DeepSeek 推理模型\n"
            "\n"
            "验证安装:\n"
            "  ollama list                 # 查看已下载模型\n"
            "  ollama run qwen3:8b         # 交互式测试\n"
        )

    @staticmethod
    def get_model_pull_command(model_name: str) -> str:
        """返回拉取指定模型的命令行命令。

        Args:
            model_name: 模型名称。

        Returns:
            完整的 ollama pull 命令字符串。
        """
        return f"ollama pull {model_name}"
