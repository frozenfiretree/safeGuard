import { useEffect, useMemo, useState } from "react";
import SectionCard from "../components/dashboard/section-card";
import SummaryStrip from "../components/dashboard/summary-strip";
import SidebarNav from "../components/layout/sidebar-nav";
import { api } from "../lib/api";
import { API_BASE_URL } from "../lib/config";
import type {
  AdminAgentItem,
  AdminAssetItem,
  AdminEventItem,
  AdminFileDetailResponse,
  AdminFileItem,
  AdminGlobalConfigResponse,
  AdminOcrHealthResponse,
  AdminTaskFailureItem,
  AdminUpgradeItem,
  AdminUploadSessionItem,
  DetectionRuleItem,
  HealthResponse,
  SensitiveFileHistoryResponse,
  SensitiveFileItem,
  SensitiveFileVersion,
} from "../lib/types";

type ViewKey = "overview" | "assets" | "agents" | "files" | "sensitive" | "rules" | "events" | "runtime" | "config";

const inputStyle: React.CSSProperties = { width: "100%", borderRadius: 12, border: "1px solid #d0d5dd", padding: "10px 12px", background: "#fff", color: "#101828" };
const textareaStyle: React.CSSProperties = { ...inputStyle, minHeight: 120, resize: "vertical", fontFamily: "Consolas, 'Courier New', monospace", fontSize: 12 };
const cardStyle: React.CSSProperties = { border: "1px solid #eaecf0", borderRadius: 12, padding: 12, background: "#fff" };

function fmtTime(ts?: number | null) {
  if (!ts) return "-";
  const value = Number(ts);
  if (Number.isNaN(value)) return "-";
  const ms = value > 10_000_000_000 ? value : value * 1000;
  const date = new Date(ms);
  return Number.isNaN(date.getTime()) ? "-" : date.toLocaleString();
}

function fmtSize(size?: number | null) {
  if (size === undefined || size === null) return "-";
  if (size < 1024) return `${size} B`;
  if (size < 1024 ** 2) return `${(size / 1024).toFixed(1)} KB`;
  if (size < 1024 ** 3) return `${(size / 1024 / 1024).toFixed(1)} MB`;
  return `${(size / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

const parseLines = (value: string) => value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean);

type RuleDraft = {
  ruleId: string;
  ruleName: string;
  ruleType: "keyword" | "ocr" | "llm";
  enabled: boolean;
  description: string;
  priority: string;
  keywordsText: string;
  regexPatternsText: string;
  matchMode: "contains" | "exact" | "regex";
  applyFileTypesText: string;
  caseSensitive: boolean;
  promptTemplate: string;
  labelIfMatched: string;
  threshold: string;
};

function emptyRuleDraft(): RuleDraft {
  return {
    ruleId: "",
    ruleName: "",
    ruleType: "keyword",
    enabled: true,
    description: "",
    priority: "100",
    keywordsText: "",
    regexPatternsText: "",
    matchMode: "contains",
    applyFileTypesText: "png\njpg\njpeg\npdf",
    caseSensitive: false,
    promptTemplate: "请判断该文件是否包含敏感信息，并说明原因。",
    labelIfMatched: "sensitive",
    threshold: "0.8",
  };
}

function draftFromRule(rule: DetectionRuleItem): RuleDraft {
  const config = rule.config || {};
  return {
    ruleId: rule.rule_id,
    ruleName: rule.rule_name || "",
    ruleType: rule.rule_type,
    enabled: !!rule.enabled,
    description: rule.description || "",
    priority: String(rule.priority ?? 100),
    keywordsText: Array.isArray(config.keywords) ? config.keywords.join("\n") : "",
    regexPatternsText: Array.isArray(config.regex_patterns) ? config.regex_patterns.join("\n") : "",
    matchMode: config.match_mode || "contains",
    applyFileTypesText: Array.isArray(config.apply_file_types) ? config.apply_file_types.join("\n") : "png\njpg\njpeg\npdf",
    caseSensitive: !!config.case_sensitive,
    promptTemplate: config.prompt_template || "请判断该文件是否包含敏感信息，并说明原因。",
    labelIfMatched: config.label_if_matched || "sensitive",
    threshold: String(config.threshold ?? 0.8),
  };
}

function payloadFromDraft(draft: RuleDraft) {
  const base = {
    rule_name: draft.ruleName.trim(),
    rule_type: draft.ruleType,
    enabled: draft.enabled,
    description: draft.description.trim(),
    priority: Number(draft.priority || 100),
    config: {} as Record<string, any>,
  };
  if (draft.ruleType === "keyword") {
    base.config = { keywords: parseLines(draft.keywordsText), match_mode: draft.matchMode, regex_patterns: parseLines(draft.regexPatternsText) };
  } else if (draft.ruleType === "ocr") {
    base.config = { keywords: parseLines(draft.keywordsText), apply_file_types: parseLines(draft.applyFileTypesText), case_sensitive: draft.caseSensitive };
  } else {
    base.config = { prompt_template: draft.promptTemplate.trim(), label_if_matched: draft.labelIfMatched.trim() || "sensitive", threshold: Number(draft.threshold || 0.8) };
  }
  return base;
}

function sensitiveTone(level?: string | null): "ok" | "error" | "pending" | "muted" {
  const normalized = String(level || "").toLowerCase();
  if (["critical", "high"].includes(normalized)) return "error";
  if (["medium", "review"].includes(normalized)) return "pending";
  if (["low"].includes(normalized)) return "muted";
  return "muted";
}

function buildConfigDraft(config?: AdminGlobalConfigResponse | null) {
  const source = config?.config || {};
  return {
    scanDirs: Array.isArray(source.scan_dirs) ? source.scan_dirs.join("\n") : "",
    watchDirs: Array.isArray(source.watch_dirs) ? source.watch_dirs.join("\n") : "",
    includeExtensions: Array.isArray(source.include_extensions) ? source.include_extensions.join("\n") : "",
    excludePaths: Array.isArray(source.exclude_paths) ? source.exclude_paths.join("\n") : "",
    heartbeatIntervalSec: String(source.heartbeat_interval_sec || ""),
    maxFileSizeMb: String(source.max_file_size_mb || ""),
    upgradeJson: JSON.stringify(source.upgrade || {}, null, 2),
  };
}

function statusText(text?: string | null) {
  const normalized = String(text || "").toLowerCase();
  const map: Record<string, string> = {
    ok: "正常", online: "在线", offline: "离线", registered: "已注册", completed: "已完成", failed: "失败",
    created: "已创建", uploading: "上传中", completing: "处理中", received: "已接收", parsing: "解析中",
    parsed: "已解析", parse_failed: "解析失败", rule_checking: "规则检测中", sensitive: "敏感",
    non_sensitive: "非敏感", rule_miss_pending: "待进一步判定", pending: "待处理", upgrading: "升级中",
    starting: "启动中", running: "运行中", review: "待复核",
  };
  return map[normalized] || text || "-";
}

function riskLevelText(text?: string | null) {
  const normalized = String(text || "").toLowerCase();
  const map: Record<string, string> = {
    critical: "极高风险", high: "高风险", medium: "中风险", low: "低风险", normal: "正常", sensitive: "敏感", review: "待复核",
  };
  return map[normalized] || text || "-";
}

function eventTypeText(text?: string | null) {
  const normalized = String(text || "").toLowerCase();
  const map: Record<string, string> = {
    file_changed: "文件发生变更", usb_changed: "USB 设备变化", file_created: "文件创建", file_deleted: "文件删除",
    file_modified: "文件内容修改", file_renamed: "文件重命名", file_moved: "文件移动", file_copied: "文件复制",
    file_overwritten: "文件覆盖", usb_inserted: "USB 设备插入", usb_removed: "USB 设备移除",
    heartbeat: "心跳上报", scan_complete: "扫描完成", upgrade_report: "升级结果上报",
  };
  return map[normalized] || text || "-";
}

function translateErrorMessage(text?: string | null) {
  const raw = String(text || "").trim();
  if (!raw) return "-";
  const normalized = raw.toLowerCase();
  const exactMap: Record<string, string> = {
    "admin authorization required": "需要管理员授权",
    "invalid token": "令牌无效",
    "token expired": "令牌已过期",
    "agent not found": "未找到对应 Agent",
    "file not found": "未找到对应文件",
    "task failure not found": "未找到失败任务记录",
    "upgrade package not found": "未找到升级包",
    "invalid range header": "分片范围头无效",
    "timestamp skew too large": "请求时间戳偏差过大",
    "request failed": "请求失败",
  };
  if (exactMap[normalized]) return exactMap[normalized];
  if (normalized.includes("connection refused")) return "连接被拒绝";
  if (normalized.includes("timed out")) return "请求超时";
  if (normalized.includes("not found")) return `未找到资源：${raw}`;
  if (normalized.includes("permission denied")) return `权限不足：${raw}`;
  return raw;
}

function statusTone(text?: string | null): "ok" | "error" | "pending" | "muted" {
  const normalized = String(text || "").toLowerCase();
  if (["ok", "online", "completed", "non_sensitive", "running"].includes(normalized)) return "ok";
  if (["failed", "error", "parse_failed", "sensitive", "critical", "high"].includes(normalized)) return "error";
  if (["uploading", "created", "completing", "parsing", "rule_checking", "registered", "rule_miss_pending", "review", "starting", "upgrading"].includes(normalized)) return "pending";
  return "muted";
}

function StatusPill(props: { text: string; tone?: "ok" | "error" | "pending" | "muted" }) {
  const tone = props.tone || "muted";
  const colors = tone === "ok" ? { border: "#1f7a45", bg: "#ecfdf3", fg: "#1f7a45" } : tone === "error" ? { border: "#b42318", bg: "#fef3f2", fg: "#b42318" } : tone === "pending" ? { border: "#b54708", bg: "#fff7ed", fg: "#b54708" } : { border: "#344054", bg: "#f2f4f7", fg: "#344054" };
  return <span style={{ display: "inline-flex", alignItems: "center", borderRadius: 999, padding: "2px 10px", fontSize: 12, fontWeight: 700, border: `1px solid ${colors.border}`, background: colors.bg, color: colors.fg }}>{props.text}</span>;
}

function SmallButton(props: React.ButtonHTMLAttributes<HTMLButtonElement> & { primary?: boolean }) {
  const { primary, style, ...rest } = props;
  return <button {...rest} style={{ borderRadius: 10, border: primary ? "1px solid #155eef" : "1px solid #d0d5dd", background: primary ? "#155eef" : "#fff", color: primary ? "#fff" : "#344054", fontSize: 13, fontWeight: 600, padding: "8px 12px", cursor: "pointer", ...style }} />;
}

function KeyValueRow(props: { label: string; value?: React.ReactNode }) {
  return <div style={{ display: "flex", justifyContent: "space-between", gap: 12, fontSize: 13, color: "#344054" }}><span style={{ color: "#667085" }}>{props.label}</span><span style={{ textAlign: "right", wordBreak: "break-word" }}>{props.value ?? "-"}</span></div>;
}

function MultiLineList(props: { items?: string[]; emptyText?: string }) {
  const items = (props.items || []).filter(Boolean);
  if (!items.length) return <div style={{ color: "#667085", fontSize: 13 }}>{props.emptyText || "暂无数据"}</div>;
  return <div style={{ display: "grid", gap: 6 }}>{items.map((item, idx) => <div key={`${item}-${idx}`} style={{ fontSize: 13, color: "#344054", wordBreak: "break-all" }}>{item}</div>)}</div>;
}

function FindingList(props: { title: string; items?: Array<Record<string, any>>; emptyText?: string }) {
  const items = props.items || [];
  return <div style={{ display: "grid", gap: 8 }}><div style={{ fontSize: 13, fontWeight: 700, color: "#344054" }}>{props.title}</div>{items.length === 0 ? <div style={{ color: "#667085", fontSize: 13 }}>{props.emptyText || "暂无命中"}</div> : items.map((item, index) => <div key={`${props.title}-${index}`} style={{ ...cardStyle, background: "#f8fafc" }}><div style={{ display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}><strong style={{ color: "#101828" }}>{item.rule_name || item.category || item.rule_id || `命中 ${index + 1}`}</strong><StatusPill text={riskLevelText(item.sensitivity || item.risk_level || "medium")} tone={statusTone(item.sensitivity || item.risk_level || "pending")} /></div><div style={{ marginTop: 8, display: "grid", gap: 6 }}>{item.matched_text ? <KeyValueRow label="命中内容" value={String(item.matched_text)} /> : null}{item.reason ? <KeyValueRow label="判定原因" value={String(item.reason)} /> : null}{item.location ? <KeyValueRow label="位置" value={String(item.location)} /> : null}{item.confidence !== undefined ? <KeyValueRow label="置信度" value={Number(item.confidence).toFixed(2)} /> : null}</div></div>)}</div>;
}

function EventCard(props: { item: AdminEventItem }) {
  const item = props.item;
  const summary = (item.event_details || {}).change_summary as { added?: string[]; removed?: string[]; more_added?: number; more_removed?: number } | undefined;
  const [expanded, setExpanded] = useState(false);
  const addedItems = summary?.added || [];
  const removedItems = summary?.removed || [];
  return <div style={cardStyle}><div style={{ display: "flex", justifyContent: "space-between", gap: 10, flexWrap: "wrap" }}><strong>{eventTypeText(item.event_type)}</strong><span style={{ fontSize: 12, color: "#667085" }}>{fmtTime(item.timestamp || item.created_at || null)}</span></div><div style={{ marginTop: 8, display: "grid", gap: 6 }}><KeyValueRow label="所属 Agent" value={item.agent_id} />{item.old_path ? <KeyValueRow label="原路径" value={item.old_path} /> : null}{item.new_path ? <KeyValueRow label="新路径" value={item.new_path} /> : null}{!item.old_path && !item.new_path && item.file_path ? <KeyValueRow label="文件路径" value={item.file_path} /> : null}{item.event_details?.copied_from ? <KeyValueRow label="复制来源" value={String(item.event_details.copied_from)} /> : null}</div>{summary ? <div style={{ marginTop: 10, display: "grid", gap: 8 }}><div style={{ fontSize: 13, fontWeight: 700, color: "#344054" }}>变更摘要</div>{addedItems.length ? <div style={{ display: "grid", gap: 4 }}><div style={{ fontSize: 12, color: "#1f7a45" }}>新增内容</div>{(expanded ? addedItems : addedItems.slice(0, 3)).map((line, idx) => <div key={`add-${idx}`} style={{ fontSize: 13, color: "#344054" }}>{line}</div>)}{!expanded && (summary.more_added || 0) > 0 ? <div style={{ fontSize: 12, color: "#667085" }}>还有 {summary.more_added} 项未展开</div> : null}</div> : null}{removedItems.length ? <div style={{ display: "grid", gap: 4 }}><div style={{ fontSize: 12, color: "#b42318" }}>删除内容</div>{(expanded ? removedItems : removedItems.slice(0, 3)).map((line, idx) => <div key={`del-${idx}`} style={{ fontSize: 13, color: "#344054" }}>{line}</div>)}{!expanded && (summary.more_removed || 0) > 0 ? <div style={{ fontSize: 12, color: "#667085" }}>还有 {summary.more_removed} 项未展开</div> : null}</div> : null}{((summary.more_added || 0) > 0 || (summary.more_removed || 0) > 0 || addedItems.length > 3 || removedItems.length > 3) ? <div><SmallButton onClick={() => setExpanded((value) => !value)}>{expanded ? "收起详情" : "查看详情"}</SmallButton></div> : null}</div> : null}</div>;
}

export default function DashboardCyber() {
  const baseUrl = API_BASE_URL;
  const [view, setView] = useState<ViewKey>("overview");
  const [loading, setLoading] = useState(false);
  const [errorText, setErrorText] = useState("");
  const [successText, setSuccessText] = useState("");
  const [adminToken, setAdminToken] = useState("");
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [assets, setAssets] = useState<AdminAssetItem[]>([]);
  const [assetsUpdatedAt, setAssetsUpdatedAt] = useState<number | null>(null);
  const [agents, setAgents] = useState<AdminAgentItem[]>([]);
  const [files, setFiles] = useState<AdminFileItem[]>([]);
  const [events, setEvents] = useState<AdminEventItem[]>([]);
  const [taskFailures, setTaskFailures] = useState<AdminTaskFailureItem[]>([]);
  const [uploadSessions, setUploadSessions] = useState<AdminUploadSessionItem[]>([]);
  const [upgrades, setUpgrades] = useState<AdminUpgradeItem[]>([]);
  const [ocrHealth, setOcrHealth] = useState<AdminOcrHealthResponse | null>(null);
  const [config, setConfig] = useState<AdminGlobalConfigResponse | null>(null);
  const [configDraft, setConfigDraft] = useState(() => buildConfigDraft(null));
  const [selectedAgentId, setSelectedAgentId] = useState("");
  const [selectedFileHash, setSelectedFileHash] = useState("");
  const [selectedFileDetail, setSelectedFileDetail] = useState<AdminFileDetailResponse | null>(null);
  const [sensitiveFiles, setSensitiveFiles] = useState<SensitiveFileItem[]>([]);
  const [sensitiveKeyword, setSensitiveKeyword] = useState("");
  const [sensitiveChangedOnly, setSensitiveChangedOnly] = useState(false);
  const [sensitiveDeletedOnly, setSensitiveDeletedOnly] = useState(false);
  const [selectedTrackedFileId, setSelectedTrackedFileId] = useState("");
  const [sensitiveHistory, setSensitiveHistory] = useState<SensitiveFileHistoryResponse | null>(null);
  const [selectedSensitiveVersionId, setSelectedSensitiveVersionId] = useState("");
  const [rules, setRules] = useState<DetectionRuleItem[]>([]);
  const [ruleTypeFilter, setRuleTypeFilter] = useState("");
  const [ruleEnabledFilter, setRuleEnabledFilter] = useState("");
  const [ruleKeywordFilter, setRuleKeywordFilter] = useState("");
  const [ruleDraft, setRuleDraft] = useState<RuleDraft>(() => emptyRuleDraft());
  const [ruleSaving, setRuleSaving] = useState(false);

  const navItems = [
    { key: "overview", label: "总览", hint: "查看服务健康、资产、Agent 和 OCR 状态" },
    { key: "assets", label: "资产探测", hint: "查看已发现主机并手动刷新探测结果" },
    { key: "agents", label: "Agent", hint: "查看注册 Agent、在线状态和配置版本" },
    { key: "files", label: "检测文件", hint: "结构化查看规则、OCR、LLM 与最终裁决" },
    { key: "sensitive", label: "敏感档案", hint: "查看敏感文件版本、事件、diff 和高亮下载" },
    { key: "rules", label: "检测规则", hint: "管理 keyword、OCR、LLM 检测规则" },
    { key: "events", label: "事件监控", hint: "查看重命名、移动、复制、覆盖、修改、删除事件" },
    { key: "runtime", label: "运行与升级", hint: "查看上传会话、升级结果与 OCR 服务" },
    { key: "config", label: "全局配置", hint: "管理扫描目录、监控目录与升级配置" },
  ];

  useEffect(() => {
    const saved = window.localStorage.getItem("safeguard_admin_token");
    if (saved) setAdminToken(saved);
    void api.getHealth(baseUrl).then(setHealth).catch(() => setHealth(null));
  }, [baseUrl]);

  useEffect(() => {
    if (!adminToken.trim()) return;
    void loadManagementData(adminToken.trim(), selectedAgentId);
  }, [selectedAgentId]);

  useEffect(() => {
    if (!adminToken || !selectedFileHash) {
      setSelectedFileDetail(null);
      return;
    }
    api.getAdminFileDetail(baseUrl, adminToken, selectedFileHash).then(setSelectedFileDetail).catch(() => setSelectedFileDetail(null));
  }, [adminToken, baseUrl, selectedFileHash]);

  useEffect(() => {
    void loadSensitiveFiles();
  }, [baseUrl, selectedAgentId, sensitiveChangedOnly, sensitiveDeletedOnly]);

  useEffect(() => {
    void loadRules();
  }, [baseUrl, ruleTypeFilter, ruleEnabledFilter]);

  useEffect(() => {
    if (!selectedTrackedFileId) {
      setSensitiveHistory(null);
      return;
    }
    api.getSensitiveFileHistory(baseUrl, selectedTrackedFileId).then((resp) => {
      setSensitiveHistory(resp);
      if (!selectedSensitiveVersionId && resp.versions?.[0]?.version_id) {
        setSelectedSensitiveVersionId(resp.versions[resp.versions.length - 1].version_id);
      }
    }).catch(() => setSensitiveHistory(null));
  }, [baseUrl, selectedTrackedFileId]);

  const filteredFiles = useMemo(() => {
    if (!selectedAgentId) return files;
    return files.filter((item) => (item.agents || []).includes(selectedAgentId));
  }, [files, selectedAgentId]);

  const filteredEvents = useMemo(() => {
    if (!selectedAgentId) return events;
    return events.filter((item) => item.agent_id === selectedAgentId);
  }, [events, selectedAgentId]);

  const overviewStats = useMemo(
    () => [
      { label: "服务状态", value: statusText(health?.status), hint: health?.version ? `版本 ${health.version}` : "健康检查" },
      { label: "发现主机", value: assets.length, hint: assetsUpdatedAt ? `最近刷新 ${fmtTime(assetsUpdatedAt)}` : "尚未探测" },
      { label: "纳管 Agent", value: agents.length, hint: "已注册到 V2 数据库" },
      { label: "在线 Agent", value: agents.filter((item) => (item.status || "").toLowerCase() === "online").length, hint: "心跳在阈值内" },
      { label: "检测文件", value: filteredFiles.length, hint: selectedAgentId ? "已按 Agent 过滤" : "全部文件" },
      { label: "监控事件", value: filteredEvents.length, hint: selectedAgentId ? "已按 Agent 过滤" : "最近上报事件" },
      { label: "上传会话", value: uploadSessions.length, hint: "分片上传记录" },
      { label: "OCR 服务", value: statusText(ocrHealth?.status), hint: ocrHealth?.service_url || "独立 OCR 服务" },
    ],
    [health, assets, assetsUpdatedAt, agents, filteredFiles.length, filteredEvents.length, uploadSessions.length, ocrHealth],
  );

  async function loadManagementData(token: string, agentId?: string) {
    setLoading(true);
    setErrorText("");
    try {
      const [assetResp, agentResp, fileResp, eventResp, taskResp, uploadResp, upgradeResp, ocrResp, configResp] = await Promise.all([
        api.getAdminAssets(baseUrl, token),
        api.getAdminAgents(baseUrl, token),
        api.getAdminFiles(baseUrl, token, false, agentId || undefined),
        api.getAdminEvents(baseUrl, token, 100, agentId || undefined),
        api.getAdminTaskFailures(baseUrl, token),
        api.getAdminUploadSessions(baseUrl, token, 100),
        api.getAdminUpgrades(baseUrl, token, 100),
        api.getAdminOcrHealth(baseUrl, token),
        api.getAdminConfigs(baseUrl, token),
      ]);
      setAssets(assetResp.items || []);
      setAssetsUpdatedAt(assetResp.updated_at || null);
      setAgents(agentResp.items || []);
      setFiles(fileResp.items || []);
      setEvents(eventResp.items || []);
      setTaskFailures(taskResp.items || []);
      setUploadSessions(uploadResp.items || []);
      setUpgrades(upgradeResp.items || []);
      setOcrHealth(ocrResp);
      setConfig(configResp);
      setConfigDraft(buildConfigDraft(configResp));
      if (!selectedFileHash && fileResp.items?.[0]?.file_hash) setSelectedFileHash(fileResp.items[0].file_hash);
      await loadSensitiveFiles();
      return true;
    } catch (error) {
      const detail = error instanceof Error ? error.message : "加载管理数据失败";
      setErrorText(detail === "admin authorization required" ? "需要管理员授权。请确认服务端已设置 SAFEGUARD_ADMIN_TOKEN，并且这里输入的值与服务端完全一致。" : translateErrorMessage(detail));
      return false;
    } finally {
      setLoading(false);
    }
  }

  async function loadSensitiveFiles() {
    try {
      const resp = await api.getSensitiveFiles(baseUrl, {
        agent_id: selectedAgentId || undefined,
        changed_only: sensitiveChangedOnly ? "true" : undefined,
        is_deleted: sensitiveDeletedOnly ? "true" : undefined,
        keyword: sensitiveKeyword || undefined,
        page: 1,
        page_size: 100,
      });
      setSensitiveFiles(resp.items || []);
      if (!selectedTrackedFileId && resp.items?.[0]?.tracked_file_id) {
        setSelectedTrackedFileId(resp.items[0].tracked_file_id);
      }
    } catch {
      setSensitiveFiles([]);
    }
  }

  async function loadRules() {
    try {
      const resp = await api.getRules(baseUrl, {
        rule_type: ruleTypeFilter || undefined,
        enabled: ruleEnabledFilter || undefined,
        keyword: ruleKeywordFilter || undefined,
      });
      setRules(resp.items || []);
    } catch (error) {
      setErrorText(translateErrorMessage(error instanceof Error ? error.message : "规则列表加载失败"));
    }
  }

  async function handleSaveRule() {
    try {
      setRuleSaving(true);
      setErrorText("");
      if (!ruleDraft.ruleName.trim()) throw new Error("规则名称不能为空");
      const payload = payloadFromDraft(ruleDraft);
      if (ruleDraft.ruleType === "keyword" && !payload.config.keywords?.length && !payload.config.regex_patterns?.length) throw new Error("关键字或正则表达式至少填写一项");
      if (ruleDraft.ruleType === "ocr" && !payload.config.keywords?.length) throw new Error("OCR 关键字列表不能为空");
      if (ruleDraft.ruleType === "llm" && !payload.config.prompt_template) throw new Error("Prompt 模板不能为空");
      if (ruleDraft.ruleId) {
        await api.updateRule(baseUrl, ruleDraft.ruleId, payload);
        setSuccessText("规则已更新。");
      } else {
        await api.createRule(baseUrl, payload);
        setSuccessText("规则已新增。");
      }
      setRuleDraft(emptyRuleDraft());
      await loadRules();
    } catch (error) {
      setErrorText(translateErrorMessage(error instanceof Error ? error.message : "规则保存失败"));
    } finally {
      setRuleSaving(false);
    }
  }

  async function handleDeleteRule(rule: DetectionRuleItem) {
    if (!window.confirm(`确认删除规则「${rule.rule_name}」吗？`)) return;
    try {
      await api.deleteRule(baseUrl, rule.rule_id);
      if (ruleDraft.ruleId === rule.rule_id) setRuleDraft(emptyRuleDraft());
      setSuccessText("规则已删除。");
      await loadRules();
    } catch (error) {
      setErrorText(translateErrorMessage(error instanceof Error ? error.message : "规则删除失败"));
    }
  }

  async function handleLoad() {
    if (!adminToken.trim()) {
      setErrorText("请先输入管理员令牌 SAFEGUARD_ADMIN_TOKEN。");
      return;
    }
    window.localStorage.setItem("safeguard_admin_token", adminToken.trim());
    const ok = await loadManagementData(adminToken.trim(), selectedAgentId);
    setSuccessText(ok ? "V2 管理数据已加载。" : "");
  }

  async function handleRefreshAssets() {
    if (!adminToken.trim()) {
      setErrorText("请先输入管理员令牌 SAFEGUARD_ADMIN_TOKEN。");
      return;
    }
    try {
      setLoading(true);
      setErrorText("");
      const resp = await api.refreshAdminAssets(baseUrl, adminToken.trim());
      setAssets(resp.items || []);
      setAssetsUpdatedAt(resp.updated_at || null);
      setSuccessText(`资产探测完成，共发现 ${resp.items?.length || 0} 台主机。`);
    } catch (error) {
      setErrorText(translateErrorMessage(error instanceof Error ? error.message : "资产探测失败"));
    } finally {
      setLoading(false);
    }
  }

  async function handleRetryFailure(id: number) {
    if (!adminToken.trim()) return;
    try {
      const result = await api.retryAdminTaskFailure(baseUrl, adminToken.trim(), id);
      setSuccessText(`失败任务已重新提交${result.task_id ? `：${result.task_id}` : ""}`);
      await loadManagementData(adminToken.trim(), selectedAgentId);
    } catch (error) {
      setErrorText(translateErrorMessage(error instanceof Error ? error.message : "重试失败"));
    }
  }

  async function handleSaveConfig() {
    if (!adminToken.trim()) {
      setErrorText("请先输入管理员令牌 SAFEGUARD_ADMIN_TOKEN。");
      return;
    }
    try {
      const updated = await api.updateAdminConfigs(baseUrl, adminToken.trim(), {
        scan_dirs: parseLines(configDraft.scanDirs),
        watch_dirs: parseLines(configDraft.watchDirs),
        include_extensions: parseLines(configDraft.includeExtensions),
        exclude_paths: parseLines(configDraft.excludePaths),
        heartbeat_interval_sec: Number(configDraft.heartbeatIntervalSec || 0) || undefined,
        max_file_size_mb: Number(configDraft.maxFileSizeMb || 0) || undefined,
        upgrade: JSON.parse(configDraft.upgradeJson || "{}"),
      });
      setConfig({ config_version: updated.config_version, config: updated.config, agent_overrides: config?.agent_overrides || [] });
      setSuccessText(`全局配置已更新到版本 ${updated.config_version}。`);
      await loadManagementData(adminToken.trim(), selectedAgentId);
    } catch (error) {
      setErrorText(translateErrorMessage(error instanceof Error ? error.message : "配置更新失败"));
    }
  }

  const selectedFile = filteredFiles.find((item) => item.file_hash === selectedFileHash) || filteredFiles[0] || null;
  const selectedSensitiveVersion = (sensitiveHistory?.versions || []).find((item) => item.version_id === selectedSensitiveVersionId) || (sensitiveHistory?.versions || [])[0] || null;
  const openDownload = (path?: string) => {
    if (!path) return;
    window.open(`${baseUrl}${path}`, "_blank", "noopener,noreferrer");
  };

  useEffect(() => {
    if (selectedFile && selectedFile.file_hash !== selectedFileHash) setSelectedFileHash(selectedFile.file_hash);
  }, [selectedFile, selectedFileHash]);

  return (
    <div style={{ minHeight: "100vh", display: "flex", background: "#f5f7fb" }}>
      <SidebarNav items={navItems} activeKey={view} onChange={(key) => setView(key as ViewKey)} />
      <main style={{ flex: 1, minWidth: 0, padding: 24 }}>
        <div style={{ maxWidth: 1680, margin: "0 auto", display: "grid", gap: 16 }}>
          <div style={{ padding: 20, display: "flex", justifyContent: "space-between", gap: 20, alignItems: "center", borderRadius: 18, border: "1px solid #eaecf0", background: "linear-gradient(135deg, rgba(21,94,239,0.08) 0%, rgba(15,23,42,0.04) 100%), #fff" }}>
            <div>
              <div style={{ fontSize: 28, fontWeight: 900, color: "#101828" }}>SafeGuard 服务器 V2 控制台</div>
              <div style={{ marginTop: 6, fontSize: 14, color: "#667085" }}>当前界面仅使用新的 <code>/api/v1/*</code> 服务端框架，按结构化方式展示资产、Agent、检测、事件和运行数据。</div>
            </div>
            <div style={{ display: "grid", gap: 10, minWidth: 420 }}>
              <input type="password" value={adminToken} onChange={(e) => setAdminToken(e.target.value)} placeholder="请输入管理员令牌 SAFEGUARD_ADMIN_TOKEN" style={inputStyle} />
              <div style={{ display: "grid", gridTemplateColumns: "1fr auto auto", gap: 10 }}>
                <select value={selectedAgentId} onChange={(e) => setSelectedAgentId(e.target.value)} style={inputStyle}>
                  <option value="">显示全部 Agent</option>
                  {agents.map((item) => <option key={item.agent_id} value={item.agent_id}>{(item.hostname || item.agent_id).slice(0, 80)}</option>)}
                </select>
                <SmallButton onClick={() => void api.getHealth(baseUrl).then(setHealth).catch(() => setHealth(null))}>刷新健康状态</SmallButton>
                <SmallButton primary onClick={() => void handleLoad()}>加载管理数据</SmallButton>
              </div>
            </div>
          </div>

          {errorText ? <div style={{ padding: 14, borderRadius: 14, border: "1px solid #fecdca", background: "#fef3f2", color: "#b42318" }}>{errorText}</div> : null}
          {successText ? <div style={{ padding: 14, borderRadius: 14, border: "1px solid #abefc6", background: "#ecfdf3", color: "#1f7a45" }}>{successText}</div> : null}

          <SummaryStrip items={overviewStats} />

          {view === "overview" ? <SectionCard title="总体概览"><div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}><div style={{ display: "grid", gap: 8 }}><KeyValueRow label="服务状态" value={statusText(health?.status)} /><KeyValueRow label="服务版本" value={health?.version || "-"} /><KeyValueRow label="当前筛选 Agent" value={selectedAgentId || "全部"} /><KeyValueRow label="当前配置版本" value={config?.config_version || 0} /></div><div style={{ display: "grid", gap: 8 }}><KeyValueRow label="发现主机" value={assets.length} /><KeyValueRow label="纳管 Agent" value={agents.length} /><KeyValueRow label="敏感文件" value={filteredFiles.filter((item) => item.is_sensitive).length} /><KeyValueRow label="OCR 服务" value={statusText(ocrHealth?.status)} /></div></div></SectionCard> : null}

          {view === "assets" ? <SectionCard title="资产探测结果" extra={<div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}><span style={{ fontSize: 12, color: "#667085" }}>最近刷新：{fmtTime(assetsUpdatedAt)}</span><SmallButton primary onClick={() => void handleRefreshAssets()}>重新探测</SmallButton></div>}><div style={{ display: "grid", gap: 10 }}>{assets.map((item) => <div key={item.ip} style={cardStyle}><div style={{ display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}><strong>{item.hostname || item.ip}</strong><StatusPill text={item.is_alive ? "在线" : "未知"} tone={item.is_alive ? "ok" : "muted"} /></div><div style={{ marginTop: 8, display: "grid", gap: 6 }}><KeyValueRow label="IP / MAC" value={`${item.ip || "-"} / ${item.mac || "-"}`} /><KeyValueRow label="主机名来源" value={item.hostname_source || "-"} /><KeyValueRow label="系统判断" value={`${item.os_type || "unknown"}${item.os_confidence ? ` (${item.os_confidence}%)` : ""}`} /><KeyValueRow label="发现来源" value={item.discovery_tool || "-"} /></div></div>)}{assets.length === 0 ? <div style={{ color: "#667085" }}>当前没有资产探测结果，请点击“重新探测”。</div> : null}</div></SectionCard> : null}

          {view === "agents" ? <SectionCard title="Agent 列表"><div style={{ display: "grid", gap: 10 }}>{agents.map((item) => <div key={item.agent_id} style={cardStyle}><div style={{ display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}><strong>{item.hostname || item.agent_id}</strong><StatusPill text={statusText(item.status)} tone={statusTone(item.status)} /></div><div style={{ marginTop: 8, display: "grid", gap: 6 }}><KeyValueRow label="Agent ID" value={item.agent_id} /><KeyValueRow label="IP / MAC" value={`${item.ip || "-"} / ${item.mac_address || "-"}`} /><KeyValueRow label="版本 / 配置" value={`${item.agent_version || "-"} / v${item.config_version || 0}`} /><KeyValueRow label="最近心跳" value={fmtTime(item.last_heartbeat)} /></div></div>)}{agents.length === 0 ? <div style={{ color: "#667085" }}>当前还没有 V2 Agent 记录。</div> : null}</div></SectionCard> : null}

          {view === "files" ? <div style={{ display: "grid", gridTemplateColumns: "0.95fr 1.25fr", gap: 16 }}><SectionCard title="检测文件列表"><div style={{ display: "grid", gap: 10, maxHeight: 640, overflow: "auto" }}>{filteredFiles.map((item) => <button key={item.file_hash} onClick={() => setSelectedFileHash(item.file_hash)} style={{ textAlign: "left", border: selectedFileHash === item.file_hash ? "1px solid #155eef" : "1px solid #eaecf0", background: "#fff", borderRadius: 12, padding: 12, cursor: "pointer" }}><div style={{ display: "flex", justifyContent: "space-between", gap: 10 }}><strong>{item.file_name || item.file_hash}</strong><StatusPill text={riskLevelText(item.risk_level || (item.is_sensitive ? "high" : "normal"))} tone={item.is_sensitive ? "error" : "ok"} /></div><div style={{ marginTop: 8, display: "grid", gap: 6 }}><KeyValueRow label="文件哈希" value={item.file_hash.slice(0, 16)} /><KeyValueRow label="类型 / 大小" value={`${item.file_type || "-"} / ${fmtSize(item.file_size)}`} /><KeyValueRow label="检测状态" value={statusText(item.detection_status)} /><KeyValueRow label="所属 Agent" value={(item.agents || []).join("、") || "-"} /></div></button>)}{filteredFiles.length === 0 ? <div style={{ color: "#667085" }}>当前没有检测文件。</div> : null}</div></SectionCard><SectionCard title="文件详情">{selectedFileDetail ? <div style={{ display: "grid", gap: 16 }}><div style={{ display: "grid", gap: 6 }}><KeyValueRow label="文件名" value={selectedFileDetail.file_name || "-"} /><KeyValueRow label="文件哈希" value={selectedFileDetail.file_hash} /><KeyValueRow label="类型 / 大小" value={`${selectedFileDetail.file_type || "-"} / ${fmtSize(selectedFileDetail.file_size)}`} /><KeyValueRow label="检测状态" value={statusText(selectedFileDetail.detection_status)} /><KeyValueRow label="风险等级" value={riskLevelText(selectedFileDetail.risk_level)} /><KeyValueRow label="最终裁决" value={selectedFileDetail.final_decision?.reason || "-"} /><KeyValueRow label="综合置信度" value={selectedFileDetail.confidence !== undefined && selectedFileDetail.confidence !== null ? Number(selectedFileDetail.confidence).toFixed(2) : "-"} /></div><div style={{ padding: 12, borderRadius: 12, background: "#f8fafc", border: "1px solid #e2e8f0", fontSize: 13, lineHeight: 1.7 }}>{selectedFileDetail.explanation_summary || "暂无摘要。"}</div><SectionCard title="当前归属"><div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}><div><div style={{ fontSize: 13, fontWeight: 700, marginBottom: 8 }}>所属 Agent</div><MultiLineList items={selectedFileDetail.agents || []} emptyText="暂无 Agent 关联" /></div><div><div style={{ fontSize: 13, fontWeight: 700, marginBottom: 8 }}>当前路径</div><MultiLineList items={selectedFileDetail.current_paths || []} emptyText="暂无路径关联" /></div></div></SectionCard><div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}><FindingList title="规则命中" items={selectedFileDetail.rule_hits || []} emptyText="未命中规则。" /><FindingList title="OCR 命中" items={selectedFileDetail.ocr_findings || []} emptyText="未命中 OCR 规则。" /><FindingList title="LLM 复判" items={selectedFileDetail.llm_findings || []} emptyText={selectedFileDetail.llm_summary || "未触发或未命中 LLM 判定。"} /></div>{selectedFileDetail.llm_summary ? <div style={{ ...cardStyle, background: "#f8fafc" }}><div style={{ fontSize: 13, fontWeight: 700, marginBottom: 8 }}>LLM 总裁决</div><div style={{ fontSize: 13, color: "#344054", lineHeight: 1.7 }}>{selectedFileDetail.llm_summary}</div></div> : null}<div style={{ display: "grid", gap: 8 }}><div style={{ fontSize: 13, fontWeight: 700, color: "#344054" }}>块级定位</div>{(selectedFileDetail.per_block_locations || []).length === 0 ? <div style={{ color: "#667085", fontSize: 13 }}>当前没有可展示的块级定位。</div> : (selectedFileDetail.per_block_locations || []).slice(0, 20).map((item, index) => <div key={`block-${index}`} style={{ ...cardStyle, background: "#f8fafc" }}><KeyValueRow label="位置" value={String(item.location || "-")} /><KeyValueRow label="来源" value={String(item.source_type || "-")} /><div style={{ marginTop: 8, fontSize: 13, color: "#344054", lineHeight: 1.7 }}>{String(item.preview || "暂无预览")}</div></div>)}</div></div> : <div style={{ color: "#667085" }}>请先从左侧选择一个文件。</div>}</SectionCard></div> : null}

          {view === "sensitive" ? <div style={{ display: "grid", gridTemplateColumns: "0.9fr 1.3fr", gap: 16 }}>
            <SectionCard title="敏感文件档案" extra={<SmallButton onClick={() => void loadSensitiveFiles()}>刷新</SmallButton>}>
              <div style={{ display: "grid", gap: 10 }}>
                <div style={{ display: "grid", gridTemplateColumns: "1fr auto", gap: 8 }}>
                  <input value={sensitiveKeyword} onChange={(event) => setSensitiveKeyword(event.target.value)} placeholder="按名称或路径搜索" style={inputStyle} />
                  <SmallButton onClick={() => void loadSensitiveFiles()}>搜索</SmallButton>
                </div>
                <div style={{ display: "flex", gap: 12, flexWrap: "wrap", fontSize: 13, color: "#344054" }}>
                  <label><input type="checkbox" checked={sensitiveChangedOnly} onChange={(event) => setSensitiveChangedOnly(event.target.checked)} /> 仅看有变更</label>
                  <label><input type="checkbox" checked={sensitiveDeletedOnly} onChange={(event) => setSensitiveDeletedOnly(event.target.checked)} /> 仅看已删除</label>
                </div>
                <div style={{ display: "grid", gap: 10, maxHeight: 620, overflow: "auto" }}>
                  {sensitiveFiles.map((item) => <button key={item.tracked_file_id} onClick={() => { setSelectedTrackedFileId(item.tracked_file_id); setSelectedSensitiveVersionId(""); }} style={{ textAlign: "left", border: selectedTrackedFileId === item.tracked_file_id ? "1px solid #155eef" : "1px solid #eaecf0", background: "#fff", borderRadius: 8, padding: 12, cursor: "pointer" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", gap: 10 }}>
                      <strong style={{ wordBreak: "break-word" }}>{item.current_name}</strong>
                      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", justifyContent: "flex-end" }}>
                        <StatusPill text={riskLevelText(item.sensitive_level || "sensitive")} tone={sensitiveTone(item.sensitive_level)} />
                        {item.is_deleted ? <StatusPill text="已删除" tone="error" /> : null}
                      </div>
                    </div>
                    <div style={{ marginTop: 8, display: "grid", gap: 6 }}>
                      <KeyValueRow label="类型 / 等级" value={`${item.file_type || "-"} / ${riskLevelText(item.sensitive_level)}`} />
                      <KeyValueRow label="最新事件" value={eventTypeText(item.latest_event_type)} />
                      <KeyValueRow label="最新版本" value={`v${item.latest_version_no || 0}`} />
                      <KeyValueRow label="最近更新" value={fmtTime(item.last_seen_at)} />
                      <div style={{ fontSize: 12, color: "#667085", wordBreak: "break-all" }}>{item.current_path}</div>
                    </div>
                  </button>)}
                  {sensitiveFiles.length === 0 ? <div style={{ color: "#667085" }}>当前没有敏感文件档案。</div> : null}
                </div>
              </div>
            </SectionCard>
            <SectionCard title="版本历史与下载">
              {sensitiveHistory ? <div style={{ display: "grid", gap: 14 }}>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                  <div style={{ display: "grid", gap: 6 }}>
                    <KeyValueRow label="当前名称" value={sensitiveHistory.file.current_name} />
                    <KeyValueRow label="原始名称" value={sensitiveHistory.file.original_name} />
                    <KeyValueRow label="修改次数" value={sensitiveHistory.file.modify_count} />
                    <KeyValueRow label="重命名次数" value={sensitiveHistory.file.rename_count} />
                  </div>
                  <div style={{ display: "grid", gap: 6 }}>
                    <KeyValueRow label="当前路径" value={sensitiveHistory.file.current_path} />
                    <KeyValueRow label="原始路径" value={sensitiveHistory.file.original_path} />
                    <KeyValueRow label="状态" value={sensitiveHistory.current_state === "deleted" ? "已删除" : "正常"} />
                    <KeyValueRow label="删除时间" value={fmtTime(sensitiveHistory.file.deleted_at)} />
                  </div>
                </div>
                <div style={{ display: "grid", gap: 8 }}>
                  <div style={{ fontSize: 13, fontWeight: 800, color: "#344054" }}>时间线</div>
                  {sensitiveHistory.versions.map((version) => <div key={version.version_id} style={{ borderLeft: selectedSensitiveVersionId === version.version_id ? "4px solid #155eef" : "4px solid #d0d5dd", padding: "8px 0 8px 12px", display: "grid", gap: 8 }}>
                    <button onClick={() => setSelectedSensitiveVersionId(version.version_id)} style={{ textAlign: "left", border: "0", background: "transparent", padding: 0, cursor: "pointer" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", gap: 10, flexWrap: "wrap" }}>
                        <strong>{eventTypeText(version.event_type)} {version.version_no ? `v${version.version_no}` : ""}</strong>
                        <span style={{ fontSize: 12, color: "#667085" }}>{fmtTime(version.snapshot_time)}</span>
                      </div>
                      <div style={{ marginTop: 4, fontSize: 13, color: "#344054", lineHeight: 1.6 }}>{version.change_summary}</div>
                      {version.snapshot_retention_note ? <div style={{ marginTop: 4, fontSize: 12, color: "#b54708" }}>{version.snapshot_retention_note}</div> : null}
                    </button>
                    <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                      <SmallButton disabled={!version.can_download} onClick={() => openDownload(version.download_url)}>下载原文件</SmallButton>
                      <SmallButton disabled={!version.has_highlight} onClick={() => openDownload(version.highlight_download_url)}>下载高亮文件</SmallButton>
                      <SmallButton disabled={!version.has_diff} onClick={() => openDownload(version.diff_download_url)}>下载 diff</SmallButton>
                    </div>
                  </div>)}
                </div>
                {selectedSensitiveVersion ? <div style={{ ...cardStyle, background: "#f8fafc" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
                    <strong>版本详情 v{selectedSensitiveVersion.version_no}</strong>
                    <StatusPill text={eventTypeText(selectedSensitiveVersion.event_type)} tone={statusTone(selectedSensitiveVersion.event_type)} />
                  </div>
                  <div style={{ marginTop: 10, display: "grid", gap: 8 }}>
                    <KeyValueRow label="摘要" value={selectedSensitiveVersion.change_summary} />
                    <KeyValueRow label="路径" value={selectedSensitiveVersion.path_at_that_time} />
                    <KeyValueRow label="文件哈希" value={selectedSensitiveVersion.content_hash || "-"} />
                    <KeyValueRow label="高亮类型" value={selectedSensitiveVersion.artifact_type || "-"} />
                    <FindingList title="敏感命中" items={selectedSensitiveVersion.sensitive_hits || []} emptyText="该版本没有命中明细。" />
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                      <div>
                        <div style={{ fontSize: 13, fontWeight: 700, color: "#1f7a45", marginBottom: 6 }}>新增文本</div>
                        <MultiLineList items={(selectedSensitiveVersion.change_detail_json?.added_texts || []).map(String)} emptyText="无新增文本" />
                      </div>
                      <div>
                        <div style={{ fontSize: 13, fontWeight: 700, color: "#b42318", marginBottom: 6 }}>删除文本</div>
                        <MultiLineList items={(selectedSensitiveVersion.change_detail_json?.removed_texts || []).map(String)} emptyText="无删除文本" />
                      </div>
                    </div>
                    {(selectedSensitiveVersion.change_detail_json?.modified_blocks || []).slice(0, 5).map((block: Record<string, any>, index: number) => <div key={`mod-${index}`} style={{ ...cardStyle, background: "#fff" }}>
                      <KeyValueRow label="修改前" value={String(block.before || "-")} />
                      <KeyValueRow label="修改后" value={String(block.after || "-")} />
                    </div>)}
                  </div>
                </div> : null}
              </div> : <div style={{ color: "#667085" }}>请先从左侧选择一个敏感文件档案。</div>}
            </SectionCard>
          </div> : null}

          {view === "rules" ? <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
            <SectionCard title="检测规则列表" extra={<SmallButton onClick={() => void loadRules()}>刷新</SmallButton>}>
              <div style={{ display: "grid", gap: 10 }}>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 150px 150px auto", gap: 8 }}>
                  <input value={ruleKeywordFilter} onChange={(event) => setRuleKeywordFilter(event.target.value)} placeholder="按规则名称搜索" style={inputStyle} />
                  <select value={ruleTypeFilter} onChange={(event) => setRuleTypeFilter(event.target.value)} style={inputStyle}>
                    <option value="">全部类型</option>
                    <option value="keyword">keyword</option>
                    <option value="ocr">ocr</option>
                    <option value="llm">llm</option>
                  </select>
                  <select value={ruleEnabledFilter} onChange={(event) => setRuleEnabledFilter(event.target.value)} style={inputStyle}>
                    <option value="">全部状态</option>
                    <option value="true">启用</option>
                    <option value="false">停用</option>
                  </select>
                  <SmallButton onClick={() => void loadRules()}>搜索</SmallButton>
                </div>
                <div style={{ display: "grid", gap: 10, maxHeight: 660, overflow: "auto" }}>
                  {rules.map((rule) => <div key={rule.rule_id} style={cardStyle}>
                    <div style={{ display: "flex", justifyContent: "space-between", gap: 10, flexWrap: "wrap" }}>
                      <strong>{rule.rule_name}</strong>
                      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                        <StatusPill text={rule.rule_type} tone={rule.rule_type === "llm" ? "pending" : rule.rule_type === "ocr" ? "muted" : "ok"} />
                        <StatusPill text={rule.enabled ? "启用" : "停用"} tone={rule.enabled ? "ok" : "muted"} />
                      </div>
                    </div>
                    <div style={{ marginTop: 8, display: "grid", gap: 6 }}>
                      <KeyValueRow label="优先级" value={rule.priority} />
                      <KeyValueRow label="更新时间" value={fmtTime(rule.updated_at)} />
                      <KeyValueRow label="描述" value={rule.description || "-"} />
                    </div>
                    <div style={{ marginTop: 10, display: "flex", gap: 8 }}>
                      <SmallButton onClick={() => setRuleDraft(draftFromRule(rule))}>编辑</SmallButton>
                      <SmallButton onClick={() => void handleDeleteRule(rule)}>删除</SmallButton>
                    </div>
                  </div>)}
                  {rules.length === 0 ? <div style={{ color: "#667085" }}>当前没有检测规则。</div> : null}
                </div>
              </div>
            </SectionCard>
            <SectionCard title={ruleDraft.ruleId ? "编辑规则" : "新增规则"}>
              <div style={{ display: "grid", gap: 12 }}>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 160px 120px", gap: 10 }}>
                  <input value={ruleDraft.ruleName} onChange={(event) => setRuleDraft((prev) => ({ ...prev, ruleName: event.target.value }))} placeholder="规则名称" style={inputStyle} />
                  <select value={ruleDraft.ruleType} onChange={(event) => setRuleDraft((prev) => ({ ...prev, ruleType: event.target.value as RuleDraft["ruleType"] }))} style={inputStyle}>
                    <option value="keyword">keyword</option>
                    <option value="ocr">ocr</option>
                    <option value="llm">llm</option>
                  </select>
                  <input value={ruleDraft.priority} onChange={(event) => setRuleDraft((prev) => ({ ...prev, priority: event.target.value }))} placeholder="优先级" style={inputStyle} />
                </div>
                <label style={{ fontSize: 13, color: "#344054" }}><input type="checkbox" checked={ruleDraft.enabled} onChange={(event) => setRuleDraft((prev) => ({ ...prev, enabled: event.target.checked }))} /> 启用规则</label>
                <textarea value={ruleDraft.description} onChange={(event) => setRuleDraft((prev) => ({ ...prev, description: event.target.value }))} placeholder="规则描述" style={{ ...textareaStyle, minHeight: 80 }} />
                {ruleDraft.ruleType === "keyword" ? <div style={{ display: "grid", gap: 10 }}>
                  <div>
                    <div style={{ fontSize: 12, color: "#667085", marginBottom: 6 }}>关键字列表，每行一项</div>
                    <textarea value={ruleDraft.keywordsText} onChange={(event) => setRuleDraft((prev) => ({ ...prev, keywordsText: event.target.value }))} style={textareaStyle} />
                  </div>
                  <div>
                    <div style={{ fontSize: 12, color: "#667085", marginBottom: 6 }}>正则表达式列表，每行一项</div>
                    <textarea value={ruleDraft.regexPatternsText} onChange={(event) => setRuleDraft((prev) => ({ ...prev, regexPatternsText: event.target.value }))} style={{ ...textareaStyle, minHeight: 90 }} />
                  </div>
                  <select value={ruleDraft.matchMode} onChange={(event) => setRuleDraft((prev) => ({ ...prev, matchMode: event.target.value as RuleDraft["matchMode"] }))} style={inputStyle}>
                    <option value="contains">contains</option>
                    <option value="exact">exact</option>
                    <option value="regex">regex</option>
                  </select>
                </div> : null}
                {ruleDraft.ruleType === "ocr" ? <div style={{ display: "grid", gap: 10 }}>
                  <div>
                    <div style={{ fontSize: 12, color: "#667085", marginBottom: 6 }}>OCR 关键字列表，每行一项</div>
                    <textarea value={ruleDraft.keywordsText} onChange={(event) => setRuleDraft((prev) => ({ ...prev, keywordsText: event.target.value }))} style={textareaStyle} />
                  </div>
                  <div>
                    <div style={{ fontSize: 12, color: "#667085", marginBottom: 6 }}>适用文件类型，每行一项</div>
                    <textarea value={ruleDraft.applyFileTypesText} onChange={(event) => setRuleDraft((prev) => ({ ...prev, applyFileTypesText: event.target.value }))} style={{ ...textareaStyle, minHeight: 90 }} />
                  </div>
                  <label style={{ fontSize: 13, color: "#344054" }}><input type="checkbox" checked={ruleDraft.caseSensitive} onChange={(event) => setRuleDraft((prev) => ({ ...prev, caseSensitive: event.target.checked }))} /> 区分大小写</label>
                </div> : null}
                {ruleDraft.ruleType === "llm" ? <div style={{ display: "grid", gap: 10 }}>
                  <div>
                    <div style={{ fontSize: 12, color: "#667085", marginBottom: 6 }}>Prompt 模板</div>
                    <textarea value={ruleDraft.promptTemplate} onChange={(event) => setRuleDraft((prev) => ({ ...prev, promptTemplate: event.target.value }))} style={{ ...textareaStyle, minHeight: 180 }} />
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 120px", gap: 10 }}>
                    <input value={ruleDraft.labelIfMatched} onChange={(event) => setRuleDraft((prev) => ({ ...prev, labelIfMatched: event.target.value }))} placeholder="匹配标签" style={inputStyle} />
                    <input value={ruleDraft.threshold} onChange={(event) => setRuleDraft((prev) => ({ ...prev, threshold: event.target.value }))} placeholder="threshold" style={inputStyle} />
                  </div>
                </div> : null}
                <div style={{ display: "flex", justifyContent: "space-between", gap: 10, flexWrap: "wrap" }}>
                  <SmallButton onClick={() => setRuleDraft(emptyRuleDraft())}>清空</SmallButton>
                  <SmallButton primary disabled={ruleSaving} onClick={() => void handleSaveRule()}>{ruleSaving ? "保存中..." : "保存规则"}</SmallButton>
                </div>
              </div>
            </SectionCard>
          </div> : null}

          {view === "events" ? <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}><SectionCard title="最近事件"><div style={{ display: "grid", gap: 10, maxHeight: 640, overflow: "auto" }}>{filteredEvents.map((item) => <EventCard key={item.event_id} item={item} />)}{filteredEvents.length === 0 ? <div style={{ color: "#667085" }}>当前没有最近事件。</div> : null}</div></SectionCard><SectionCard title="失败任务"><div style={{ display: "grid", gap: 10, maxHeight: 640, overflow: "auto" }}>{taskFailures.map((item) => <div key={item.id} style={cardStyle}><div style={{ display: "flex", justifyContent: "space-between", gap: 10, flexWrap: "wrap" }}><strong>{item.task_name}</strong><SmallButton onClick={() => void handleRetryFailure(item.id)}>重新提交</SmallButton></div><div style={{ marginTop: 8, fontSize: 13, color: "#b42318", whiteSpace: "pre-wrap" }}>{translateErrorMessage(item.error_message)}</div></div>)}{taskFailures.length === 0 ? <div style={{ color: "#667085" }}>当前没有失败任务。</div> : null}</div></SectionCard></div> : null}

          {view === "runtime" ? <div style={{ display: "grid", gap: 16 }}><div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}><SectionCard title="上传会话"><div style={{ display: "grid", gap: 10, maxHeight: 420, overflow: "auto" }}>{uploadSessions.map((item) => <div key={item.session_id} style={cardStyle}><div style={{ display: "flex", justifyContent: "space-between", gap: 8, flexWrap: "wrap" }}><strong>{item.file_name || item.file_hash}</strong><StatusPill text={statusText(item.status)} tone={statusTone(item.status)} /></div><div style={{ marginTop: 8, display: "grid", gap: 6 }}><KeyValueRow label="会话 ID" value={item.session_id} /><KeyValueRow label="所属 Agent" value={item.agent_id} /><KeyValueRow label="上传分片" value={`${item.uploaded_chunks?.length || 0} / ${item.total_chunks || 0}`} /><KeyValueRow label="更新时间" value={fmtTime(item.updated_at)} /></div></div>)}{uploadSessions.length === 0 ? <div style={{ color: "#667085" }}>当前没有上传会话。</div> : null}</div></SectionCard><SectionCard title="升级结果"><div style={{ display: "grid", gap: 10, maxHeight: 420, overflow: "auto" }}>{upgrades.map((item, index) => <div key={`${item.agent_id}-${index}`} style={cardStyle}><div style={{ display: "flex", justifyContent: "space-between", gap: 10, flexWrap: "wrap" }}><strong>{item.hostname || item.agent_id}</strong><StatusPill text={item.upgrade_report?.success ? "成功" : "失败"} tone={item.upgrade_report?.success ? "ok" : "error"} /></div><div style={{ marginTop: 8, display: "grid", gap: 6 }}><KeyValueRow label="当前版本" value={item.agent_version || "-"} /><KeyValueRow label="目标版本" value={item.upgrade_target || item.upgrade_report?.new_version || "-"} /><KeyValueRow label="更新时间" value={fmtTime(item.updated_at)} /></div></div>)}{upgrades.length === 0 ? <div style={{ color: "#667085" }}>当前没有升级记录。</div> : null}</div></SectionCard></div><SectionCard title="OCR 服务状态"><div style={{ display: "grid", gap: 8 }}><KeyValueRow label="状态" value={<StatusPill text={statusText(ocrHealth?.status)} tone={ocrHealth?.status === "ok" ? "ok" : "error"} />} /><KeyValueRow label="服务地址" value={ocrHealth?.service_url || "-"} /><KeyValueRow label="错误信息" value={ocrHealth?.error ? translateErrorMessage(ocrHealth.error) : "-"} /></div></SectionCard></div> : null}

          {view === "config" ? <SectionCard title="全局配置"><div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}><div style={{ display: "grid", gap: 12 }}><div><div style={{ fontSize: 12, color: "#667085", marginBottom: 6 }}>扫描目录 scan_dirs</div><textarea value={configDraft.scanDirs} onChange={(e) => setConfigDraft((prev) => ({ ...prev, scanDirs: e.target.value }))} style={textareaStyle} /></div><div><div style={{ fontSize: 12, color: "#667085", marginBottom: 6 }}>监控目录 watch_dirs</div><textarea value={configDraft.watchDirs} onChange={(e) => setConfigDraft((prev) => ({ ...prev, watchDirs: e.target.value }))} style={textareaStyle} /></div><div><div style={{ fontSize: 12, color: "#667085", marginBottom: 6 }}>包含扩展名 include_extensions</div><textarea value={configDraft.includeExtensions} onChange={(e) => setConfigDraft((prev) => ({ ...prev, includeExtensions: e.target.value }))} style={textareaStyle} /></div><div><div style={{ fontSize: 12, color: "#667085", marginBottom: 6 }}>排除路径 exclude_paths</div><textarea value={configDraft.excludePaths} onChange={(e) => setConfigDraft((prev) => ({ ...prev, excludePaths: e.target.value }))} style={textareaStyle} /></div></div><div style={{ display: "grid", gap: 12 }}><div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}><div><div style={{ fontSize: 12, color: "#667085", marginBottom: 6 }}>心跳间隔 heartbeat_interval_sec</div><input value={configDraft.heartbeatIntervalSec} onChange={(e) => setConfigDraft((prev) => ({ ...prev, heartbeatIntervalSec: e.target.value }))} style={inputStyle} /></div><div><div style={{ fontSize: 12, color: "#667085", marginBottom: 6 }}>最大文件大小 max_file_size_mb</div><input value={configDraft.maxFileSizeMb} onChange={(e) => setConfigDraft((prev) => ({ ...prev, maxFileSizeMb: e.target.value }))} style={inputStyle} /></div></div><div><div style={{ fontSize: 12, color: "#667085", marginBottom: 6 }}>升级配置 upgrade</div><textarea value={configDraft.upgradeJson} onChange={(e) => setConfigDraft((prev) => ({ ...prev, upgradeJson: e.target.value }))} style={{ ...textareaStyle, minHeight: 260 }} /></div><div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, flexWrap: "wrap" }}><div style={{ fontSize: 12, color: "#667085" }}>当前版本：{config?.config_version || 0}</div><SmallButton primary onClick={() => void handleSaveConfig()}>保存配置</SmallButton></div></div></div></SectionCard> : null}

          {loading ? <div style={{ textAlign: "center", color: "#667085", fontSize: 13 }}>正在加载 V2 管理数据，请稍候...</div> : null}
        </div>
      </main>
    </div>
  );
}
