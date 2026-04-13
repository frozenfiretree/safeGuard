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
  SensitiveFileListResponse,
} from "./types";

type HttpMethod = "GET" | "POST" | "PUT" | "DELETE";

async function request<T>(
  baseUrl: string,
  path: string,
  options?: {
    method?: HttpMethod;
    body?: any;
    headers?: Record<string, string>;
  }
): Promise<T> {
  const method = options?.method || "GET";
  const headers: Record<string, string> = {
    ...(options?.headers || {}),
  };

  let body: BodyInit | undefined;
  if (options?.body !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(options.body);
  }

  const resp = await fetch(`${baseUrl}${path}`, { method, headers, body });
  const text = await resp.text();
  let data: any = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }

  if (!resp.ok) {
    const detail =
      typeof data === "object" && data
        ? data.detail || data.message || JSON.stringify(data)
        : String(data || resp.statusText || "request failed");
    throw new Error(detail);
  }

  return data as T;
}

function buildQuery(params: Record<string, any>) {
  const q = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === null || value === "") return;
    q.set(key, String(value));
  });
  const result = q.toString();
  return result ? `?${result}` : "";
}

function adminHeaders(adminToken: string) {
  return { Authorization: `Bearer ${adminToken}` };
}

export const api = {
  async getHealth(baseUrl: string): Promise<HealthResponse> {
    return request<HealthResponse>(baseUrl, "/api/v1/health");
  },

  async getAdminAgents(baseUrl: string, adminToken: string): Promise<{ items: AdminAgentItem[] }> {
    return request<{ items: AdminAgentItem[] }>(baseUrl, "/api/v1/admin/agents", {
      headers: adminHeaders(adminToken),
    });
  },

  async getAdminAssets(baseUrl: string, adminToken: string): Promise<{ items: AdminAssetItem[]; updated_at?: number | null }> {
    return request<{ items: AdminAssetItem[]; updated_at?: number | null }>(baseUrl, "/api/v1/admin/assets", {
      headers: adminHeaders(adminToken),
    });
  },

  async refreshAdminAssets(baseUrl: string, adminToken: string): Promise<{ items: AdminAssetItem[]; updated_at?: number | null }> {
    return request<{ items: AdminAssetItem[]; updated_at?: number | null }>(baseUrl, "/api/v1/admin/assets/refresh", {
      method: "POST",
      headers: adminHeaders(adminToken),
    });
  },

  async getAdminFiles(baseUrl: string, adminToken: string, sensitive = false, agentId?: string): Promise<{ items: AdminFileItem[] }> {
    const query = buildQuery({ sensitive: sensitive ? "true" : undefined, agent_id: agentId });
    return request<{ items: AdminFileItem[] }>(baseUrl, `/api/v1/admin/files${query}`, {
      headers: adminHeaders(adminToken),
    });
  },

  async getAdminEvents(baseUrl: string, adminToken: string, limit = 100, agentId?: string): Promise<{ items: AdminEventItem[] }> {
    const query = buildQuery({ limit, agent_id: agentId });
    return request<{ items: AdminEventItem[] }>(baseUrl, `/api/v1/admin/events${query}`, {
      headers: adminHeaders(adminToken),
    });
  },

  async getAdminTaskFailures(baseUrl: string, adminToken: string): Promise<{ items: AdminTaskFailureItem[] }> {
    return request<{ items: AdminTaskFailureItem[] }>(baseUrl, "/api/v1/admin/task-failures", {
      headers: adminHeaders(adminToken),
    });
  },

  async retryAdminTaskFailure(baseUrl: string, adminToken: string, failureId: number): Promise<{ status: string; task_id?: string | null }> {
    return request<{ status: string; task_id?: string | null }>(baseUrl, `/api/v1/admin/task-failures/${failureId}/retry`, {
      method: "POST",
      headers: adminHeaders(adminToken),
    });
  },

  async getAdminUploadSessions(baseUrl: string, adminToken: string, limit = 100): Promise<{ items: AdminUploadSessionItem[] }> {
    const query = buildQuery({ limit });
    return request<{ items: AdminUploadSessionItem[] }>(baseUrl, `/api/v1/admin/upload-sessions${query}`, {
      headers: adminHeaders(adminToken),
    });
  },

  async getAdminUpgrades(baseUrl: string, adminToken: string, limit = 100): Promise<{ items: AdminUpgradeItem[] }> {
    const query = buildQuery({ limit });
    return request<{ items: AdminUpgradeItem[] }>(baseUrl, `/api/v1/admin/upgrades${query}`, {
      headers: adminHeaders(adminToken),
    });
  },

  async getAdminOcrHealth(baseUrl: string, adminToken: string): Promise<AdminOcrHealthResponse> {
    return request<AdminOcrHealthResponse>(baseUrl, "/api/v1/admin/ocr/health", {
      headers: adminHeaders(adminToken),
    });
  },

  async getAdminFileDetail(baseUrl: string, adminToken: string, fileHash: string): Promise<AdminFileDetailResponse> {
    return request<AdminFileDetailResponse>(baseUrl, `/api/v1/admin/files/${encodeURIComponent(fileHash)}`, {
      headers: adminHeaders(adminToken),
    });
  },

  async getAdminConfigs(baseUrl: string, adminToken: string): Promise<AdminGlobalConfigResponse> {
    return request<AdminGlobalConfigResponse>(baseUrl, "/api/v1/admin/configs", {
      headers: adminHeaders(adminToken),
    });
  },

  async updateAdminConfigs(baseUrl: string, adminToken: string, payload: Record<string, any>): Promise<{ config_version: number; config: Record<string, any> }> {
    return request<{ config_version: number; config: Record<string, any> }>(baseUrl, "/api/v1/admin/configs", {
      method: "PUT",
      headers: adminHeaders(adminToken),
      body: payload,
    });
  },

  async getSensitiveFiles(baseUrl: string, params: Record<string, any> = {}): Promise<SensitiveFileListResponse> {
    const query = buildQuery(params);
    return request<SensitiveFileListResponse>(baseUrl, `/api/v1/sensitive-files${query}`);
  },

  async getSensitiveFileHistory(baseUrl: string, trackedFileId: string): Promise<SensitiveFileHistoryResponse> {
    return request<SensitiveFileHistoryResponse>(baseUrl, `/api/v1/sensitive-files/${encodeURIComponent(trackedFileId)}/versions`);
  },

  async getRules(baseUrl: string, params: Record<string, any> = {}): Promise<{ items: DetectionRuleItem[] }> {
    const query = buildQuery(params);
    return request<{ items: DetectionRuleItem[] }>(baseUrl, `/api/v1/rules${query}`);
  },

  async createRule(baseUrl: string, payload: Record<string, any>): Promise<DetectionRuleItem> {
    return request<DetectionRuleItem>(baseUrl, "/api/v1/rules", { method: "POST", body: payload });
  },

  async updateRule(baseUrl: string, ruleId: string, payload: Record<string, any>): Promise<DetectionRuleItem> {
    return request<DetectionRuleItem>(baseUrl, `/api/v1/rules/${encodeURIComponent(ruleId)}`, { method: "PUT", body: payload });
  },

  async deleteRule(baseUrl: string, ruleId: string): Promise<{ status: string; rule_id: string }> {
    return request<{ status: string; rule_id: string }>(baseUrl, `/api/v1/rules/${encodeURIComponent(ruleId)}`, { method: "DELETE" });
  },
};
