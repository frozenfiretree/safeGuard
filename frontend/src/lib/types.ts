export interface HealthResponse {
  status: string;
  version?: string;
}

export interface AdminAgentItem {
  agent_id: string;
  hostname?: string | null;
  ip?: string | null;
  device_fingerprint?: string | null;
  mac_address?: string | null;
  agent_version?: string | null;
  status: string;
  config_version?: number;
  last_heartbeat?: number | null;
  token_expires_at?: number | null;
  scan_progress?: Record<string, any>;
  created_at?: number | null;
  updated_at?: number | null;
}

export interface AdminAssetItem {
  ip: string;
  mac?: string | null;
  hostname?: string | null;
  hostname_source?: string | null;
  os_type?: string | null;
  os_source?: string | null;
  os_confidence?: number | null;
  open_ports?: Array<Record<string, any>>;
  is_alive?: boolean;
  discovery_tool?: string | null;
  arp_verified?: boolean;
  host_discovery_verified?: boolean;
  icmp_verified?: boolean;
  tcp_verified?: boolean;
  suspicious?: boolean;
  interface_ip?: string | null;
  last_seen_at?: number | null;
}

export interface AdminFileItem {
  file_hash: string;
  file_name?: string | null;
  file_type?: string | null;
  file_size?: number | null;
  detection_status?: string | null;
  is_sensitive?: boolean;
  risk_level?: string | null;
  explanation_summary?: string | null;
  agents?: string[];
  current_paths?: string[];
  updated_at?: number | null;
}

export interface AdminTaskFailureItem {
  id: number;
  task_name: string;
  task_payload?: Record<string, any>;
  error_message: string;
  created_at?: number | null;
}

export interface AdminEventItem {
  event_id: string;
  agent_id: string;
  event_type: string;
  file_path?: string | null;
  old_path?: string | null;
  new_path?: string | null;
  old_hash?: string | null;
  new_hash?: string | null;
  file_size?: number | null;
  timestamp?: number | null;
  usb_context?: Record<string, any>;
  event_details?: Record<string, any>;
  created_at?: number | null;
}

export interface AdminUploadSessionItem {
  session_id: string;
  agent_id: string;
  file_hash: string;
  file_name?: string | null;
  file_type?: string | null;
  file_path?: string | null;
  file_size?: number | null;
  total_chunks?: number;
  uploaded_chunks?: number[];
  status: string;
  expires_at?: number | null;
  created_at?: number | null;
  updated_at?: number | null;
}

export interface AdminUpgradeItem {
  agent_id: string;
  hostname?: string | null;
  ip?: string | null;
  agent_version?: string | null;
  upgrade_target?: string | null;
  upgrade_report?: Record<string, any> | null;
  updated_at?: number | null;
}

export interface AdminFileDetailResponse {
  file_hash: string;
  file_name?: string | null;
  file_type?: string | null;
  file_size?: number | null;
  detection_status?: string | null;
  is_sensitive?: boolean;
  risk_level?: string | null;
  explanation_summary?: string | null;
  agents?: string[];
  current_paths?: string[];
  parse_result?: Record<string, any> | null;
  rule_hits?: Array<Record<string, any>>;
  ocr_findings?: Array<Record<string, any>>;
  llm_findings?: Array<Record<string, any>>;
  llm_summary?: string | null;
  final_decision?: Record<string, any> | null;
  confidence?: number | null;
  per_block_locations?: Array<Record<string, any>>;
}

export interface AdminOcrHealthResponse {
  status: string;
  service_url: string;
  health?: Record<string, any>;
  error?: string;
}

export interface AdminGlobalConfigResponse {
  config_version: number;
  config: Record<string, any>;
  agent_overrides: Array<{
    agent_id?: string | null;
    version?: number;
    config?: Record<string, any>;
    updated_at?: number | null;
  }>;
}

export interface SensitiveFileItem {
  tracked_file_id: string;
  agent_id: string;
  file_key: string;
  current_path: string;
  current_name: string;
  original_path: string;
  original_name: string;
  file_type?: string | null;
  sensitive_level?: string | null;
  is_deleted: boolean;
  first_seen_at?: number | null;
  last_seen_at?: number | null;
  deleted_at?: number | null;
  latest_event_type?: string | null;
  latest_version_no: number;
  latest_version_id?: string | null;
  rename_count: number;
  modify_count: number;
}

export interface SensitiveFileVersion {
  version_id: string;
  tracked_file_id: string;
  version_no: number;
  snapshot_time?: number | null;
  event_type: string;
  path_at_that_time: string;
  name_at_that_time: string;
  content_hash?: string | null;
  prev_version_id?: string | null;
  change_summary: string;
  change_detail_json?: Record<string, any>;
  sensitive_hits?: Array<Record<string, any>>;
  can_download: boolean;
  has_highlight: boolean;
  has_diff: boolean;
  download_url: string;
  highlight_download_url: string;
  diff_download_url: string;
  snapshot_retention_note?: string;
  artifact_type?: string | null;
}

export interface SensitiveFileEvent {
  event_id: string;
  tracked_file_id: string;
  event_time?: number | null;
  event_type: string;
  old_path?: string | null;
  new_path?: string | null;
  old_name?: string | null;
  new_name?: string | null;
  description: string;
  raw_event_json?: Record<string, any>;
  version_id?: string | null;
}

export interface SensitiveFileHistoryResponse {
  file: SensitiveFileItem;
  current_state: string;
  versions: SensitiveFileVersion[];
  events: SensitiveFileEvent[];
}

export interface SensitiveFileListResponse {
  items: SensitiveFileItem[];
  page: number;
  page_size: number;
  total: number;
}

export type DetectionRuleType = "keyword" | "ocr" | "llm";

export interface DetectionRuleItem {
  rule_id: string;
  rule_name: string;
  rule_type: DetectionRuleType;
  enabled: boolean;
  description?: string | null;
  priority: number;
  created_at?: number | null;
  updated_at?: number | null;
  config: Record<string, any>;
}
