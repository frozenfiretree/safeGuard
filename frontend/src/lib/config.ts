function stripTrailingSlash(value: string) {
  return value.replace(/\/+$/, "");
}

function guessDefaultBaseUrl() {
  if (typeof window === "undefined") {
    return "http://127.0.0.1:8000";
  }

  const { protocol, hostname } = window.location;

  // Vite 开发环境通常在 5173，后端在 8000
  if (hostname === "localhost" || hostname === "127.0.0.1") {
    return `${protocol}//${hostname}:8000`;
  }

  // 生产环境如果前后端同域部署，可直接回源到当前域名 8000
  return `${protocol}//${hostname}:8000`;
}

const rawBaseUrl =
  (import.meta as any)?.env?.VITE_API_BASE_URL ||
  guessDefaultBaseUrl();

export const API_BASE_URL = stripTrailingSlash(rawBaseUrl);

export const DEFAULT_SCAN_TARGET_DIR =
  (import.meta as any)?.env?.VITE_DEFAULT_SCAN_TARGET_DIR || "C:\\test";

/**
 * 页面自动刷新周期，单位毫秒。
 * 设为 0 可关闭自动刷新。
 */
export const UI_REFRESH_INTERVAL_MS = Number(
  (import.meta as any)?.env?.VITE_UI_REFRESH_INTERVAL_MS || 15000
);

export const APP_NAME = "敏感信息检测与溯源系统";

export const APP_SUBTITLE =
  "面向终端侧敏感文件检测、持续监控、版本归档与差异追踪的一体化控制台";