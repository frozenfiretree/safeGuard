export type SidebarNavItem = {
  key: string;
  label: string;
  hint?: string;
};

export default function SidebarNav(props: {
  items: SidebarNavItem[];
  activeKey: string;
  onChange: (key: string) => void;
}) {
  return (
    <aside
      style={{
        width: 260,
        minWidth: 260,
        background: "linear-gradient(180deg, #0f172a 0%, #111827 100%)",
        color: "#f8fafc",
        borderRight: "1px solid rgba(148, 163, 184, 0.18)",
        padding: 20,
        display: "flex",
        flexDirection: "column",
        gap: 18,
      }}
    >
      <div>
        <div style={{ fontSize: 12, letterSpacing: "0.08em", textTransform: "uppercase", color: "#93c5fd" }}>
          SafeGuard
        </div>
        <div style={{ marginTop: 6, fontSize: 22, fontWeight: 800, lineHeight: 1.2 }}>
          V2 管理控制台
        </div>
        <div style={{ marginTop: 8, fontSize: 13, color: "#cbd5e1", lineHeight: 1.7 }}>
          统一查看资产探测、Agent、检测结果、事件监控、运行状态与全局配置。
        </div>
      </div>

      <div style={{ display: "grid", gap: 8 }}>
        {props.items.map((item) => {
          const active = item.key === props.activeKey;
          return (
            <button
              key={item.key}
              onClick={() => props.onChange(item.key)}
              style={{
                textAlign: "left",
                borderRadius: 14,
                border: active ? "1px solid rgba(147, 197, 253, 0.7)" : "1px solid transparent",
                background: active ? "rgba(37, 99, 235, 0.22)" : "rgba(255,255,255,0.04)",
                color: "#f8fafc",
                padding: "12px 14px",
                cursor: "pointer",
              }}
            >
              <div style={{ fontSize: 14, fontWeight: 700 }}>{item.label}</div>
              {item.hint ? (
                <div style={{ marginTop: 4, fontSize: 12, color: active ? "#dbeafe" : "#94a3b8", lineHeight: 1.6 }}>
                  {item.hint}
                </div>
              ) : null}
            </button>
          );
        })}
      </div>
    </aside>
  );
}
