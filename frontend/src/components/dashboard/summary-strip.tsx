type SummaryItem = {
  label: string;
  value: string | number;
  hint?: string;
};

function StatBox(props: SummaryItem) {
  return (
    <div
      style={{
        background: "#f8fafc",
        border: "1px solid #e2e8f0",
        borderRadius: 14,
        padding: 10,
        minWidth: 0,
      }}
    >
      <div
        style={{
          fontSize: 12,
          color: "#475467",
          marginBottom: 4,
          whiteSpace: "nowrap",
          overflow: "hidden",
          textOverflow: "ellipsis",
        }}
      >
        {props.label}
      </div>
      <div style={{ fontSize: 22, fontWeight: 800, color: "#0f172a", lineHeight: 1.1 }}>
        {props.value}
      </div>
      {props.hint ? (
        <div style={{ fontSize: 12, color: "#667085", marginTop: 6 }}>
          {props.hint}
        </div>
      ) : null}
    </div>
  );
}

export default function SummaryStrip(props: { items: SummaryItem[] }) {
  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: `repeat(${props.items.length || 1}, minmax(0, 1fr))`,
        gap: 8,
      }}
    >
      {props.items.map((item) => (
        <StatBox key={item.label} {...item} />
      ))}
    </div>
  );
}
