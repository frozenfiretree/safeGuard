import type { ReactNode } from "react";

export default function SectionCard(props: {
  title: string;
  extra?: ReactNode;
  children: ReactNode;
  minHeight?: number;
}) {
  return (
    <section
      style={{
        background: "#ffffff",
        border: "1px solid #eaecf0",
        borderRadius: 16,
        padding: 16,
        minHeight: props.minHeight,
        boxShadow: "0 1px 2px rgba(16,24,40,0.04)",
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 12,
          marginBottom: 12,
          flexWrap: "wrap",
        }}
      >
        <div style={{ fontSize: 16, fontWeight: 700, color: "#101828" }}>
          {props.title}
        </div>
        <div>{props.extra}</div>
      </div>
      {props.children}
    </section>
  );
}
