const COLORS = {
  low: "var(--low)",
  medium: "var(--medium)",
  high: "var(--high)",
  critical: "var(--critical)",
  default: "var(--accent)",
};

export default function BarChart({ data, colorKey = "default" }) {
  if (!data?.length) {
    return <p className="muted">Nessun dato disponibile.</p>;
  }

  const max = Math.max(...data.map((d) => d.value), 1);

  return (
    <div className="bar-chart">
      {data.map((item) => (
        <div className="bar-row" key={item.label}>
          <span className="mono" title={item.label}>
            {item.label.length > 14
              ? `${item.label.slice(0, 14)}…`
              : item.label}
          </span>
          <div className="bar-track">
            <div
              className="bar-fill"
              style={{
                width: `${(item.value / max) * 100}%`,
                background:
                  COLORS[item.color || colorKey] || COLORS.default,
              }}
            />
          </div>
          <span className="mono">{item.value}</span>
        </div>
      ))}
    </div>
  );
}
