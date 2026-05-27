export default function SeverityBadge({ severity }) {
  const s = (severity || "low").toLowerCase();
  return <span className={`badge badge-${s}`}>{s}</span>;
}
