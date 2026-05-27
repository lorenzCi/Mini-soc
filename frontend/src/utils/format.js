export function formatDate(iso) {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString("it-IT", {
      dateStyle: "short",
      timeStyle: "medium",
    });
  } catch {
    return iso;
  }
}

export function formatPorts(src, dst) {
  if (src == null && dst == null) return "—";
  return `${src ?? "·"} → ${dst ?? "·"}`;
}

export function groupAlertsByDay(alerts) {
  const buckets = {};
  for (const a of alerts) {
    const day = (a.last_seen_at || "").slice(0, 10);
    if (!day) continue;
    buckets[day] = (buckets[day] || 0) + 1;
  }
  return Object.entries(buckets)
    .sort(([a], [b]) => a.localeCompare(b))
    .slice(-14)
    .map(([label, value]) => ({ label, value }));
}
