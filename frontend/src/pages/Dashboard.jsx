import { api } from "../services/api";
import { useFetch } from "../components/useFetch";
import { groupAlertsByDay } from "../utils/format";
import BarChart from "../components/BarChart";

const SEVERITIES = ["critical", "high", "medium", "low"];

export default function Dashboard() {
  const stats = useFetch(() => api.stats(), []);
  const rules = useFetch(() => api.rules(), []);
  const packets = useFetch(() => api.packets(200), []);
  const alerts = useFetch(() => api.alerts(200), []);

  const loading = stats.loading || rules.loading;
  const error = stats.error || rules.error;

  if (loading) return <p className="loading">Caricamento dashboard…</p>;
  if (error) return <div className="error-box">{error}</div>;

  const bySev = stats.data?.alerts_by_severity || {};
  const activeRules =
    rules.data?.items?.filter((r) => r.enabled).length ?? 0;
  const totalRules = rules.data?.count ?? 0;
  const timeline = groupAlertsByDay(alerts.data?.items || []);

  return (
    <>
      <header className="page-header">
        <h2>Dashboard</h2>
        <p>Panoramica del sistema Mini SOC</p>
      </header>

      <div className="cards">
        <div className="card">
          <div className="card-label">Alert totali</div>
          <div className="card-value">{stats.data?.total_alerts ?? 0}</div>
        </div>
        <div className="card">
          <div className="card-label">Pacchetti (campione)</div>
          <div className="card-value">{packets.data?.count ?? "—"}</div>
        </div>
        <div className="card">
          <div className="card-label">Regole attive</div>
          <div className="card-value">
            {activeRules}
            <span
              style={{
                fontSize: "0.9rem",
                color: "var(--text-muted)",
                fontWeight: 400,
              }}
            >
              {" "}
              / {totalRules}
            </span>
          </div>
        </div>
        <div className="card">
          <div className="card-label">Top IP sorgente</div>
          <div className="card-value" style={{ fontSize: "1rem" }}>
            {stats.data?.top_source_ips?.[0]?.src_ip ?? "—"}
          </div>
        </div>
      </div>

      <div className="panel">
        <h3>Alert per severità</h3>
        <div className="severity-grid">
          {SEVERITIES.map((sev) => (
            <div
              key={sev}
              className="sev-pill"
              style={{
                borderColor: `var(--${sev})`,
                background: `color-mix(in srgb, var(--${sev}) 12%, transparent)`,
              }}
            >
              <div className="count">{bySev[sev] ?? 0}</div>
              <div className="label">{sev}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="chart-row">
        <div className="panel">
          <h3>Alert nel tempo (ultimi giorni)</h3>
          <BarChart data={timeline} />
        </div>
        <div className="panel">
          <h3>Top IP sorgente</h3>
          <BarChart
            data={(stats.data?.top_source_ips || []).map((r) => ({
              label: r.src_ip,
              value: r.alert_count,
            }))}
          />
        </div>
      </div>
    </>
  );
}
