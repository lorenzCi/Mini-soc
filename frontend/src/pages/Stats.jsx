import { api } from "../services/api";
import { useFetch } from "../components/useFetch";
import BarChart from "../components/BarChart";
import { groupAlertsByDay } from "../utils/format";

const SEVERITY_ORDER = ["critical", "high", "medium", "low"];

export default function Stats() {
  const stats = useFetch(() => api.stats(15), []);
  const alerts = useFetch(() => api.alerts(300), []);

  const loading = stats.loading || alerts.loading;
  const error = stats.error || alerts.error;

  if (loading) return <p className="loading">Caricamento statistiche…</p>;
  if (error) return <div className="error-box">{error}</div>;

  const bySev = stats.data?.alerts_by_severity || {};
  const severityChart = SEVERITY_ORDER.map((sev) => ({
    label: sev,
    value: bySev[sev] ?? 0,
    color: sev,
  }));

  const timeline = groupAlertsByDay(alerts.data?.items || []);
  const topIps = (stats.data?.top_source_ips || []).map((r) => ({
    label: r.src_ip,
    value: r.alert_count,
  }));

  return (
    <>
      <header className="page-header">
        <h2>Statistics</h2>
        <p>Analisi aggregata degli alert</p>
      </header>

      <div className="cards">
        <div className="card">
          <div className="card-label">Alert totali</div>
          <div className="card-value">{stats.data?.total_alerts ?? 0}</div>
        </div>
        <div className="card">
          <div className="card-label">Pacchetti totali</div>
          <div className="card-value">{stats.data?.total_packets ?? 0}</div>
        </div>
        <div className="card">
          <div className="card-label">Regole attive</div>
          <div className="card-value">
            {stats.data?.enabled_rules ?? 0}
            <span
              style={{
                fontSize: "0.9rem",
                color: "var(--text-muted)",
                fontWeight: 400,
              }}
            >
              {" "}
              / {stats.data?.total_rules ?? 0}
            </span>
          </div>
        </div>
      </div>

      <div className="chart-row">
        <div className="panel">
          <h3>Alert per severità</h3>
          <BarChart data={severityChart} />
        </div>
        <div className="panel">
          <h3>Top source IP</h3>
          <BarChart data={topIps} />
        </div>
      </div>

      <div className="panel">
        <h3>Alert nel tempo (per giorno)</h3>
        <p className="muted" style={{ marginTop: 0, fontSize: "0.85rem" }}>
          Derivato dagli ultimi {alerts.data?.count ?? 0} alert (API /alerts)
        </p>
        <BarChart data={timeline} />
      </div>
    </>
  );
}
