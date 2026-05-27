import { api } from "../services/api";
import { useFetch } from "../components/useFetch";
import SeverityBadge from "../components/SeverityBadge";
import { formatDate, formatPorts } from "../utils/format";

export default function Alerts() {
  const { data, loading, error, reload } = useFetch(() => api.alerts(200), []);

  if (loading) return <p className="loading">Caricamento alert…</p>;

  const items = [...(data?.items || [])].sort(
    (a, b) => new Date(b.last_seen_at) - new Date(a.last_seen_at)
  );

  return (
    <>
      <header className="page-header">
        <h2>Alerts</h2>
        <p>Eventi di detection ordinati per ultima attività</p>
      </header>

      {error && <div className="error-box">{error}</div>}

      <div className="toolbar">
        <span className="muted">{items.length} alert</span>
        <button type="button" className="btn btn-ghost" onClick={reload}>
          Aggiorna
        </button>
      </div>

      <div className="panel table-wrap">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Regola</th>
              <th>Severità</th>
              <th>Src IP</th>
              <th>Dst IP</th>
              <th>Porte</th>
              <th>Stato</th>
              <th>Eventi</th>
              <th>Ultimo visto</th>
            </tr>
          </thead>
          <tbody>
            {items.length === 0 ? (
              <tr>
                <td colSpan={9} className="muted">
                  Nessun alert.
                </td>
              </tr>
            ) : (
              items.map((a) => (
                <tr key={a.id}>
                  <td className="mono">{a.id}</td>
                  <td>{a.title}</td>
                  <td>
                    <SeverityBadge severity={a.severity} />
                  </td>
                  <td className="mono">{a.src_ip ?? "—"}</td>
                  <td className="mono">{a.dst_ip ?? "—"}</td>
                  <td className="mono">
                    {formatPorts(a.src_port, a.dst_port)}
                  </td>
                  <td>{a.status}</td>
                  <td className="mono">{a.event_count}</td>
                  <td>{formatDate(a.last_seen_at)}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}
