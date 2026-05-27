import { api } from "../services/api";
import { useFetch } from "../components/useFetch";
import SeverityBadge from "../components/SeverityBadge";

export default function Rules() {
  const { data, loading, error, reload } = useFetch(() => api.rules(), []);

  if (loading) return <p className="loading">Caricamento regole…</p>;

  const items = data?.items || [];

  return (
    <>
      <header className="page-header">
        <h2>Detection Rules</h2>
        <p>Regole IDS caricate dal database</p>
      </header>

      {error && <div className="error-box">{error}</div>}

      <div className="toolbar">
        <span className="muted">{items.length} regole</span>
        <button type="button" className="btn btn-ghost" onClick={reload}>
          Aggiorna
        </button>
      </div>

      <div className="panel table-wrap">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Nome</th>
              <th>Tipo</th>
              <th>Severità</th>
              <th>Stato</th>
              <th>Descrizione</th>
            </tr>
          </thead>
          <tbody>
            {items.length === 0 ? (
              <tr>
                <td colSpan={6} className="muted">
                  Nessuna regola. Esegui seed_detection_rules.py
                </td>
              </tr>
            ) : (
              items.map((r) => (
                <tr key={r.id}>
                  <td className="mono">{r.id}</td>
                  <td>{r.name}</td>
                  <td className="mono">{r.rule_type}</td>
                  <td>
                    <SeverityBadge severity={r.severity} />
                  </td>
                  <td>
                    <span
                      className={`badge ${
                        r.enabled ? "badge-enabled" : "badge-disabled"
                      }`}
                    >
                      {r.enabled ? "enabled" : "disabled"}
                    </span>
                  </td>
                  <td className="muted">{r.description || "—"}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}
