import { useEffect } from "react";
import { api } from "../services/api";
import { useFetch } from "../components/useFetch";
import { formatDate, formatPorts } from "../utils/format";

const REFRESH_MS = 5000;

export default function Packets() {
  const { data, loading, error, reload } = useFetch(() => api.packets(150), []);

  useEffect(() => {
    const id = setInterval(reload, REFRESH_MS);
    return () => clearInterval(id);
  }, [reload]);

  if (loading && !data) return <p className="loading">Caricamento pacchetti…</p>;

  const items = data?.items || [];

  return (
    <>
      <header className="page-header">
        <h2>Packets</h2>
        <p>
          Ultimi pacchetti catturati — aggiornamento ogni {REFRESH_MS / 1000}s
        </p>
      </header>

      {error && <div className="error-box">{error}</div>}

      <div className="toolbar">
        <span className="muted">{items.length} pacchetti recenti</span>
        <button type="button" className="btn btn-ghost" onClick={reload}>
          Aggiorna ora
        </button>
      </div>

      <div className="panel table-wrap">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Src IP</th>
              <th>Dst IP</th>
              <th>Protocollo</th>
              <th>Porte</th>
              <th>Size</th>
              <th>Flags</th>
              <th>Catturato</th>
            </tr>
          </thead>
          <tbody>
            {items.length === 0 ? (
              <tr>
                <td colSpan={8} className="muted">
                  Nessun pacchetto. Avvia il collector live.
                </td>
              </tr>
            ) : (
              items.map((p) => (
                <tr key={p.id}>
                  <td className="mono">{p.id}</td>
                  <td className="mono">{p.src_ip ?? "—"}</td>
                  <td className="mono">{p.dst_ip ?? "—"}</td>
                  <td>{p.protocol?.toUpperCase()}</td>
                  <td className="mono">
                    {formatPorts(p.src_port, p.dst_port)}
                  </td>
                  <td className="mono">{p.packet_size ?? "—"}</td>
                  <td className="mono">{p.tcp_flags ?? "—"}</td>
                  <td>{formatDate(p.captured_at)}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}
