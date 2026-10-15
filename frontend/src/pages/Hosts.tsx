import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import Layout from "../components/Layout";
import { getHosts } from "../api/hosts";
import type { Host } from "../types/siem";

function Hosts() {
  const [hosts, setHosts] = useState<Host[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getHosts()
      .then((data) => {
        setHosts(data);
      })
      .catch((error) => {
        setError(
          error instanceof Error
            ? error.message
            : "Failed to load hosts.",
        );
      })
      .finally(() => {
        setLoading(false);
      });
  }, []);

  return (
    <Layout>
      <div className="page">
        <header className="page-header">
          <div>
            <span className="dashboard-eyebrow">
              INFRASTRUCTURE
            </span>

            <h1>Hosts</h1>

            <p>
              Monitored systems and endpoints
            </p>
          </div>

          <div className="page-live-status">
            <span className="status-dot" />
            Host monitoring
          </div>
        </header>

        {loading && (
          <div className="state-card">
            <span className="status-dot" style={{ marginRight: "10px" }} />
            Loading hosts...
          </div>
        )}

        {error && (
          <div className="error-state" role="alert">
            <div>
              <strong>Unable to load hosts</strong>
              <p style={{ margin: "4px 0 0", fontSize: "12px" }}>{error}</p>
            </div>
          </div>
        )}

        {!loading && !error && (
          <section className="content-card">
            <div className="section-header">
              <div>
                <h2>Host Inventory</h2>
                <p>
                  Systems currently known to MiniSIEM
                </p>
              </div>

              <span className="btn" style={{ cursor: "default", opacity: 0.8 }}>
                {hosts.length} {hosts.length === 1 ? "host" : "hosts"}
              </span>
            </div>

            <div className="table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Hostname</th>
                    <th>IP Address</th>
                    <th>Events</th>
                    <th>Alerts</th>
                    <th>Status</th>
                    <th>Last Seen</th>
                  </tr>
                </thead>

                <tbody>
                  {hosts.map((host) => {
                    const status = host.status.toLowerCase();
                    const statusClass =
                      status === "online" || status === "active"
                        ? "status-resolved"
                        : status === "offline" || status === "inactive"
                        ? "status-open"
                        : "status-false_positive";

                    return (
                      <tr key={host.id}>
                        <td>
                          <Link
                            to={`/hosts/${host.id}`}
                            className="text-link"
                            style={{ fontWeight: 500 }}
                          >
                            {host.hostname}
                          </Link>
                        </td>

                        <td className="text-mono">
                          {host.ip_address}
                        </td>

                        <td className="text-mono">
                          {host.events.toLocaleString()}
                        </td>

                        <td>
                          {host.alerts > 0 ? (
                            <span className="badge-severity severity-critical">
                              {host.alerts.toLocaleString()}
                            </span>
                          ) : (
                            <span
                              style={{
                                color: "var(--text-subtle)",
                                fontSize: "12px",
                              }}
                            >
                              0
                            </span>
                          )}
                        </td>

                        <td>
                          <span className={`badge-status ${statusClass}`}>
                            {status.replace("_", " ")}
                          </span>
                        </td>

                        <td className="text-timestamp">
                          {new Date(host.last_seen).toLocaleString()}
                        </td>
                      </tr>
                    );
                  })}

                  {hosts.length === 0 && (
                    <tr>
                      <td colSpan={6}>
                        <div className="empty-state">
                          <span className="empty-icon">⌕</span>
                          <strong>No hosts found</strong>
                          <p
                            style={{
                              margin: 0,
                              color: "var(--text-subtle)",
                              fontSize: "12px",
                            }}
                          >
                            No monitored systems are currently available.
                          </p>
                        </div>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            <div
              style={{
                padding: "14px 20px",
                background: "var(--bg-card-alt)",
                borderTop: "1px solid var(--border-subtle)",
                fontSize: "12px",
                color: "var(--text-muted)",
              }}
            >
              <span>
                Showing {hosts.length.toLocaleString()} monitored{" "}
                {hosts.length === 1 ? "host" : "hosts"}
              </span>
            </div>
          </section>
        )}
      </div>
    </Layout>
  );
}

export default Hosts;