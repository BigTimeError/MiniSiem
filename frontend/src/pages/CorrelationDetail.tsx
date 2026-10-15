import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";

import Layout from "../components/Layout";
import { getCorrelation } from "../api/correlations";
import { getAlert } from "../api/alerts";

import type { Alert, Correlation } from "../types/siem";

function CorrelationDetail() {
  const { correlationId } = useParams();

  const [correlation, setCorrelation] = useState<Correlation | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadCorrelation() {
      setLoading(true);
      setError(null);
      setCorrelation(null);
      setAlerts([]);

      if (!correlationId || !Number.isFinite(Number(correlationId))) {
        setError("Invalid correlation ID.");
        setLoading(false);
        return;
      }

      try {
        const loadedCorrelation = await getCorrelation(
          Number(correlationId),
        );

        setCorrelation(loadedCorrelation);

        const loadedAlerts = await Promise.all(
          loadedCorrelation.alerts.map((alertId) => getAlert(alertId)),
        );

        setAlerts(loadedAlerts);
      } catch (error) {
        setError(
          error instanceof Error
            ? error.message
            : "Failed to load correlation.",
        );
      } finally {
        setLoading(false);
      }
    }

    loadCorrelation();
  }, [correlationId]);

  return (
    <Layout>
      <div className="page">
        <header
          className="page-header"
          style={{ flexDirection: "column", alignItems: "flex-start" }}
        >
          <Link to="/correlations" className="detail-back-link">
            <span aria-hidden="true">←</span>
            Back to correlations
          </Link>

          <span className="dashboard-eyebrow">
            SECURITY MONITORING
          </span>

          <h1>Correlation Details</h1>

          <p>
            Investigate related alerts and their shared context
          </p>
        </header>

        {loading && (
          <div className="state-card">
            <span className="status-dot" style={{ marginRight: "10px" }} />
            Loading correlation...
          </div>
        )}

        {!loading && error && (
          <div className="error-state" role="alert">
            <div>
              <strong>Unable to load correlation</strong>
              <p style={{ margin: "4px 0 10px", fontSize: "12px" }}>{error}</p>
              <Link to="/correlations" className="text-link" style={{ fontSize: "12px" }}>
                Return to correlations
              </Link>
            </div>
          </div>
        )}

        {!loading && !error && correlation && (
          <>
            <section className="detail-summary">
              <div className="detail-summary-header">
                <div>
                  <span className="detail-id">
                    CORRELATION #{correlation.id}
                  </span>

                  <h2 className="detail-title">{correlation.correlation_rule_id}</h2>

                  <p style={{ margin: 0, color: "var(--text-muted)", fontSize: "12px" }}>
                    Correlation rule that groups related security alerts
                  </p>
                </div>

                <div
                  style={{
                    display: "flex",
                    gap: "8px",
                    flexShrink: 0,
                    flexWrap: "wrap",
                    justifyContent: "flex-end",
                  }}
                >
                  <span className="badge-severity severity-info">
                    {correlation.alerts.length}{" "}
                    {correlation.alerts.length === 1 ? "ALERT" : "ALERTS"}
                  </span>
                </div>
              </div>

              <div className="detail-summary-footer">
                <div className="detail-summary-item">
                  <span>Timestamp</span>
                  <strong>
                    {new Date(correlation.timestamp).toLocaleString()}
                  </strong>
                </div>

                <div className="detail-summary-item">
                  <span>Related Alerts</span>
                  <strong>{correlation.alerts.length}</strong>
                </div>
              </div>
            </section>

            <section className="content-card" style={{ padding: "20px" }}>
              <div
                className="section-header"
                style={{ padding: 0, marginBottom: "20px", borderBottom: "none" }}
              >
                <div>
                  <h2>Correlation Context</h2>
                  <p>Source and affected system information</p>
                </div>

                <span style={{ fontSize: "18px", color: "var(--accent-blue-light)" }}>
                  ◎
                </span>
              </div>

              <div className="detail-fields-grid">
                <div className="detail-field">
                  <span>Correlation Rule</span>
                  <strong>{correlation.correlation_rule_id}</strong>
                </div>

                <div className="detail-field">
                  <span>Source IP</span>
                  <strong className="text-mono">
                    {correlation.source_ip ?? "-"}
                  </strong>
                </div>

                <div className="detail-field">
                  <span>Affected Host</span>
                  <strong>{correlation.affected_host ?? "-"}</strong>
                </div>

                <div className="detail-field">
                  <span>Correlation ID</span>
                  <strong className="text-mono">
                    #{correlation.id}
                  </strong>
                </div>
              </div>
            </section>

            <section className="content-card" style={{ padding: "20px" }}>
              <div
                className="section-header"
                style={{ padding: 0, marginBottom: "20px", borderBottom: "none" }}
              >
                <div>
                  <h2>Related Alerts</h2>
                  <p>
                    Alerts associated with this correlation
                  </p>
                </div>

                <span className="btn" style={{ cursor: "default", opacity: 0.8 }}>
                  {alerts.length}
                </span>
              </div>

              {alerts.length === 0 ? (
                <div className="empty-state">
                  <strong>No related alerts</strong>
                  <p
                    style={{
                      margin: 0,
                      color: "var(--text-subtle)",
                      fontSize: "12px",
                    }}
                  >
                    No alerts are currently linked to this correlation.
                  </p>
                </div>
              ) : (
                <div className="related-list">
                  {alerts.map((alert) => (
                    <Link
                      key={alert.id}
                      to={`/alerts/${alert.id}`}
                      className="related-item"
                    >
                      <span
                        style={{
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          width: "34px",
                          height: "34px",
                          color: "var(--accent-red)",
                          background: "var(--bg-critical)",
                          border: "1px solid var(--border-critical)",
                          borderRadius: "6px",
                          fontSize: "16px",
                          fontWeight: "bold",
                        }}
                      >
                        !
                      </span>

                      <div
                        style={{
                          display: "flex",
                          flexDirection: "column",
                          gap: "4px",
                          minWidth: 0,
                        }}
                      >
                        <strong
                          style={{
                            color: "var(--text-primary)",
                            fontSize: "12px",
                          }}
                        >
                          {alert.title}
                        </strong>

                        <span
                          style={{
                            color: "var(--text-muted)",
                            fontSize: "11px",
                          }}
                        >
                          Alert #{alert.id} · Rule: {alert.rule_id}
                        </span>

                        <span
                          style={{
                            color: "var(--text-muted)",
                            fontSize: "11px",
                          }}
                        >
                          Source: {alert.source_ip ?? "-"}
                          {" · "}
                          Host: {alert.affected_host ?? "-"}
                        </span>
                      </div>

                      <div
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: "12px",
                          flexShrink: 0,
                        }}
                      >
                        <span
                          className={`badge-severity severity-${alert.severity.toLowerCase()}`}
                        >
                          {alert.severity.toUpperCase()}
                        </span>

                        <span
                          style={{
                            color: "var(--text-muted)",
                            fontSize: "16px",
                          }}
                        >
                          →
                        </span>
                      </div>
                    </Link>
                  ))}
                </div>
              )}
            </section>
          </>
        )}
      </div>
    </Layout>
  );
}

export default CorrelationDetail;