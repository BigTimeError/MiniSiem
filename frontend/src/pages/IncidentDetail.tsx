import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";

import Layout from "../components/Layout";
import { getIncidentById } from "../api/incidents";
import { getAlert } from "../api/alerts";
import { getCorrelation } from "../api/correlations";

import type {
  Alert,
  Correlation,
  Incident,
} from "../types/siem";

function IncidentDetail() {
  const { incidentId } = useParams();

  const [incident, setIncident] = useState<Incident | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [correlations, setCorrelations] = useState<Correlation[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadIncident() {
      setLoading(true);
      setError(null);
      setIncident(null);
      setAlerts([]);
      setCorrelations([]);

      if (!incidentId || !Number.isFinite(Number(incidentId))) {
        setError("Invalid incident ID.");
        setLoading(false);
        return;
      }

      try {
        const loadedIncident = await getIncidentById(Number(incidentId));
        setIncident(loadedIncident);

        const [loadedAlerts, loadedCorrelations] = await Promise.all([
          Promise.all(
            loadedIncident.related_alerts.map((id) => getAlert(id)),
          ),
          Promise.all(
            loadedIncident.related_correlations.map((id) =>
              getCorrelation(id),
            ),
          ),
        ]);

        setAlerts(loadedAlerts);
        setCorrelations(loadedCorrelations);
      } catch (error) {
        setError(
          error instanceof Error
            ? error.message
            : "Failed to load incident details.",
        );
      } finally {
        setLoading(false);
      }
    }

    loadIncident();
  }, [incidentId]);

  return (
    <Layout>
      <div className="page">
        <header
          className="page-header"
          style={{ flexDirection: "column", alignItems: "flex-start" }}
        >
          <Link to="/incidents" className="detail-back-link">
            <span aria-hidden="true">←</span>
            Back to incidents
          </Link>

          <span className="dashboard-eyebrow">
            SECURITY MONITORING
          </span>

          <h1>Incident Details</h1>

          <p>
            Investigate the incident, related alerts and correlated activity
          </p>
        </header>

        {loading && (
          <div className="state-card">
            <span className="status-dot" style={{ marginRight: "10px" }} />
            Loading incident...
          </div>
        )}

        {!loading && error && (
          <div className="error-state" role="alert">
            <div>
              <strong>Unable to load incident</strong>
              <p style={{ margin: "4px 0 10px", fontSize: "12px" }}>{error}</p>
              <Link to="/incidents" className="text-link" style={{ fontSize: "12px" }}>
                Return to incidents
              </Link>
            </div>
          </div>
        )}

        {!loading && !error && incident && (
          <>
            <section className="detail-summary">
              <div className="detail-summary-header">
                <div>
                  <span className="detail-id">
                    INCIDENT #{incident.id}
                  </span>

                  <h2 className="detail-title">{incident.title}</h2>

                  <p style={{ margin: 0, color: "var(--text-muted)", fontSize: "12px" }}>
                    Security incident and its associated activity
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
                  <span
                    className={`badge-severity severity-${incident.severity.toLowerCase()}`}
                  >
                    {incident.severity.toUpperCase()}
                  </span>

                  <span
                    className={`badge-status status-${incident.status.toLowerCase()}`}
                  >
                    {incident.status.replace(/_/g, " ").toUpperCase()}
                  </span>
                </div>
              </div>

              <div className="detail-summary-footer">
                <div className="detail-summary-item">
                  <span>Timestamp</span>
                  <strong>
                    {new Date(incident.timestamp).toLocaleString()}
                  </strong>
                </div>

                <div className="detail-summary-item">
                  <span>Related Alerts</span>
                  <strong>{alerts.length}</strong>
                </div>

                <div className="detail-summary-item">
                  <span>Related Correlations</span>
                  <strong>{correlations.length}</strong>
                </div>
              </div>
            </section>

            <section className="content-card" style={{ padding: "20px" }}>
              <div
                className="section-header"
                style={{ padding: 0, marginBottom: "20px", borderBottom: "none" }}
              >
                <div>
                  <h2>Incident Context</h2>
                  <p>Source, affected system and incident overview</p>
                </div>
                <span style={{ fontSize: "18px", color: "var(--accent-blue-light)" }}>
                  ◎
                </span>
              </div>

              <div className="detail-fields-grid">
                <div className="detail-field">
                  <span>Source IP</span>
                  <strong className="text-mono">
                    {incident.source_ip ?? "-"}
                  </strong>
                </div>

                <div className="detail-field">
                  <span>Affected Host</span>
                  <strong>{incident.affected_host ?? "-"}</strong>
                </div>

                <div className="detail-field">
                  <span>Severity</span>
                  <strong style={{ textTransform: "uppercase" }}>
                    {incident.severity}
                  </strong>
                </div>

                <div className="detail-field">
                  <span>Status</span>
                  <strong style={{ textTransform: "capitalize" }}>
                    {incident.status.replace(/_/g, " ")}
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
                  <h2>Description</h2>
                  <p>Incident summary and investigation context</p>
                </div>
              </div>

              <p
                style={{
                  margin: 0,
                  fontSize: "13px",
                  lineHeight: "1.6",
                  color: "var(--text-secondary)",
                }}
              >
                {incident.description || "No description available."}
              </p>
            </section>

            <section className="content-card" style={{ padding: "20px" }}>
              <div
                className="section-header"
                style={{ padding: 0, marginBottom: "20px", borderBottom: "none" }}
              >
                <div>
                  <h2>Related Alerts</h2>
                  <p>Alerts associated with this incident</p>
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
                    No alerts are currently linked to this incident.
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

                        <span
                          style={{
                            color: "var(--text-subtle)",
                            fontSize: "11px",
                          }}
                        >
                          {new Date(alert.timestamp).toLocaleString()}
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

            <section className="content-card" style={{ padding: "20px" }}>
              <div
                className="section-header"
                style={{ padding: 0, marginBottom: "20px", borderBottom: "none" }}
              >
                <div>
                  <h2>Related Correlations</h2>
                  <p>
                    Groups of alerts connected by correlation rules
                  </p>
                </div>

                <span className="btn" style={{ cursor: "default", opacity: 0.8 }}>
                  {correlations.length}
                </span>
              </div>

              {correlations.length === 0 ? (
                <div className="empty-state">
                  <strong>No related correlations</strong>
                  <p
                    style={{
                      margin: 0,
                      color: "var(--text-subtle)",
                      fontSize: "12px",
                    }}
                  >
                    No correlations are currently linked to this incident.
                  </p>
                </div>
              ) : (
                <div className="related-list">
                  {correlations.map((correlation) => (
                    <Link
                      key={correlation.id}
                      to={`/correlations/${correlation.id}`}
                      className="related-item"
                    >
                      <span
                        style={{
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          width: "34px",
                          height: "34px",
                          color: "var(--accent-blue-light)",
                          background: "var(--bg-card-alt)",
                          border: "1px solid var(--border-subtle)",
                          borderRadius: "6px",
                          fontSize: "16px",
                        }}
                      >
                        ⌘
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
                          {correlation.correlation_rule_id}
                        </strong>

                        <span
                          style={{
                            color: "var(--text-muted)",
                            fontSize: "11px",
                          }}
                        >
                          Correlation #{correlation.id}
                        </span>

                        <span
                          style={{
                            color: "var(--text-muted)",
                            fontSize: "11px",
                          }}
                        >
                          Source: {correlation.source_ip ?? "-"}
                          {" · "}
                          Host: {correlation.affected_host ?? "-"}
                        </span>

                        <span
                          style={{
                            color: "var(--text-subtle)",
                            fontSize: "11px",
                          }}
                        >
                          {correlation.alerts.length} related alert(s)
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
                        <span className="badge-severity severity-info">
                          {correlation.alerts.length} ALERTS
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

export default IncidentDetail;