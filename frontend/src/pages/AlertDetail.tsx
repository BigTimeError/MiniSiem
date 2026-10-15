import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";

import Layout from "../components/Layout";
import { getAlert } from "../api/alerts";
import { getEvent } from "../api/events";

import type { Alert, Event } from "../types/siem";

function AlertDetail() {
  const { alertId } = useParams();

  const [alert, setAlert] = useState<Alert | null>(null);
  const [events, setEvents] = useState<Event[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadAlert() {
      setLoading(true);
      setError(null);
      setAlert(null);
      setEvents([]);

      if (!alertId || !Number.isFinite(Number(alertId))) {
        setError("Invalid alert ID.");
        setLoading(false);
        return;
      }

      try {
        const loadedAlert = await getAlert(Number(alertId));
        setAlert(loadedAlert);

        const loadedEvents = await Promise.all(
          loadedAlert.related_events.map((eventId) =>
            getEvent(eventId),
          ),
        );

        setEvents(loadedEvents);
      } catch (error) {
        setError(
          error instanceof Error
            ? error.message
            : "Failed to load alert or related events.",
        );
      } finally {
        setLoading(false);
      }
    }

    loadAlert();
  }, [alertId]);

  return (
    <Layout>
      <div className="page">
        <header
          className="page-header"
          style={{ flexDirection: "column", alignItems: "flex-start" }}
        >
          <Link to="/alerts" className="detail-back-link">
            <span aria-hidden="true">←</span>
            Back to alerts
          </Link>

          <span className="dashboard-eyebrow">
            SECURITY MONITORING
          </span>

          <h1>Alert Details</h1>

          <p>
            Investigate the alert, its detection rule and related events
          </p>
        </header>

        {loading && (
          <div className="state-card">
            <span className="status-dot" style={{ marginRight: "10px" }} />
            Loading alert...
          </div>
        )}

        {!loading && error && (
          <div className="error-state" role="alert">
            <div>
              <strong>Unable to load alert</strong>
              <p style={{ margin: "4px 0 10px", fontSize: "12px" }}>{error}</p>
              <Link to="/alerts" className="text-link" style={{ fontSize: "12px" }}>
                Return to alerts
              </Link>
            </div>
          </div>
        )}

        {!loading && !error && alert && (
          <>
            <section className="detail-summary">
              <div className="detail-summary-header">
                <div>
                  <span className="detail-id">
                    ALERT #{alert.id}
                  </span>

                  <h2 className="detail-title">{alert.title}</h2>

                  <p style={{ margin: 0, color: "var(--text-muted)", fontSize: "12px" }}>
                    Detection rule:{" "}
                    <strong style={{ color: "var(--text-primary)" }}>
                      {alert.rule_id}
                    </strong>
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
                    className={`badge-severity severity-${alert.severity.toLowerCase()}`}
                  >
                    {alert.severity.toUpperCase()}
                  </span>

                  <span
                    className={`badge-status status-${alert.status.toLowerCase()}`}
                  >
                    {alert.status.replace(/_/g, " ").toUpperCase()}
                  </span>
                </div>
              </div>

              <div className="detail-summary-footer">
                <div className="detail-summary-item">
                  <span>Timestamp</span>
                  <strong>
                    {new Date(alert.timestamp).toLocaleString()}
                  </strong>
                </div>

                <div className="detail-summary-item">
                  <span>Related events</span>
                  <strong>
                    {alert.related_events.length.toLocaleString()}
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
                  <h2>Alert Context</h2>
                  <p>Source, affected system and threat classification</p>
                </div>
                <span style={{ fontSize: "18px", color: "var(--accent-blue-light)" }}>
                  ◎
                </span>
              </div>

              <div className="detail-fields-grid">
                <div className="detail-field">
                  <span>Source IP</span>
                  <strong className="text-mono">
                    {alert.source_ip ?? "-"}
                  </strong>
                </div>

                <div className="detail-field">
                  <span>Affected Host</span>
                  <strong>{alert.affected_host ?? "-"}</strong>
                </div>

                <div className="detail-field">
                  <span>Detection Rule</span>
                  <strong>{alert.rule_id || "-"}</strong>
                </div>

                <div className="detail-field">
                  <span>MITRE Technique</span>
                  <strong>{alert.mitre_technique ?? "-"}</strong>
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
                  <p>Why this alert was generated</p>
                </div>
              </div>

              <p
                className="detail-code-block"
                style={{ margin: 0, fontFamily: "var(--font-base)" }}
              >
                {alert.description || "No description available."}
              </p>
            </section>

            <section className="content-card" style={{ padding: "20px" }}>
              <div
                className="section-header"
                style={{ padding: 0, marginBottom: "20px", borderBottom: "none" }}
              >
                <div>
                  <h2>Related Events</h2>
                  <p>
                    Event details and evidence associated with this alert
                  </p>
                </div>

                <span className="btn" style={{ cursor: "default", opacity: 0.8 }}>
                  {events.length}
                </span>
              </div>

              {events.length === 0 ? (
                <div className="empty-state">
                  <strong>No related events</strong>
                  <p
                    style={{
                      margin: 0,
                      color: "var(--text-subtle)",
                      fontSize: "12px",
                    }}
                  >
                    No events are currently linked to this alert.
                  </p>
                </div>
              ) : (
                <div className="related-list">
                  {events.map((event) => (
                    <Link
                      key={event.id}
                      to={`/events/${event.id}`}
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
                          background: "rgba(96, 165, 250, 0.08)",
                          border: "1px solid rgba(96, 165, 250, 0.16)",
                          borderRadius: "6px",
                          fontSize: "18px",
                        }}
                      >
                        ≋
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
                          {event.event_type.replace(/_/g, " ")}
                        </strong>

                        <span
                          style={{
                            color: "var(--text-muted)",
                            fontSize: "11px",
                          }}
                        >
                          Event #{event.id} ·{" "}
                          {new Date(event.timestamp).toLocaleString()}
                        </span>

                        <span
                          style={{
                            color: "var(--text-muted)",
                            fontSize: "11px",
                          }}
                        >
                          Source: {event.source_ip ?? "-"}
                          {" · "}
                          Destination: {event.destination_ip ?? "-"}
                        </span>

                        <span
                          style={{
                            color: "var(--text-muted)",
                            fontSize: "11px",
                          }}
                        >
                          User: {event.username ?? "-"}
                          {" · "}
                          Service: {event.service ?? "-"}
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
                          className={`badge-severity severity-${event.severity.toLowerCase()}`}
                        >
                          {event.severity.toUpperCase()}
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

export default AlertDetail;