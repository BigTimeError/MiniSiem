import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";

import Layout from "../components/Layout";
import { getEvent } from "../api/events";
import type { Event } from "../types/siem";

function EventDetail() {
  const { eventId } = useParams();

  const [event, setEvent] = useState<Event | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    setError(null);
    setEvent(null);

    if (!eventId || !Number.isFinite(Number(eventId))) {
      setError("Invalid event ID.");
      setLoading(false);
      return;
    }

    getEvent(Number(eventId))
      .then((data) => {
        setEvent(data);
      })
      .catch((error) => {
        setError(
          error instanceof Error
            ? error.message
            : "Failed to load event.",
        );
      })
      .finally(() => {
        setLoading(false);
      });
  }, [eventId]);

  return (
    <Layout>
      <div className="page">
        <header
          className="page-header"
          style={{ flexDirection: "column", alignItems: "flex-start" }}
        >
          <Link to="/events" className="detail-back-link">
            <span aria-hidden="true">←</span>
            Back to events
          </Link>

          <span className="dashboard-eyebrow">
            SECURITY MONITORING
          </span>

          <h1>Event Details</h1>

          <p>
            Inspect the event and its associated technical data
          </p>
        </header>

        {loading && (
          <div className="state-card">
            <span className="status-dot" style={{ marginRight: "10px" }} />
            Loading event...
          </div>
        )}

        {!loading && error && (
          <div className="error-state" role="alert">
            <div>
              <strong>Unable to load event</strong>
              <p style={{ margin: "4px 0 10px", fontSize: "12px" }}>{error}</p>
              <Link to="/events" className="text-link" style={{ fontSize: "12px" }}>
                Return to events
              </Link>
            </div>
          </div>
        )}

        {!loading && !error && event && (
          <>
            <section className="detail-summary">
              <div className="detail-summary-header">
                <div>
                  <span className="detail-id">
                    EVENT #{event.id}
                  </span>

                  <h2 className="detail-title">
                    {event.event_type.replace(/_/g, " ")}
                  </h2>

                  <p style={{ margin: 0, color: "var(--text-muted)", fontSize: "12px" }}>
                    Reported by{" "}
                    <strong style={{ color: "var(--text-primary)" }}>
                      {event.source || "Unknown source"}
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
                    className={`badge-severity severity-${event.severity.toLowerCase()}`}
                  >
                    {event.severity.toUpperCase()}
                  </span>
                </div>
              </div>

              <div className="detail-summary-footer">
                <div className="detail-summary-item">
                  <span>Timestamp</span>
                  <strong>
                    {new Date(event.timestamp).toLocaleString()}
                  </strong>
                </div>

                <div className="detail-summary-item">
                  <span>Event ID</span>
                  <strong className="text-mono">
                    #{event.id}
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
                  <h2>Event Context</h2>
                  <p>Network, source and user information</p>
                </div>
                <span style={{ fontSize: "18px", color: "var(--accent-blue-light)" }}>
                  ◎
                </span>
              </div>

              <div className="detail-fields-grid">
                <div className="detail-field">
                  <span>Source</span>
                  <strong>{event.source || "-"}</strong>
                </div>

                <div className="detail-field">
                  <span>Source IP</span>
                  <strong className="text-mono">
                    {event.source_ip ?? "-"}
                  </strong>
                </div>

                <div className="detail-field">
                  <span>Source Port</span>
                  <strong className="text-mono">
                    {event.source_port ?? "-"}
                  </strong>
                </div>

                <div className="detail-field">
                  <span>Destination IP</span>
                  <strong className="text-mono">
                    {event.destination_ip ?? "-"}
                  </strong>
                </div>

                <div className="detail-field">
                  <span>Destination Port</span>
                  <strong className="text-mono">
                    {event.destination_port ?? "-"}
                  </strong>
                </div>

                <div className="detail-field">
                  <span>Username</span>
                  <strong>{event.username ?? "-"}</strong>
                </div>

                <div className="detail-field">
                  <span>Service</span>
                  <strong>{event.service ?? "-"}</strong>
                </div>

                <div className="detail-field">
                  <span>Severity</span>
                  <strong style={{ textTransform: "uppercase" }}>
                    {event.severity}
                  </strong>
                </div>
              </div>
            </section>

            {event.message && (
              <section className="content-card" style={{ padding: "20px" }}>
                <div
                  className="section-header"
                  style={{ padding: 0, marginBottom: "20px", borderBottom: "none" }}
                >
                  <div>
                    <h2>Event Message</h2>
                    <p>Original message associated with this event</p>
                  </div>
                  <span style={{ fontSize: "18px", color: "var(--accent-blue-light)" }}>
                    ≡
                  </span>
                </div>

                <pre className="detail-code-block" style={{ margin: 0 }}>
                  {event.message}
                </pre>
              </section>
            )}

            <section className="content-card" style={{ padding: "20px" }}>
              <div
                className="section-header"
                style={{ padding: 0, marginBottom: "20px", borderBottom: "none" }}
              >
                <div>
                  <h2>Raw Metadata</h2>
                  <p>Structured data stored with this event</p>
                </div>
                <span
                  className="btn"
                  style={{
                    cursor: "default",
                    opacity: 0.8,
                    fontSize: "10px",
                    fontWeight: 700,
                  }}
                >
                  JSON
                </span>
              </div>

              <pre className="detail-code-block" style={{ margin: 0 }}>
                {JSON.stringify(event.metadata ?? {}, null, 2)}
              </pre>
            </section>
          </>
        )}
      </div>
    </Layout>
  );
}

export default EventDetail;