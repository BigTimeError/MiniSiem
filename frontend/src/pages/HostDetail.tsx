import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";

import Layout from "../components/Layout";
import {
  getHost,
  getHostAlerts,
  getHostEvents,
} from "../api/hosts";

import type { Host, Alert, Event } from "../types/siem";

const ITEMS_PER_PAGE = 10;

function HostDetail() {
  const { hostId } = useParams();

  const [host, setHost] = useState<Host | null>(null);

  const [events, setEvents] = useState<Event[]>([]);
  const [eventsTotal, setEventsTotal] = useState(0);
  const [eventsPage, setEventsPage] = useState(0);

  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [alertsTotal, setAlertsTotal] = useState(0);
  const [alertsPage, setAlertsPage] = useState(0);

  const [loading, setLoading] = useState(true);
  const [eventsLoading, setEventsLoading] = useState(true);
  const [alertsLoading, setAlertsLoading] = useState(true);

  const [error, setError] = useState<string | null>(null);
  const [eventsError, setEventsError] = useState<string | null>(null);
  const [alertsError, setAlertsError] = useState<string | null>(null);

  useEffect(() => {
    if (!hostId) {
      setHost(null);
      setError("Host ID is missing.");
      setLoading(false);
      return;
    }

    setLoading(true);
    setError(null);
    setHost(null);

    getHost(hostId)
      .then((data) => {
        setHost(data);
      })
      .catch((error) => {
        setError(
          error instanceof Error ? error.message : "Failed to load host.",
        );
      })
      .finally(() => {
        setLoading(false);
      });
  }, [hostId]);

  useEffect(() => {
    if (!hostId) {
      setEvents([]);
      setEventsTotal(0);
      setEventsLoading(false);
      return;
    }

    setEventsLoading(true);
    setEventsError(null);

    getHostEvents(hostId, {
      limit: ITEMS_PER_PAGE,
      offset: eventsPage * ITEMS_PER_PAGE,
    })
      .then((response) => {
        setEvents(response.items);
        setEventsTotal(response.total);
      })
      .catch((error) => {
        setEventsError(
          error instanceof Error
            ? error.message
            : "Failed to load host events.",
        );
      })
      .finally(() => {
        setEventsLoading(false);
      });
  }, [hostId, eventsPage]);

  useEffect(() => {
    if (!host) {
      setAlerts([]);
      setAlertsTotal(0);
      setAlertsLoading(false);
      return;
    }

    setAlertsLoading(true);
    setAlertsError(null);

    getHostAlerts(host.hostname, {
      limit: ITEMS_PER_PAGE,
      offset: alertsPage * ITEMS_PER_PAGE,
    })
      .then((response) => {
        setAlerts(response.items);
        setAlertsTotal(response.total);
      })
      .catch((error) => {
        setAlertsError(
          error instanceof Error
            ? error.message
            : "Failed to load host alerts.",
        );
      })
      .finally(() => {
        setAlertsLoading(false);
      });
  }, [host, alertsPage]);

  useEffect(() => {
    setEventsPage(0);
    setAlertsPage(0);
  }, [hostId]);

  const totalEventPages = Math.ceil(eventsTotal / ITEMS_PER_PAGE);
  const totalAlertPages = Math.ceil(alertsTotal / ITEMS_PER_PAGE);

  if (loading) {
    return (
      <Layout>
        <div className="page">
          <div className="state-card">
            <span className="status-dot" style={{ marginRight: "10px" }} />
            Loading host...
          </div>
        </div>
      </Layout>
    );
  }

  if (error || !host) {
    return (
      <Layout>
        <div className="page">
          <Link to="/hosts" className="detail-back-link">
            <span aria-hidden="true">←</span> Back to hosts
          </Link>

          <div className="error-state" role="alert">
            <div>
              <strong>Host not found</strong>
              <p style={{ margin: "4px 0 0", fontSize: "12px" }}>
                {error ?? "The requested host does not exist."}
              </p>
            </div>
          </div>
        </div>
      </Layout>
    );
  }

  const hostStatus = host.status.toLowerCase();
  const statusClass =
    hostStatus === "online" || hostStatus === "active"
      ? "status-resolved"
      : hostStatus === "offline" || hostStatus === "inactive"
      ? "status-open"
      : "status-false_positive";

  return (
    <Layout>
      <div className="page">
        <header
          className="page-header"
          style={{ flexDirection: "column", alignItems: "flex-start" }}
        >
          <div
            style={{
              width: "100%",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "flex-start",
              flexWrap: "wrap",
              gap: "16px",
            }}
          >
            <div>
              <Link to="/hosts" className="detail-back-link">
                <span aria-hidden="true">←</span> Back to hosts
              </Link>

              <span className="dashboard-eyebrow">
                SECURITY MONITORING
              </span>

              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "12px",
                  marginTop: "4px",
                }}
              >
                <h1 style={{ margin: 0 }}>{host.hostname}</h1>

                <span className={`badge-status ${statusClass}`}>
                  {host.status.toUpperCase()}
                </span>
              </div>

              <p
                className="text-mono"
                style={{
                  margin: "8px 0 0",
                  color: "var(--text-muted)",
                  fontSize: "13px",
                }}
              >
                {host.ip_address}
              </p>
            </div>

            <div className="page-live-status">
              <span className="status-dot" />
              Host monitored
            </div>
          </div>
        </header>

        <section className="dashboard-stats">
          <div className="stat-card">
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
              }}
            >
              <span className="stat-label">Total Events</span>
              <span style={{ color: "var(--accent-blue-light)", fontSize: "16px" }}>
                ≋
              </span>
            </div>

            <strong className="stat-value">
              {host.events.toLocaleString()}
            </strong>

            <span style={{ fontSize: "11px", color: "var(--text-subtle)" }}>
              Events received from this host
            </span>
          </div>

          <div className="stat-card">
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
              }}
            >
              <span className="stat-label">Security Alerts</span>
              <span
                style={{
                  color: "var(--accent-red)",
                  fontSize: "16px",
                  fontWeight: "bold",
                }}
              >
                !
              </span>
            </div>

            <strong className="stat-value">
              {host.alerts.toLocaleString()}
            </strong>

            <span style={{ fontSize: "11px", color: "var(--text-subtle)" }}>
              Alerts associated with this host
            </span>
          </div>

          <div className="stat-card">
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
              }}
            >
              <span className="stat-label">Last Seen</span>
              <span style={{ color: "var(--accent-yellow)", fontSize: "16px" }}>
                ◷
              </span>
            </div>

            <strong className="stat-value" style={{ fontSize: "22px" }}>
              {new Date(host.last_seen).toLocaleTimeString([], {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit",
              })}
            </strong>

            <span style={{ fontSize: "11px", color: "var(--text-subtle)" }}>
              Last received event
            </span>
          </div>
        </section>

        <section className="content-card" style={{ padding: "20px" }}>
          <div
            className="section-header"
            style={{ padding: 0, marginBottom: "20px", borderBottom: "none" }}
          >
            <div>
              <h2>Host Information</h2>
              <p>System information and monitoring details</p>
            </div>

            <span style={{ fontSize: "18px", color: "var(--accent-blue-light)" }}>
              ◎
            </span>
          </div>

          <div className="detail-fields-grid">
            <div className="detail-field">
              <span>Hostname</span>
              <strong>{host.hostname}</strong>
            </div>

            <div className="detail-field">
              <span>IP Address</span>
              <strong className="text-mono">{host.ip_address}</strong>
            </div>

            <div className="detail-field">
              <span>Total Events</span>
              <strong>{host.events.toLocaleString()}</strong>
            </div>

            <div className="detail-field">
              <span>Total Alerts</span>
              <strong>{host.alerts.toLocaleString()}</strong>
            </div>

            <div className="detail-field">
              <span>Last Seen</span>
              <strong>{new Date(host.last_seen).toLocaleString()}</strong>
            </div>

            <div className="detail-field">
              <span>Monitoring Status</span>
              <strong style={{ textTransform: "uppercase" }}>{host.status}</strong>
            </div>
          </div>
        </section>

        <section className="content-card" style={{ padding: "20px" }}>
          <div
            className="section-header"
            style={{ padding: 0, marginBottom: "20px", borderBottom: "none" }}
          >
            <div>
              <h2>Recent Events</h2>
              <p>Latest events associated with this host</p>
            </div>

            <Link
              to={`/events?destination_ip=${encodeURIComponent(host.ip_address)}`}
              className="text-link"
              style={{
                fontSize: "12px",
                display: "inline-flex",
                alignItems: "center",
                gap: "4px",
              }}
            >
              View all events <span>→</span>
            </Link>
          </div>

          {eventsLoading && (
            <div className="empty-state">Loading events...</div>
          )}

          {!eventsLoading && eventsError && (
            <div className="error-state" role="alert" style={{ margin: 0 }}>
              <div>{eventsError}</div>
            </div>
          )}

          {!eventsLoading && !eventsError && events.length === 0 && (
            <div className="empty-state">
              <strong>No events found</strong>
              <p
                style={{
                  margin: 0,
                  color: "var(--text-subtle)",
                  fontSize: "12px",
                }}
              >
                No events are currently associated with this host.
              </p>
            </div>
          )}

          {!eventsLoading && !eventsError && events.length > 0 && (
            <>
              <div className="table-container">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Timestamp</th>
                      <th>Event Type</th>
                      <th>Severity</th>
                      <th>Source IP</th>
                      <th>Username</th>
                      <th>Service</th>
                    </tr>
                  </thead>

                  <tbody>
                    {events.map((event) => (
                      <tr key={event.id}>
                        <td className="text-timestamp">
                          {new Date(event.timestamp).toLocaleString()}
                        </td>

                        <td>
                          <Link
                            to={`/events/${event.id}`}
                            className="text-link"
                            style={{ fontWeight: 500 }}
                          >
                            {event.event_type.replace(/_/g, " ")}
                          </Link>
                        </td>

                        <td>
                          <span
                            className={`badge-severity severity-${event.severity.toLowerCase()}`}
                          >
                            {event.severity}
                          </span>
                        </td>

                        <td className="text-mono">{event.source_ip ?? "-"}</td>
                        <td>{event.username ?? "-"}</td>
                        <td>{event.service ?? "-"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {totalEventPages > 1 && (
                <div className="pagination">
                  <span>
                    Page {eventsPage + 1} of {totalEventPages}
                  </span>

                  <div className="pagination-buttons">
                    <button
                      disabled={eventsPage === 0}
                      onClick={() => setEventsPage((current) => current - 1)}
                    >
                      ← Previous
                    </button>

                    <button
                      disabled={eventsPage >= totalEventPages - 1}
                      onClick={() => setEventsPage((current) => current + 1)}
                    >
                      Next →
                    </button>
                  </div>
                </div>
              )}
            </>
          )}
        </section>

        <section className="content-card" style={{ padding: "20px" }}>
          <div
            className="section-header"
            style={{ padding: 0, marginBottom: "20px", borderBottom: "none" }}
          >
            <div>
              <h2>Security Alerts</h2>
              <p>Alerts associated with this host</p>
            </div>

            <Link
              to={`/alerts?affected_host=${encodeURIComponent(host.hostname)}`}
              className="text-link"
              style={{
                fontSize: "12px",
                display: "inline-flex",
                alignItems: "center",
                gap: "4px",
              }}
            >
              View all alerts <span>→</span>
            </Link>
          </div>

          {alertsLoading && (
            <div className="empty-state">Loading alerts...</div>
          )}

          {!alertsLoading && alertsError && (
            <div className="error-state" role="alert" style={{ margin: 0 }}>
              <div>{alertsError}</div>
            </div>
          )}

          {!alertsLoading && !alertsError && alerts.length === 0 && (
            <div className="empty-state">
              <strong>No alerts found</strong>
              <p
                style={{
                  margin: 0,
                  color: "var(--text-subtle)",
                  fontSize: "12px",
                }}
              >
                No security alerts are currently associated with this host.
              </p>
            </div>
          )}

          {!alertsLoading && !alertsError && alerts.length > 0 && (
            <>
              <div className="table-container">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Timestamp</th>
                      <th>Alert</th>
                      <th>Rule</th>
                      <th>Source IP</th>
                      <th>Severity</th>
                      <th>Status</th>
                    </tr>
                  </thead>

                  <tbody>
                    {alerts.map((alert) => (
                      <tr key={alert.id}>
                        <td className="text-timestamp">
                          {new Date(alert.timestamp).toLocaleString()}
                        </td>

                        <td>
                          <Link
                            to={`/alerts/${alert.id}`}
                            className="text-link"
                            style={{ fontWeight: 500 }}
                          >
                            {alert.title}
                          </Link>
                        </td>

                        <td className="text-mono">{alert.rule_id}</td>
                        <td className="text-mono">{alert.source_ip ?? "-"}</td>

                        <td>
                          <span
                            className={`badge-severity severity-${alert.severity.toLowerCase()}`}
                          >
                            {alert.severity}
                          </span>
                        </td>

                        <td>
                          <span
                            className={`badge-status status-${alert.status.toLowerCase()}`}
                          >
                            {alert.status.replace(/_/g, " ")}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {totalAlertPages > 1 && (
                <div className="pagination">
                  <span>
                    Page {alertsPage + 1} of {totalAlertPages}
                  </span>

                  <div className="pagination-buttons">
                    <button
                      disabled={alertsPage === 0}
                      onClick={() => setAlertsPage((current) => current - 1)}
                    >
                      ← Previous
                    </button>

                    <button
                      disabled={alertsPage >= totalAlertPages - 1}
                      onClick={() => setAlertsPage((current) => current + 1)}
                    >
                      Next →
                    </button>
                  </div>
                </div>
              )}
            </>
          )}
        </section>
      </div>
    </Layout>
  );
}

export default HostDetail;