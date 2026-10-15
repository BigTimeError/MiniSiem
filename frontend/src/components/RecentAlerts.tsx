import { Link } from "react-router-dom";
import type { Alert } from "../types/siem";

interface RecentAlertsProps {
  alerts: Alert[];
}

function RecentAlerts({ alerts }: RecentAlertsProps) {
  return (
    <section className="content-card" style={{ padding: "20px" }}>
      <div
        className="section-header"
        style={{ padding: 0, marginBottom: "20px", borderBottom: "none" }}
      >
        <div>
          <h2>Recent Alerts</h2>
          <p>Latest security alerts detected by the system</p>
        </div>

        <Link
          to="/alerts"
          className="text-link"
          style={{
            fontSize: "12px",
            display: "inline-flex",
            alignItems: "center",
            gap: "4px",
          }}
        >
          View all <span aria-hidden="true">→</span>
        </Link>
      </div>

      <div
        className="related-list"
        style={{ display: "flex", flexDirection: "column", gap: "8px" }}
      >
        {alerts.length === 0 ? (
          <div className="empty-state">
            <span className="empty-icon">✓</span>
            <strong>No security alerts found</strong>
            <p
              style={{
                margin: 0,
                color: "var(--text-subtle)",
                fontSize: "12px",
              }}
            >
              There are no alerts to review right now.
            </p>
          </div>
        ) : (
          alerts.map((alert) => {
            const severity = alert.severity.toLowerCase();

            return (
              <Link
                key={alert.id}
                to={`/alerts/${alert.id}`}
                className="related-item"
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  width: "100%",
                  textDecoration: "none",
                }}
              >
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "12px",
                    minWidth: 0,
                  }}
                >
                  <span
                    className="status-dot"
                    style={{
                      backgroundColor: `var(--severity-${severity})`,
                      boxShadow: `0 0 8px var(--severity-${severity})`,
                      flexShrink: 0,
                    }}
                  />

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
                      <span className="text-mono">
                        {alert.source_ip ?? "Unknown source"}
                      </span>
                      {" · "}
                      <span className="text-mono">{alert.rule_id}</span>
                    </span>
                  </div>
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
                    className={`badge-severity severity-${severity}`}
                  >
                    {alert.severity.toUpperCase()}
                  </span>

                  <span
                    className="text-timestamp"
                    style={{ fontSize: "11px" }}
                  >
                    {new Date(alert.timestamp).toLocaleTimeString([], {
                      hour: "2-digit",
                      minute: "2-digit",
                    })}
                  </span>
                </div>
              </Link>
            );
          })
        )}
      </div>
    </section>
  );
}

export default RecentAlerts;