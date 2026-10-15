import { Link } from "react-router-dom";
import type { Incident } from "../types/siem";

interface RecentIncidentsProps {
  incidents: Incident[];
}

function RecentIncidents({
  incidents,
}: RecentIncidentsProps) {
  return (
    <section className="content-card" style={{ padding: "20px" }}>
      <div
        className="section-header"
        style={{ padding: 0, marginBottom: "20px", borderBottom: "none" }}
      >
        <div>
          <h2>Recent Incidents</h2>
          <p>Security incidents requiring attention</p>
        </div>

        <Link
          to="/incidents"
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
        {incidents.length === 0 ? (
          <div className="empty-state">
            <span className="empty-icon">✓</span>
            <strong>No incidents found</strong>
            <p
              style={{
                margin: 0,
                color: "var(--text-subtle)",
                fontSize: "12px",
              }}
            >
              No incidents require review right now.
            </p>
          </div>
        ) : (
          incidents.map((incident, index) => {
            const severity = incident.severity.toLowerCase();
            const status = incident.status.toLowerCase();

            return (
              <Link
                key={incident.id ?? `incident-${index}`}
                to={
                  incident.id != null
                    ? `/incidents/${incident.id}`
                    : "/incidents"
                }
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
                      {incident.title}
                    </strong>

                    <span
                      style={{
                        color: "var(--text-muted)",
                        fontSize: "11px",
                      }}
                    >
                      <span className="text-mono">
                        {incident.source_ip ?? "Unknown source"}
                      </span>
                      {" · "}
                      <span>
                        {incident.affected_host ?? "Unknown host"}
                      </span>
                    </span>

                    <span
                      style={{
                        color: "var(--text-subtle)",
                        fontSize: "11px",
                      }}
                    >
                      {incident.related_alerts.length} alert
                      {incident.related_alerts.length !== 1 ? "s" : ""}
                      {" · "}
                      {incident.related_correlations.length} correlation
                      {incident.related_correlations.length !== 1 ? "s" : ""}
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
                    {incident.severity.toUpperCase()}
                  </span>

                  <span
                    className={`badge-status status-${status}`}
                  >
                    {status.replace(/_/g, " ").toUpperCase()}
                  </span>

                  <span
                    className="text-timestamp"
                    style={{ fontSize: "11px" }}
                  >
                    {new Date(incident.timestamp).toLocaleTimeString(
                      [],
                      {
                        hour: "2-digit",
                        minute: "2-digit",
                      },
                    )}
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

export default RecentIncidents;