import { Link } from "react-router-dom";
import type { Correlation } from "../types/siem";

interface RecentCorrelationsProps {
  correlations: Correlation[];
}

function RecentCorrelations({
  correlations,
}: RecentCorrelationsProps) {
  return (
    <section className="content-card" style={{ padding: "20px" }}>
      <div
        className="section-header"
        style={{ padding: 0, marginBottom: "20px", borderBottom: "none" }}
      >
        <div>
          <h2>Recent Correlations</h2>
          <p>Related security events grouped together</p>
        </div>

        <Link
          to="/correlations"
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
        {correlations.length === 0 ? (
          <div className="empty-state">
            <span className="empty-icon">✓</span>
            <strong>No correlations found</strong>
            <p
              style={{
                margin: 0,
                color: "var(--text-subtle)",
                fontSize: "12px",
              }}
            >
              No related event groups to review right now.
            </p>
          </div>
        ) : (
          correlations.map((correlation, index) => (
            <Link
              key={correlation.id ?? `correlation-${index}`}
              to={
                correlation.id != null
                  ? `/correlations/${correlation.id}`
                  : "/correlations"
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
                    backgroundColor: "var(--accent-blue-light)",
                    boxShadow: "0 0 8px var(--accent-blue-light)",
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
                    {correlation.correlation_rule_id}
                  </strong>

                  <span
                    style={{
                      color: "var(--text-muted)",
                      fontSize: "11px",
                    }}
                  >
                    <span className="text-mono">
                      {correlation.source_ip ?? "Unknown source"}
                    </span>
                    {" · "}
                    <span>
                      {correlation.affected_host ?? "Unknown host"}
                    </span>
                  </span>

                  <span
                    style={{
                      color: "var(--accent-blue-light)",
                      fontSize: "11px",
                      display: "inline-flex",
                      alignItems: "center",
                      gap: "2px",
                    }}
                  >
                    <span aria-hidden="true">↗</span>
                    {correlation.alerts.length} related alert
                    {correlation.alerts.length !== 1 ? "s" : ""}
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
                  className="text-timestamp"
                  style={{ fontSize: "11px" }}
                >
                  {new Date(correlation.timestamp).toLocaleTimeString(
                    [],
                    {
                      hour: "2-digit",
                      minute: "2-digit",
                    },
                  )}
                </span>
              </div>
            </Link>
          ))
        )}
      </div>
    </section>
  );
}

export default RecentCorrelations;