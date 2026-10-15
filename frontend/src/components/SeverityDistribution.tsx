import type { Event } from "../types/siem";

interface SeverityDistributionProps {
  events: Event[];
}

const severities = [
  { label: "Critical", color: "var(--severity-critical, #f87171)" },
  { label: "High", color: "var(--severity-high, #fb923c)" },
  { label: "Medium", color: "var(--severity-medium, #facc15)" },
  { label: "Low", color: "var(--severity-low, #4ade80)" },
  { label: "Info", color: "var(--severity-info, #60a5fa)" },
] as const;

function SeverityDistribution({
  events,
}: SeverityDistributionProps) {
  const counts = severities.map((severity) => ({
    ...severity,
    count: events.filter(
      (event) =>
        event.severity.toLowerCase() ===
        severity.label.toLowerCase(),
    ).length,
  }));

  const total = counts.reduce(
    (sum, severity) => sum + severity.count,
    0,
  );

  return (
    <section className="content-card" style={{ padding: "20px" }}>
      <div
        className="section-header"
        style={{ padding: 0, marginBottom: "20px", borderBottom: "none" }}
      >
        <div>
          <h2>Event Severity</h2>
          <p>Distribution of loaded events</p>
        </div>

        <span className="btn" style={{ cursor: "default", opacity: 0.8 }}>
          {total}
        </span>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
        {counts.map((severity) => {
          const percentage =
            total > 0
              ? (severity.count / total) * 100
              : 0;

          return (
            <div
              key={severity.label}
              style={{
                display: "flex",
                flexDirection: "column",
                gap: "6px",
              }}
            >
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  fontSize: "12px",
                }}
              >
                <span
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: "8px",
                    color: "var(--text-primary)",
                    fontWeight: 500,
                  }}
                >
                  <span
                    className="status-dot"
                    style={{
                      backgroundColor: severity.color,
                      boxShadow: `0 0 8px ${severity.color}`,
                    }}
                  />
                  {severity.label}
                </span>

                <span style={{ color: "var(--text-muted)" }}>
                  <strong
                    style={{
                      color: "var(--text-primary)",
                      marginRight: "4px",
                    }}
                  >
                    {severity.count}
                  </strong>
                  ({percentage.toFixed(0)}%)
                </span>
              </div>

              <div
                style={{
                  height: "6px",
                  width: "100%",
                  backgroundColor: "var(--bg-card-alt, #1c202b)",
                  borderRadius: "3px",
                  overflow: "hidden",
                }}
              >
                <div
                  style={{
                    height: "100%",
                    width: `${percentage}%`,
                    backgroundColor: severity.color,
                    borderRadius: "3px",
                    transition: "width 0.3s ease",
                  }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}

export default SeverityDistribution;