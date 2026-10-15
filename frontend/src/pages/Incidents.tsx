import {
  useCallback,
  useEffect,
  useState,
} from "react";
import {
  Link,
  useSearchParams,
} from "react-router-dom";

import Layout from "../components/Layout";
import {
  getIncidents,
  updateIncidentStatus,
} from "../api/incidents";

import { useEventStream } from "../hooks/useEventStream";

import type {
  Incident,
  IncidentStatus,
  Severity,
} from "../types/siem";

const PAGE_SIZE = 20;

const STATUSES: IncidentStatus[] = [
  "open",
  "investigating",
  "resolved",
  "closed",
  "false_positive",
];

const SEVERITIES: Severity[] = [
  "info",
  "low",
  "medium",
  "high",
  "critical",
];

function Incidents() {
  const [searchParams, setSearchParams] =
    useSearchParams();

  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);

  const [status, setStatus] = useState<IncidentStatus | "">(
    (searchParams.get("status") as IncidentStatus | null) ?? "",
  );

  const [severity, setSeverity] = useState<Severity | "">(
    (searchParams.get("severity") as Severity | null) ?? "",
  );

  const [affectedHost, setAffectedHost] = useState(
    searchParams.get("affected_host") ?? "",
  );

  const [hostInput, setHostInput] = useState(
    searchParams.get("affected_host") ?? "",
  );

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadIncidents = useCallback(() => {
    setLoading(true);
    setError(null);

    getIncidents({
      limit: PAGE_SIZE,
      offset: page * PAGE_SIZE,
      status: status || undefined,
      severity: severity || undefined,
      affected_host: affectedHost || undefined,
    })
      .then((response) => {
        setIncidents(response.items);
        setTotal(response.total);
      })
      .catch((error) => {
        setError(
          error instanceof Error
            ? error.message
            : "Failed to load incidents.",
        );
      })
      .finally(() => {
        setLoading(false);
      });
  }, [page, status, severity, affectedHost]);

  useEffect(() => {
    loadIncidents();
  }, [loadIncidents]);

  useEventStream(
    useCallback(
      (streamEvent) => {
        if (streamEvent.type === "incident_created") {
          loadIncidents();
        }
      },
      [loadIncidents],
    ),
  );

  const totalPages = Math.ceil(total / PAGE_SIZE);

  function updateUrl(
    newStatus: IncidentStatus | "",
    newSeverity: Severity | "",
    newAffectedHost: string,
  ) {
    const params = new URLSearchParams();

    if (newStatus) {
      params.set("status", newStatus);
    }

    if (newSeverity) {
      params.set("severity", newSeverity);
    }

    if (newAffectedHost.trim()) {
      params.set("affected_host", newAffectedHost.trim());
    }

    setSearchParams(params);
  }

  function handleStatusChange(value: IncidentStatus | "") {
    setStatus(value);
    setPage(0);
    updateUrl(value, severity, affectedHost);
  }

  function handleSeverityChange(value: Severity | "") {
    setSeverity(value);
    setPage(0);
    updateUrl(status, value, affectedHost);
  }

  function applyHostFilter() {
    const value = hostInput.trim();

    setAffectedHost(value);
    setHostInput(value);
    setPage(0);
    updateUrl(status, severity, value);
  }

  function clearHostFilter() {
    setHostInput("");
    setAffectedHost("");
    setPage(0);
    updateUrl(status, severity, "");
  }

  function handleHostKeyDown(
    event: React.KeyboardEvent<HTMLInputElement>,
  ) {
    if (event.key === "Enter") {
      applyHostFilter();
    }
  }

  async function handleIncidentStatusChange(
    incidentId: number,
    newStatus: IncidentStatus,
  ) {
    try {
      const updatedIncident = await updateIncidentStatus(
        incidentId,
        newStatus,
      );

      setIncidents((currentIncidents) =>
        currentIncidents.map((incident) =>
          incident.id === updatedIncident.id
            ? updatedIncident
            : incident,
        ),
      );
    } catch (error) {
      setError(
        error instanceof Error
          ? error.message
          : "Failed to update incident.",
      );
    }
  }

  return (
    <Layout>
      <div className="page">
        <header className="page-header">
          <div>
            <span className="dashboard-eyebrow">
              SECURITY RESPONSE
            </span>

            <h1>Incidents</h1>

            <p>
              Investigate and manage security incidents created
              from correlated alerts.
            </p>
          </div>

          <div className="page-live-status">
            <span className="status-dot" />
            Incident monitoring
          </div>
        </header>

        <section className="filter-card">
          <div
            className="section-header"
            style={{ padding: 0, marginBottom: "20px", borderBottom: "none" }}
          >
            <div>
              <h2>Filters</h2>
              <p>
                Narrow down incidents by status, severity or host.
              </p>
            </div>

            <span className="btn" style={{ cursor: "default", opacity: 0.8 }}>
              {total} {total === 1 ? "incident" : "incidents"}
            </span>
          </div>

          <div className="filter-grid">
            <div className="filter-group">
              <label htmlFor="incident-status">Status</label>

              <select
                id="incident-status"
                className="filter-select"
                value={status}
                onChange={(event) =>
                  handleStatusChange(
                    event.target.value as IncidentStatus | "",
                  )
                }
              >
                <option value="">All statuses</option>

                {STATUSES.map((value) => (
                  <option key={value} value={value}>
                    {value.replace("_", " ")}
                  </option>
                ))}
              </select>
            </div>

            <div className="filter-group">
              <label htmlFor="incident-severity">Severity</label>

              <select
                id="incident-severity"
                className="filter-select"
                value={severity}
                onChange={(event) =>
                  handleSeverityChange(
                    event.target.value as Severity | "",
                  )
                }
              >
                <option value="">All severities</option>

                {SEVERITIES.map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </select>
            </div>

            <div className="filter-group">
              <label htmlFor="incident-affected-host">
                Affected host
              </label>

              <div className="filter-actions">
                <input
                  id="incident-affected-host"
                  type="text"
                  className="filter-input"
                  placeholder="e.g. server01"
                  value={hostInput}
                  onChange={(event) =>
                    setHostInput(event.target.value)
                  }
                  onKeyDown={handleHostKeyDown}
                />

                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={applyHostFilter}
                >
                  Apply
                </button>

                {affectedHost && (
                  <button
                    type="button"
                    className="btn"
                    onClick={clearHostFilter}
                  >
                    Clear
                  </button>
                )}
              </div>
            </div>
          </div>
        </section>

        {error && (
          <div className="error-state" role="alert">
            <div>
              <strong>Something went wrong</strong>
              <p style={{ margin: "4px 0 0", fontSize: "12px" }}>{error}</p>
            </div>

            <button type="button" className="btn" onClick={loadIncidents}>
              Retry
            </button>
          </div>
        )}

        {loading ? (
          <div className="state-card">
            <span className="status-dot" style={{ marginRight: "10px" }} />
            Loading incidents...
          </div>
        ) : !error ? (
          <section className="content-card">
            <div className="section-header">
              <div>
                <h2>All incidents</h2>
                <p>
                  Review incident details, severity and response status.
                </p>
              </div>

              <span className="btn" style={{ cursor: "default", opacity: 0.8 }}>
                {total} total
              </span>
            </div>

            <div className="table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Incident</th>
                    <th>Source IP</th>
                    <th>Affected Host</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Action</th>
                  </tr>
                </thead>

                <tbody>
                  {incidents.map((incident) => (
                    <tr key={incident.id}>
                      <td className="text-timestamp">
                        {new Date(
                          incident.timestamp,
                        ).toLocaleString()}
                      </td>

                      <td>
                        <Link
                          to={`/incidents/${incident.id}`}
                          className="text-link"
                          style={{ fontWeight: 500 }}
                        >
                          {incident.title}
                        </Link>
                      </td>

                      <td className="text-mono">
                        {incident.source_ip ?? "-"}
                      </td>

                      <td>
                        {incident.affected_host ?? "-"}
                      </td>

                      <td>
                        <span
                          className={`badge-severity severity-${incident.severity.toLowerCase()}`}
                        >
                          {incident.severity}
                        </span>
                      </td>

                      <td>
                        <span
                          className={`badge-status status-${incident.status.toLowerCase()}`}
                        >
                          {incident.status.replace("_", " ")}
                        </span>
                      </td>

                      <td>
                        <select
                          aria-label={`Update status for ${incident.title}`}
                          className="filter-select"
                          style={{ padding: "4px 8px", fontSize: "12px" }}
                          value={incident.status}
                          onChange={(event) =>
                            handleIncidentStatusChange(
                              incident.id!,
                              event.target.value as IncidentStatus,
                            )
                          }
                        >
                          {STATUSES.map((value) => (
                            <option key={value} value={value}>
                              {value.replace("_", " ")}
                            </option>
                          ))}
                        </select>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>

              {incidents.length === 0 && (
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
                    Try changing your filters or check back when new incidents are created.
                  </p>
                </div>
              )}
            </div>

            {totalPages > 1 && (
              <div className="pagination">
                <span>
                  Page {page + 1} of {totalPages}
                </span>

                <div className="pagination-buttons">
                  <button
                    disabled={page === 0}
                    onClick={() =>
                      setPage((current) => current - 1)
                    }
                  >
                    ← Previous
                  </button>

                  <button
                    disabled={page >= totalPages - 1}
                    onClick={() =>
                      setPage((current) => current + 1)
                    }
                  >
                    Next →
                  </button>
                </div>
              </div>
            )}
          </section>
        ) : null}
      </div>
    </Layout>
  );
}

export default Incidents;