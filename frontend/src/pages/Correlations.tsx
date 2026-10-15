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
import { getCorrelations } from "../api/correlations";

import { useEventStream } from "../hooks/useEventStream";

import type { Correlation } from "../types/siem";

const PAGE_SIZE = 20;

function Correlations() {
  const [searchParams, setSearchParams] =
    useSearchParams();

  const [correlations, setCorrelations] = useState<
    Correlation[]
  >([]);

  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);

  const [sourceIp, setSourceIp] = useState(
    searchParams.get("source_ip") ?? "",
  );

  const [affectedHost, setAffectedHost] = useState(
    searchParams.get("affected_host") ?? "",
  );

  const [sourceIpInput, setSourceIpInput] = useState(
    searchParams.get("source_ip") ?? "",
  );

  const [hostInput, setHostInput] = useState(
    searchParams.get("affected_host") ?? "",
  );

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadCorrelations = useCallback(() => {
    setLoading(true);
    setError(null);

    getCorrelations({
      limit: PAGE_SIZE,
      offset: page * PAGE_SIZE,
      source_ip: sourceIp || undefined,
      affected_host: affectedHost || undefined,
    })
      .then((response) => {
        setCorrelations(response.items);
        setTotal(response.total);
      })
      .catch((error) => {
        setError(
          error instanceof Error
            ? error.message
            : "Failed to load correlations.",
        );
      })
      .finally(() => {
        setLoading(false);
      });
  }, [page, sourceIp, affectedHost]);

  useEffect(() => {
    loadCorrelations();
  }, [loadCorrelations]);

  useEventStream(
    useCallback(
      (streamEvent) => {
        if (streamEvent.type === "correlation_created") {
          loadCorrelations();
        }
      },
      [loadCorrelations],
    ),
  );

  const totalPages = Math.ceil(total / PAGE_SIZE);

  function updateUrl(
    newSourceIp: string,
    newAffectedHost: string,
  ) {
    const params = new URLSearchParams();

    if (newSourceIp.trim()) {
      params.set("source_ip", newSourceIp.trim());
    }

    if (newAffectedHost.trim()) {
      params.set("affected_host", newAffectedHost.trim());
    }

    setSearchParams(params);
  }

  function applySourceIpFilter() {
    const value = sourceIpInput.trim();

    setSourceIp(value);
    setSourceIpInput(value);
    setPage(0);
    updateUrl(value, affectedHost);
  }

  function clearSourceIpFilter() {
    setSourceIpInput("");
    setSourceIp("");
    setPage(0);
    updateUrl("", affectedHost);
  }

  function applyHostFilter() {
    const value = hostInput.trim();

    setAffectedHost(value);
    setHostInput(value);
    setPage(0);
    updateUrl(sourceIp, value);
  }

  function clearHostFilter() {
    setHostInput("");
    setAffectedHost("");
    setPage(0);
    updateUrl(sourceIp, "");
  }

  function handleSourceIpKeyDown(
    event: React.KeyboardEvent<HTMLInputElement>,
  ) {
    if (event.key === "Enter") {
      applySourceIpFilter();
    }
  }

  function handleHostKeyDown(
    event: React.KeyboardEvent<HTMLInputElement>,
  ) {
    if (event.key === "Enter") {
      applyHostFilter();
    }
  }

  return (
    <Layout>
      <div className="page">
        <header className="page-header">
          <div>
            <span className="dashboard-eyebrow">
              SECURITY ANALYSIS
            </span>

            <h1>Correlations</h1>

            <p>
              Relationships detected between multiple
              security alerts.
            </p>
          </div>

          <div className="page-live-status">
            <span className="status-dot" />
            Correlation monitoring
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
                Find correlations by source IP or affected host.
              </p>
            </div>

            <span className="btn" style={{ cursor: "default", opacity: 0.8 }}>
              {total} {total === 1 ? "correlation" : "correlations"}
            </span>
          </div>

          <div className="filter-grid">
            <div className="filter-group">
              <label htmlFor="correlation-source-ip">
                Source IP
              </label>

              <div className="filter-actions">
                <input
                  id="correlation-source-ip"
                  type="text"
                  className="filter-input"
                  placeholder="e.g. 192.168.1.100"
                  value={sourceIpInput}
                  onChange={(event) =>
                    setSourceIpInput(event.target.value)
                  }
                  onKeyDown={handleSourceIpKeyDown}
                />

                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={applySourceIpFilter}
                >
                  Apply
                </button>

                {sourceIp && (
                  <button
                    type="button"
                    className="btn"
                    onClick={clearSourceIpFilter}
                  >
                    Clear
                  </button>
                )}
              </div>
            </div>

            <div className="filter-group">
              <label htmlFor="correlation-affected-host">
                Affected host
              </label>

              <div className="filter-actions">
                <input
                  id="correlation-affected-host"
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

            <button type="button" className="btn" onClick={loadCorrelations}>
              Retry
            </button>
          </div>
        )}

        {loading ? (
          <div className="state-card">
            <span className="status-dot" style={{ marginRight: "10px" }} />
            Loading correlations...
          </div>
        ) : !error ? (
          <section className="content-card">
            <div className="section-header">
              <div>
                <h2>Detected correlations</h2>
                <p>
                  Review related alerts and investigate their details.
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
                    <th>Correlation Rule</th>
                    <th>Source IP</th>
                    <th>Affected Host</th>
                    <th>Alerts</th>
                  </tr>
                </thead>

                <tbody>
                  {correlations.map((correlation) => (
                    <tr key={correlation.id}>
                      <td className="text-timestamp">
                        <Link
                          to={`/correlations/${correlation.id}`}
                          className="text-link"
                        >
                          {new Date(
                            correlation.timestamp,
                          ).toLocaleString()}
                        </Link>
                      </td>

                      <td>
                        <Link
                          to={`/correlations/${correlation.id}`}
                          className="text-link text-mono"
                          style={{ fontWeight: 500 }}
                        >
                          {correlation.correlation_rule_id}
                        </Link>
                      </td>

                      <td className="text-mono">
                        {correlation.source_ip ?? "-"}
                      </td>

                      <td>
                        {correlation.affected_host ?? "-"}
                      </td>

                      <td>
                        <span
                          className="text-mono"
                          style={{
                            padding: "2px 8px",
                            background: "#202531",
                            borderRadius: "4px",
                            border: "1px solid #2b3140",
                            fontSize: "11px",
                            fontWeight: 600,
                          }}
                        >
                          {correlation.alerts.length}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>

              {correlations.length === 0 && (
                <div className="empty-state">
                  <span className="empty-icon">↗</span>
                  <strong>No correlations found</strong>
                  <p
                    style={{
                      margin: 0,
                      color: "var(--text-subtle)",
                      fontSize: "12px",
                    }}
                  >
                    Try changing your filters or check back when
                    new correlations are detected.
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
                    Previous
                  </button>

                  <button
                    disabled={page >= totalPages - 1}
                    onClick={() =>
                      setPage((current) => current + 1)
                    }
                  >
                    Next
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

export default Correlations;