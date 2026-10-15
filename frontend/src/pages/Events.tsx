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
import { getEvents } from "../api/events";
import { useEventStream } from "../hooks/useEventStream";

import type {
  Event,
  EventType,
} from "../types/siem";

const PAGE_SIZE = 20;

const EVENT_TYPES: EventType[] = [
  "authentication_failure",
  "authentication_success",
  "invalid_user_login",
  "network_connection",
  "process_execution",
  "http_request",
];

function Events() {
  const [searchParams, setSearchParams] =
    useSearchParams();

  const [events, setEvents] = useState<Event[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);

  const [eventType, setEventType] = useState<
    EventType | ""
  >(
    (searchParams.get("event_type") as EventType | null) ??
      "",
  );

  const [sourceIp, setSourceIp] = useState(
    searchParams.get("source_ip") ?? "",
  );

  const [sourceIpInput, setSourceIpInput] = useState(
    searchParams.get("source_ip") ?? "",
  );

  const [destinationIp, setDestinationIp] = useState(
    searchParams.get("destination_ip") ?? "",
  );

  const [destinationIpInput, setDestinationIpInput] =
    useState(
      searchParams.get("destination_ip") ?? "",
    );

  const [loading, setLoading] = useState(true);

  const [error, setError] = useState<string | null>(
    null,
  );

  const loadEvents = useCallback(() => {
    setLoading(true);
    setError(null);

    return getEvents({
      limit: PAGE_SIZE,
      offset: page * PAGE_SIZE,
      event_type: eventType || undefined,
      source_ip: sourceIp || undefined,
      destination_ip: destinationIp || undefined,
    })
      .then((response) => {
        setEvents(response.items);
        setTotal(response.total);
      })
      .catch((error) => {
        setError(
          error instanceof Error
            ? error.message
            : "Failed to load events.",
        );
      })
      .finally(() => {
        setLoading(false);
      });
  }, [
    page,
    eventType,
    sourceIp,
    destinationIp,
  ]);

  useEffect(() => {
    loadEvents();
  }, [loadEvents]);

  useEventStream(
    useCallback(
      (streamEvent) => {
        if (streamEvent.type !== "event_created") {
          return;
        }

        loadEvents();
      },
      [loadEvents],
    ),
  );

  const totalPages = Math.ceil(total / PAGE_SIZE);

  function updateUrl(
    newEventType: EventType | "",
    newSourceIp: string,
    newDestinationIp: string,
  ) {
    const params = new URLSearchParams();

    if (newEventType) {
      params.set("event_type", newEventType);
    }

    if (newSourceIp.trim()) {
      params.set("source_ip", newSourceIp.trim());
    }

    if (newDestinationIp.trim()) {
      params.set(
        "destination_ip",
        newDestinationIp.trim(),
      );
    }

    setSearchParams(params);
  }

  function handleEventTypeChange(
    value: EventType | "",
  ) {
    setEventType(value);
    setPage(0);

    updateUrl(value, sourceIp, destinationIp);
  }

  function applySourceIpFilter() {
    const value = sourceIpInput.trim();

    setSourceIp(value);
    setSourceIpInput(value);
    setPage(0);

    updateUrl(eventType, value, destinationIp);
  }

  function clearSourceIpFilter() {
    setSourceIpInput("");
    setSourceIp("");
    setPage(0);

    updateUrl(eventType, "", destinationIp);
  }

  function applyDestinationIpFilter() {
    const value = destinationIpInput.trim();

    setDestinationIp(value);
    setDestinationIpInput(value);
    setPage(0);

    updateUrl(eventType, sourceIp, value);
  }

  function clearDestinationIpFilter() {
    setDestinationIpInput("");
    setDestinationIp("");
    setPage(0);

    updateUrl(eventType, sourceIp, "");
  }

  function handleSourceIpKeyDown(
    event: React.KeyboardEvent<HTMLInputElement>,
  ) {
    if (event.key === "Enter") {
      applySourceIpFilter();
    }
  }

  function handleDestinationIpKeyDown(
    event: React.KeyboardEvent<HTMLInputElement>,
  ) {
    if (event.key === "Enter") {
      applyDestinationIpFilter();
    }
  }

  return (
    <Layout>
      <div className="page">
        <header className="page-header">
          <div>
            <span className="dashboard-eyebrow">
              SECURITY OPERATIONS CENTER
            </span>

            <h1>Events</h1>

            <p>
              Security events collected by MiniSIEM
            </p>
          </div>

          <div className="page-live-status">
            <span className="status-dot" />

            <span>
              {loading
                ? "Loading events"
                : error
                  ? "Data unavailable"
                  : "Event monitoring"}
            </span>
          </div>
        </header>

        <section className="filter-card">
          <div
            className="section-header"
            style={{ padding: 0, marginBottom: "20px", borderBottom: "none" }}
          >
            <div>
              <h2>Filter Events</h2>
              <p>
                Narrow down events by type or IP address.
              </p>
            </div>

            <span className="btn" style={{ cursor: "default", opacity: 0.8 }}>
              {total.toLocaleString()} events
            </span>
          </div>

          <div className="filter-grid">
            <div className="filter-group">
              <label htmlFor="event-type">
                Event Type
              </label>

              <select
                id="event-type"
                className="filter-select"
                value={eventType}
                onChange={(event) =>
                  handleEventTypeChange(
                    event.target.value as EventType | "",
                  )
                }
              >
                <option value="">All event types</option>

                {EVENT_TYPES.map((type) => (
                  <option key={type} value={type}>
                    {type.replace(/_/g, " ")}
                  </option>
                ))}
              </select>
            </div>

            <div className="filter-group">
              <label htmlFor="source-ip">
                Source IP
              </label>

              <div className="filter-actions">
                <input
                  id="source-ip"
                  type="text"
                  className="filter-input"
                  placeholder="e.g. 192.168.1.10"
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
              <label htmlFor="destination-ip">
                Destination IP
              </label>

              <div className="filter-actions">
                <input
                  id="destination-ip"
                  type="text"
                  className="filter-input"
                  placeholder="e.g. 192.168.1.10"
                  value={destinationIpInput}
                  onChange={(event) =>
                    setDestinationIpInput(
                      event.target.value,
                    )
                  }
                  onKeyDown={handleDestinationIpKeyDown}
                />

                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={applyDestinationIpFilter}
                >
                  Apply
                </button>

                {destinationIp && (
                  <button
                    type="button"
                    className="btn"
                    onClick={clearDestinationIpFilter}
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
              <strong>Unable to load events</strong>
              <p style={{ margin: "4px 0 0", fontSize: "12px" }}>{error}</p>
            </div>

            <button
              type="button"
              className="btn"
              onClick={() => void loadEvents()}
              disabled={loading}
            >
              Try again
            </button>
          </div>
        )}

        {loading ? (
          <div className="state-card">
            <span className="status-dot" style={{ marginRight: "10px" }} />
            <span>Loading security events...</span>
          </div>
        ) : !error ? (
          <>
            <section className="content-card">
              <div className="section-header">
                <div>
                  <h2>Security Events</h2>
                  <p>
                    {total > 0
                      ? `Showing ${page * PAGE_SIZE + 1}–${Math.min(
                          (page + 1) * PAGE_SIZE,
                          total,
                        )} of ${total.toLocaleString()} events`
                      : "No matching events"}
                  </p>
                </div>
              </div>

              <div className="table-container">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Timestamp</th>
                      <th>Event Type</th>
                      <th>Source</th>
                      <th>Source IP</th>
                      <th>Username</th>
                      <th>Severity</th>
                    </tr>
                  </thead>

                  <tbody>
                    {events.map((event) => (
                      <tr key={event.id}>
                        <td className="text-timestamp">
                          {new Date(
                            event.timestamp,
                          ).toLocaleString()}
                        </td>

                        <td>
                          <Link
                            to={`/events/${event.id}`}
                            className="text-link"
                            style={{ fontWeight: 500 }}
                          >
                            {event.event_type.replace(
                              /_/g,
                              " ",
                            )}
                          </Link>
                        </td>

                        <td>{event.source}</td>

                        <td className="text-mono">
                          {event.source_ip ?? "—"}
                        </td>

                        <td>
                          {event.username ?? "—"}
                        </td>

                        <td>
                          <span
                            className={`badge-severity severity-${event.severity.toLowerCase()}`}
                          >
                            {event.severity.toUpperCase()}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>

                {events.length === 0 && (
                  <div className="empty-state">
                    <span className="empty-icon">⌕</span>
                    <strong>No events found</strong>
                    <p
                      style={{
                        margin: 0,
                        color: "var(--text-subtle)",
                        fontSize: "12px",
                      }}
                    >
                      Try changing your filters to see more results.
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
                      type="button"
                      disabled={page === 0}
                      onClick={() =>
                        setPage((current) => current - 1)
                      }
                    >
                      ← Previous
                    </button>

                    <button
                      type="button"
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
          </>
        ) : null}
      </div>
    </Layout>
  );
}

export default Events;