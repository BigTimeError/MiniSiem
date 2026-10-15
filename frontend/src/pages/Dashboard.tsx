import { useCallback, useEffect, useState } from "react";

import Layout from "../components/Layout";
import StatCard from "../components/StatCard";
import EventsOverTimeChart from "../components/EventsOverTimeChart";
import SeverityDistribution from "../components/SeverityDistribution";
import RecentAlerts from "../components/RecentAlerts";
import RecentCorrelations from "../components/RecentCorrelations";
import RecentIncidents from "../components/RecentIncidents";

import {
  getDashboardStats,
  getEventsOverTime,
  getAlertsOverTime,
} from "../api/dashboard";

import { getCorrelations } from "../api/correlations";
import { getIncidents } from "../api/incidents";
import { getAlerts } from "../api/alerts";
import { getEvents } from "../api/events";
import { getHosts } from "../api/hosts";

import type {
  DashboardStats,
  EventTimeBucket,
  Alert,
  TimeInterval,
  Correlation,
  Incident,
  Event,
  Host,
} from "../types/siem";

function Dashboard() {
  const [stats, setStats] =
    useState<DashboardStats | null>(null);

  const [eventsOverTime, setEventsOverTime] =
    useState<EventTimeBucket[]>([]);

  const [alertsOverTime, setAlertsOverTime] =
    useState<EventTimeBucket[]>([]);

  const [events, setEvents] =
    useState<Event[]>([]);

  const [hosts, setHosts] =
    useState<Host[]>([]);

  const [recentAlerts, setRecentAlerts] =
    useState<Alert[]>([]);

  const [correlations, setRecentCorrelations] =
    useState<Correlation[]>([]);

  const [incidents, setRecentIncidents] =
    useState<Incident[]>([]);

  const [interval, setInterval] =
    useState<TimeInterval>("hour");

  const [loading, setLoading] =
    useState(true);

  const [refreshing, setRefreshing] =
    useState(false);

  const [error, setError] =
    useState<string | null>(null);

  const [lastUpdated, setLastUpdated] =
    useState<Date | null>(null);

  const loadDashboard = useCallback(
    async (showLoading: boolean = false) => {
      if (showLoading) {
        setLoading(true);
      } else {
        setRefreshing(true);
      }

      setError(null);

      try {
        const [
          statsData,
          alertsData,
          eventsData,
          alertsOverTimeData,
          correlationsData,
          incidentsData,
          allEventsData,
          hostsData,
        ] = await Promise.all([
          getDashboardStats(),
          getAlerts({
            limit: 5,
            offset: 0,
          }),
          getEventsOverTime({
            interval,
          }),
          getAlertsOverTime({
            interval,
          }),
          getCorrelations({
            limit: 5,
            offset: 0,
          }),
          getIncidents({
            limit: 5,
            offset: 0,
          }),
          getEvents({
            limit: 100,
            offset: 0,
          }),
          getHosts(),
        ]);

        setStats(statsData);
        setRecentAlerts(alertsData.items);
        setEventsOverTime(eventsData);
        setAlertsOverTime(alertsOverTimeData);
        setRecentCorrelations(correlationsData.items);
        setRecentIncidents(incidentsData.items);
        setEvents(allEventsData.items);
        setHosts(hostsData);

        setLastUpdated(new Date());
      } catch (error) {
        setError(
          error instanceof Error
            ? error.message
            : "Unable to load dashboard data.",
        );
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    [interval],
  );

  useEffect(() => {
    void loadDashboard(true);
  }, [loadDashboard]);

  const chartData = Array.from(
    new Set([
      ...eventsOverTime.map(
        (bucket) => bucket.timestamp,
      ),
      ...alertsOverTime.map(
        (bucket) => bucket.timestamp,
      ),
    ]),
  )
    .sort()
    .map((timestamp) => {
      const eventBucket = eventsOverTime.find(
        (bucket) => bucket.timestamp === timestamp,
      );

      const alertBucket = alertsOverTime.find(
        (bucket) => bucket.timestamp === timestamp,
      );

      return {
        timestamp,
        events: eventBucket?.count ?? 0,
        alerts: alertBucket?.count ?? 0,
      };
    });

  const formattedLastUpdated = lastUpdated
    ? lastUpdated.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      })
    : null;

  return (
    <Layout>
      <div className="page">
        <header className="page-header">
          <div>
            <span
              style={{
                display: "block",
                color: "var(--accent-blue-light)",
                fontSize: "10px",
                fontWeight: 700,
                letterSpacing: "0.08em",
                textTransform: "uppercase",
                marginBottom: "4px",
              }}
            >
              SECURITY OPERATIONS CENTER
            </span>

            <h1>Dashboard</h1>

            <p>
              Monitor security events, threats and
              detection activity.
            </p>
          </div>

          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "12px",
              flexWrap: "wrap",
            }}
          >
            <div className="page-live-status">
              <span className="status-dot" />

              <span>
                {error
                  ? "Data unavailable"
                  : loading
                    ? "Loading data"
                    : "Monitoring active"}
              </span>
            </div>

            <button
              type="button"
              className="btn btn-primary"
              onClick={() => void loadDashboard()}
              disabled={loading || refreshing}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: "6px",
              }}
            >
              <span
                style={{
                  display: "inline-block",
                  transition: "transform 0.5s ease",
                  transform: refreshing ? "rotate(360deg)" : "none",
                }}
              >
                ↻
              </span>

              {refreshing ? "Refreshing..." : "Refresh"}
            </button>
          </div>
        </header>

        <div className="dashboard-meta">
          <span
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "8px",
              fontSize: "12px",
              fontWeight: 600,
              color: "var(--text-secondary)",
            }}
          >
            <span className="status-dot" style={{ width: "6px", height: "6px" }} />
            Security overview
          </span>

          <span style={{ fontSize: "12px", color: "var(--text-subtle)" }}>
            {formattedLastUpdated
              ? `Last updated at ${formattedLastUpdated}`
              : "Waiting for first update"}
          </span>
        </div>

        {error && (
          <div className="error-state" role="alert">
            <div>
              <strong>Unable to load dashboard data</strong>
              <p style={{ margin: "4px 0 0", fontSize: "12px" }}>{error}</p>
            </div>

            <button
              type="button"
              className="btn"
              onClick={() => void loadDashboard()}
              disabled={refreshing}
            >
              Try again
            </button>
          </div>
        )}

        {loading && !stats ? (
          <div className="state-card">
            <span className="status-dot" style={{ marginRight: "10px" }} />
            Loading dashboard data...
          </div>
        ) : (
          <>
            {stats && (
              <section className="dashboard-stats">
                <StatCard
                  label="Total Events"
                  value={stats.total_events}
                />

                <StatCard
                  label="Open Alerts"
                  value={stats.open_alerts}
                />

                <StatCard
                  label="Critical Alerts"
                  value={stats.critical_alerts}
                />

                <StatCard
                  label="Monitored Hosts"
                  value={hosts.length}
                />
              </section>
            )}

            <section className="dashboard-analytics-grid">
              <EventsOverTimeChart
                data={chartData}
                interval={interval}
                onIntervalChange={setInterval}
              />

              <SeverityDistribution events={events} />
            </section>

            <section className="dashboard-activity-grid">
              <RecentCorrelations
                correlations={correlations}
              />

              <RecentIncidents
                incidents={incidents}
              />
            </section>

            <section style={{ marginTop: "1.25rem" }}>
              <RecentAlerts alerts={recentAlerts} />
            </section>
          </>
        )}
      </div>
    </Layout>
  );
}

export default Dashboard;