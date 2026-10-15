
import type {
  Alert,
  AlertListResponse,
  AlertStatus,
  Correlation,
  CorrelationListResponse,
  DashboardStats,
  Event,
  EventListResponse,
  Incident,
  IncidentListResponse,
  IncidentStatus,
  Host,
} from "../types/siem";

import {
  demoAlerts,
  demoCorrelations,
  demoDashboardStats,
  demoEvents,
  demoEventsOverTime,
  demoAlertsOverTime,
  demoHosts,
  demoIncidents,
} from "../mockData/demoData";

const API_ORIGIN = "http://demo.local";

let alerts: Alert[] = demoAlerts.map((alert) => ({ ...alert }));
let incidents: Incident[] = demoIncidents.map((incident) => ({
  ...incident,
}));

function getUrl(path: string): URL {
  return new URL(path, API_ORIGIN);
}

function paginate<T>(items: T[], url: URL) {
  const limit = Math.max(0, Number(url.searchParams.get("limit") ?? 100));
  const offset = Math.max(0, Number(url.searchParams.get("offset") ?? 0));

  return {
    items: items.slice(offset, offset + limit),
    total: items.length,
    limit,
    offset,
  };
}

function matchesHost(
  value: string | null,
  host: Host,
): boolean {
  return value === host.hostname || value === host.ip_address;
}

function findHost(hostId: string): Host | undefined {
  return demoHosts.find(
    (host) =>
      host.id === hostId ||
      host.hostname === hostId ||
      host.ip_address === hostId,
  );
}

function getRequestBody(options?: RequestInit): Record<string, unknown> {
  if (typeof options?.body !== "string") {
    return {};
  }

  try {
    return JSON.parse(options.body) as Record<string, unknown>;
  } catch {
    return {};
  }
}

function filterEvents(url: URL): Event[] {
  let result = [...demoEvents];

  const sourceIp = url.searchParams.get("source_ip");
  const destinationIp = url.searchParams.get("destination_ip");
  const eventType = url.searchParams.get("event_type");
  const host = url.searchParams.get("host");

  if (sourceIp) {
    result = result.filter((event) => event.source_ip === sourceIp);
  }

  if (destinationIp) {
    result = result.filter(
      (event) => event.destination_ip === destinationIp,
    );
  }

  if (eventType) {
    result = result.filter((event) => event.event_type === eventType);
  }

  if (host) {
    const matchingHost = findHost(host);

    result = result.filter((event) =>
      matchingHost
        ? event.source === matchingHost.hostname ||
          event.source_ip === matchingHost.ip_address ||
          event.destination_ip === matchingHost.ip_address
        : event.source === host ||
          event.source_ip === host ||
          event.destination_ip === host,
    );
  }

  return result;
}

function filterAlerts(url: URL): Alert[] {
  let result = [...alerts];

  const status = url.searchParams.get("status");
  const severity = url.searchParams.get("severity");
  const host = url.searchParams.get("affected_host");

  if (status) {
    result = result.filter((alert) => alert.status === status);
  }

  if (severity) {
    result = result.filter((alert) => alert.severity === severity);
  }

  if (host) {
    result = result.filter(
      (alert) =>
        alert.affected_host === host || alert.source_ip === host,
    );
  }

  return result;
}

function filterCorrelations(url: URL): Correlation[] {
  let result = [...demoCorrelations];

  const sourceIp = url.searchParams.get("source_ip");
  const host = url.searchParams.get("affected_host");

  if (sourceIp) {
    result = result.filter(
      (correlation) => correlation.source_ip === sourceIp,
    );
  }

  if (host) {
    result = result.filter(
      (correlation) =>
        correlation.affected_host === host ||
        correlation.source_ip === host,
    );
  }

  return result;
}

function filterIncidents(url: URL): Incident[] {
  let result = [...incidents];

  const status = url.searchParams.get("status");
  const severity = url.searchParams.get("severity");
  const host = url.searchParams.get("affected_host");

  if (status) {
    result = result.filter((incident) => incident.status === status);
  }

  if (severity) {
    result = result.filter((incident) => incident.severity === severity);
  }

  if (host) {
    result = result.filter(
      (incident) =>
        incident.affected_host === host || incident.source_ip === host,
    );
  }

  return result;
}

function findAlert(id: number): Alert | undefined {
  return alerts.find((alert) => alert.id === id);
}

function findIncident(id: number): Incident | undefined {
  return incidents.find((incident) => incident.id === id);
}

function notFound(resource: string): never {
  throw new Error(`Demo API: ${resource} not found`);
}

export async function demoFetch<T>(
  path: string,
  options?: RequestInit,
): Promise<T> {
  const url = getUrl(path);
  const pathname = url.pathname.replace(/\/+$/, "") || "/";
  const method = options?.method?.toUpperCase() ?? "GET";

  // Dashboard
  if (method === "GET" && pathname === "/dashboard/stats") {
    const stats: DashboardStats = {
      ...demoDashboardStats,
      open_alerts: alerts.filter((alert) => alert.status === "open").length,
      critical_alerts: alerts.filter(
        (alert) =>
          alert.severity === "critical" && alert.status === "open",
      ).length,
    };

    return stats as T;
  }

  if (
    method === "GET" &&
    pathname === "/dashboard/events-over-time"
  ) {
    const interval = url.searchParams.get("interval");

  if (interval === "day") {
    return demoEventsOverTime.slice(-7) as T;
  }

  if (interval === "week") {
    return demoEventsOverTime.slice(-4) as T;
  }

    return demoEventsOverTime as T;
  }

  if (
    method === "GET" &&
    pathname === "/dashboard/alerts-over-time"
  ) {
    const interval = url.searchParams.get("interval");

  if (interval === "day") {
    return demoAlertsOverTime.slice(-7) as T;
  }

  if (interval === "week") {
    return demoAlertsOverTime.slice(-4) as T;
  }

    return demoAlertsOverTime as T;
  }

  // Events
  if (method === "GET" && pathname === "/events") {
    const response: EventListResponse = paginate(filterEvents(url), url);
    return response as T;
  }

  const eventMatch = pathname.match(/^\/events\/(\d+)$/);

  if (method === "GET" && eventMatch) {
    const event = demoEvents.find(
      (item) => item.id === Number(eventMatch[1]),
    );

    if (!event) {
      return notFound(`Event ${eventMatch[1]}`);
    }

    return event as T;
  }

  // Alerts
  if (method === "GET" && pathname === "/alerts") {
    const response: AlertListResponse = paginate(filterAlerts(url), url);
    return response as T;
  }

  const alertStatusMatch = pathname.match(
    /^\/alerts\/(\d+)\/status$/,
  );

  if (method === "PATCH" && alertStatusMatch) {
    const alert = findAlert(Number(alertStatusMatch[1]));

    if (!alert) {
      return notFound(`Alert ${alertStatusMatch[1]}`);
    }

    const body = getRequestBody(options);
    const status = body.status;

    const validStatuses: AlertStatus[] = [
      "open",
      "acknowledged",
      "resolved",
      "false_positive",
    ];

    if (
      typeof status !== "string" ||
      !validStatuses.includes(status as AlertStatus)
    ) {
      throw new Error("Demo API: invalid alert status");
    }

    alert.status = status as AlertStatus;
    return alert as T;
  }

  const alertMatch = pathname.match(/^\/alerts\/(\d+)$/);

  if (method === "GET" && alertMatch) {
    const alert = findAlert(Number(alertMatch[1]));

    if (!alert) {
      return notFound(`Alert ${alertMatch[1]}`);
    }

    return alert as T;
  }

  // Correlations
  if (method === "GET" && pathname === "/correlations/count") {
    return { count: filterCorrelations(url).length } as T;
  }

  if (method === "GET" && pathname === "/correlations") {
    const response: CorrelationListResponse = paginate(
      filterCorrelations(url),
      url,
    );

    return response as T;
  }

  const correlationMatch = pathname.match(/^\/correlations\/(\d+)$/);

  if (method === "GET" && correlationMatch) {
    const correlation = demoCorrelations.find(
      (item) => item.id === Number(correlationMatch[1]),
    );

    if (!correlation) {
      return notFound(`Correlation ${correlationMatch[1]}`);
    }

    return correlation as T;
  }

  // Incidents
  if (method === "GET" && pathname === "/incidents") {
    const response: IncidentListResponse = paginate(
      filterIncidents(url),
      url,
    );

    return response as T;
  }

  const incidentStatusMatch = pathname.match(
    /^\/incidents\/(\d+)\/status$/,
  );

  if (method === "PATCH" && incidentStatusMatch) {
    const incident = findIncident(Number(incidentStatusMatch[1]));

    if (!incident) {
      return notFound(`Incident ${incidentStatusMatch[1]}`);
    }

    const body = getRequestBody(options);
    const status = body.status;

    const validStatuses: IncidentStatus[] = [
      "open",
      "investigating",
      "resolved",
      "closed",
      "false_positive",
    ];

    if (
      typeof status !== "string" ||
      !validStatuses.includes(status as IncidentStatus)
    ) {
      throw new Error("Demo API: invalid incident status");
    }

    incident.status = status as IncidentStatus;
    return incident as T;
  }

  const incidentMatch = pathname.match(/^\/incidents\/(\d+)$/);

  if (method === "GET" && incidentMatch) {
    const incident = findIncident(Number(incidentMatch[1]));

    if (!incident) {
      return notFound(`Incident ${incidentMatch[1]}`);
    }

    return incident as T;
  }

  // Hosts
  if (method === "GET" && pathname === "/hosts") {
    return demoHosts as T;
  }

  const hostEventsMatch = pathname.match(
    /^\/hosts\/([^/]+)\/events$/,
  );

  if (method === "GET" && hostEventsMatch) {
    const host = findHost(decodeURIComponent(hostEventsMatch[1]));

    if (!host) {
      return notFound(`Host ${hostEventsMatch[1]}`);
    }

    const events = demoEvents.filter(
      (event) =>
        event.source === host.hostname ||
        event.source_ip === host.ip_address ||
        event.destination_ip === host.ip_address,
    );

    return paginate(events, url) as T;
  }

  const hostAlertsMatch = pathname.match(
    /^\/hosts\/([^/]+)\/alerts$/,
  );

  if (method === "GET" && hostAlertsMatch) {
    const host = findHost(decodeURIComponent(hostAlertsMatch[1]));

    if (!host) {
      return notFound(`Host ${hostAlertsMatch[1]}`);
    }

    const hostAlerts = alerts.filter((alert) =>
      matchesHost(alert.affected_host, host),
    );

    return paginate(hostAlerts, url) as T;
  }

  const hostMatch = pathname.match(/^\/hosts\/([^/]+)$/);

  if (method === "GET" && hostMatch) {
    const host = findHost(decodeURIComponent(hostMatch[1]));

    if (!host) {
      return notFound(`Host ${hostMatch[1]}`);
    }

    return host as T;
  }

  throw new Error(`Demo API: unsupported request ${method} ${pathname}`);
}
