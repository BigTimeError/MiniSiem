
import type {
  Alert,
  Correlation,
  DashboardStats,
  Event,
  EventTimeBucket,
  Incident,
  Host,
} from "../types/siem";

/*
 * Static demo data for the GitHub Pages showcase.
 *
 * The records describe one connected SSH brute-force scenario:
 * repeated failed logins against server01, followed by an alert,
 * a correlation and an incident.
 *
 * Changes made to these records in the UI are temporary and
 * reset when the page is reloaded.
 */

const now = Date.now();

function minutesAgo(minutes: number): string {
  return new Date(now - minutes * 60_000).toISOString();
}

export const demoHosts: Host[] = [
  {
    id: "server01",
    hostname: "server01",
    ip_address: "192.168.1.10",
    events: 8,
    alerts: 2,
    status: "online",
    last_seen: minutesAgo(1),
  },
  {
    id: "server02",
    hostname: "server02",
    ip_address: "192.168.1.11",
    events: 3,
    alerts: 1,
    status: "online",
    last_seen: minutesAgo(3),
  },
  {
    id: "web01",
    hostname: "web01",
    ip_address: "192.168.1.20",
    events: 2,
    alerts: 0,
    status: "online",
    last_seen: minutesAgo(5),
  },
  {
    id: "workstation01",
    hostname: "workstation01",
    ip_address: "192.168.1.101",
    events: 1,
    alerts: 0,
    status: "offline",
    last_seen: minutesAgo(180),
  },
];

export const demoEvents: Event[] = [
  {
    id: 1,
    timestamp: minutesAgo(2),
    source: "server01",
    event_type: "invalid_user_login",
    severity: "medium",
    source_ip: "203.0.113.42",
    source_port: 51204,
    destination_ip: "192.168.1.10",
    destination_port: 22,
    username: "admin",
    service: "sshd",
    message: "Failed SSH login: invalid user admin",
    metadata: { scenario: "ssh_brute_force", attempt: 6 },
  },
  {
    id: 2,
    timestamp: minutesAgo(3),
    source: "server01",
    event_type: "authentication_failure",
    severity: "medium",
    source_ip: "203.0.113.42",
    source_port: 51198,
    destination_ip: "192.168.1.10",
    destination_port: 22,
    username: "root",
    service: "sshd",
    message: "Failed password for root over SSH",
    metadata: { scenario: "ssh_brute_force", attempt: 5 },
  },
  {
    id: 3,
    timestamp: minutesAgo(4),
    source: "server01",
    event_type: "invalid_user_login",
    severity: "medium",
    source_ip: "203.0.113.42",
    source_port: 51192,
    destination_ip: "192.168.1.10",
    destination_port: 22,
    username: "test",
    service: "sshd",
    message: "Failed SSH login: invalid user test",
    metadata: { scenario: "ssh_brute_force", attempt: 4 },
  },
  {
    id: 4,
    timestamp: minutesAgo(5),
    source: "server01",
    event_type: "authentication_failure",
    severity: "medium",
    source_ip: "203.0.113.42",
    source_port: 51186,
    destination_ip: "192.168.1.10",
    destination_port: 22,
    username: "ubuntu",
    service: "sshd",
    message: "Failed password for ubuntu over SSH",
    metadata: { scenario: "ssh_brute_force", attempt: 3 },
  },
  {
    id: 5,
    timestamp: minutesAgo(6),
    source: "server01",
    event_type: "invalid_user_login",
    severity: "low",
    source_ip: "203.0.113.42",
    source_port: 51180,
    destination_ip: "192.168.1.10",
    destination_port: 22,
    username: "oracle",
    service: "sshd",
    message: "Failed SSH login: invalid user oracle",
    metadata: { scenario: "ssh_brute_force", attempt: 2 },
  },
  {
    id: 6,
    timestamp: minutesAgo(7),
    source: "server01",
    event_type: "authentication_failure",
    severity: "low",
    source_ip: "203.0.113.42",
    source_port: 51174,
    destination_ip: "192.168.1.10",
    destination_port: 22,
    username: "guest",
    service: "sshd",
    message: "Failed password for guest over SSH",
    metadata: { scenario: "ssh_brute_force", attempt: 1 },
  },
  {
    id: 7,
    timestamp: minutesAgo(12),
    source: "server02",
    event_type: "authentication_success",
    severity: "info",
    source_ip: "192.168.1.101",
    source_port: 49200,
    destination_ip: "192.168.1.11",
    destination_port: 22,
    username: "deploy",
    service: "sshd",
    message: "Accepted publickey for deploy",
    metadata: { authentication_method: "publickey" },
  },
  {
    id: 8,
    timestamp: minutesAgo(18),
    source: "web01",
    event_type: "http_request",
    severity: "info",
    source_ip: "198.51.100.24",
    source_port: 43112,
    destination_ip: "192.168.1.20",
    destination_port: 443,
    username: null,
    service: "https",
    message: "HTTP GET /login returned 200",
    metadata: {
      method: "GET",
      path: "/login",
      status_code: 200,
    },
  },
  {
    id: 9,
    timestamp: minutesAgo(25),
    source: "server02",
    event_type: "authentication_failure",
    severity: "low",
    source_ip: "198.51.100.77",
    source_port: 48321,
    destination_ip: "192.168.1.11",
    destination_port: 22,
    username: "backup",
    service: "sshd",
    message: "Failed password for backup over SSH",
    metadata: { scenario: "isolated_failed_login" },
  },
  {
    id: 10,
    timestamp: minutesAgo(32),
    source: "web01",
    event_type: "network_connection",
    severity: "info",
    source_ip: "192.168.1.20",
    source_port: 51443,
    destination_ip: "192.168.1.10",
    destination_port: 8080,
    username: null,
    service: "tcp",
    message: "Internal connection from web01 to application service",
    metadata: { protocol: "tcp" },
  },
  {
    id: 11,
    timestamp: minutesAgo(41),
    source: "server01",
    event_type: "authentication_success",
    severity: "info",
    source_ip: "192.168.1.50",
    source_port: 50001,
    destination_ip: "192.168.1.10",
    destination_port: 22,
    username: "analyst",
    service: "sshd",
    message: "Accepted publickey for analyst",
    metadata: { authentication_method: "publickey" },
  },
  {
    id: 12,
    timestamp: minutesAgo(54),
    source: "server02",
    event_type: "process_execution",
    severity: "info",
    source_ip: null,
    source_port: null,
    destination_ip: "192.168.1.11",
    destination_port: null,
    username: "deploy",
    service: "auditd",
    message: "Process executed by deploy",
    metadata: { process: "deploy-agent" },
  },
];

export const demoAlerts: Alert[] = [
  {
    id: 101,
    timestamp: minutesAgo(2),
    rule_id: "SSH_BRUTE_FORCE",
    title: "SSH brute-force attempt detected",
    description:
      "Multiple failed SSH authentication attempts from the same source address exceeded the configured detection threshold.",
    severity: "high",
    status: "open",
    source_ip: "203.0.113.42",
    affected_host: "server01",
    mitre_technique: "T1110",
    related_events: [1, 2, 3, 4, 5, 6],
  },
  {
    id: 102,
    timestamp: minutesAgo(4),
    rule_id: "SSH_USER_ENUMERATION",
    title: "SSH user enumeration detected",
    description:
      "Repeated attempts using different usernames may indicate account discovery against the SSH service.",
    severity: "medium",
    status: "acknowledged",
    source_ip: "203.0.113.42",
    affected_host: "server01",
    mitre_technique: "T1087",
    related_events: [1, 3, 5],
  },
  {
    id: 103,
    timestamp: minutesAgo(25),
    rule_id: "SSH_AUTH_FAILURE",
    title: "Failed SSH authentication",
    description:
      "An unsuccessful SSH login was recorded. No additional related activity was detected in this example.",
    severity: "low",
    status: "resolved",
    source_ip: "198.51.100.77",
    affected_host: "server02",
    mitre_technique: "T1110",
    related_events: [9],
  },
];

export const demoCorrelations: Correlation[] = [
  {
    id: 201,
    timestamp: minutesAgo(2),
    correlation_rule_id: "MULTI_STAGE_SSH_ATTACK",
    source_ip: "203.0.113.42",
    affected_host: "server01",
    alerts: [101, 102],
  },
];

export const demoIncidents: Incident[] = [
  {
    id: 301,
    timestamp: minutesAgo(2),
    title: "SSH brute-force activity against server01",
    description:
      "Several failed SSH logins and suspicious username probes were correlated into one security incident. Review the related alerts and authentication events.",
    severity: "high",
    status: "investigating",
    source_ip: "203.0.113.42",
    affected_host: "server01",
    related_alerts: [101, 102],
    related_correlations: [201],
  },
];

export const demoDashboardStats: DashboardStats = {
  total_events: 12,
  open_alerts: demoAlerts.filter(
    (alert) => alert.status === "open",
  ).length,
  critical_alerts: demoAlerts.filter(
    (alert) =>
      alert.severity === "critical" &&
      alert.status !== "resolved",
  ).length,
};

/*
 * Buckets for the dashboard chart. Timestamps are generated relative
 * to the current time so the chart remains recent when the demo loads.
 */
export const demoEventsOverTime: EventTimeBucket[] = Array.from(
  { length: 12 },
  (_, index) => ({
    timestamp: new Date(
      now - (11 - index) * 5 * 60_000,
    ).toISOString(),
    count: [2, 1, 3, 2, 4, 1, 3, 2, 5, 4, 3, 6][index],
  }),
);

export const demoAlertsOverTime: EventTimeBucket[] = Array.from(
  { length: 12 },
  (_, index) => ({
    timestamp: new Date(
      now - (11 - index) * 5 * 60_000,
    ).toISOString(),
    count: [0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 2, 2][index],
  }),
);
