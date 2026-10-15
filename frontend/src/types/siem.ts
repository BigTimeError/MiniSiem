export type Severity =
  | "info"
  | "low"
  | "medium"
  | "high"
  | "critical";

export type EventType =
  | "authentication_failure"
  | "authentication_success"
  | "invalid_user_login"
  | "network_connection"
  | "process_execution"
  | "http_request";

export type AlertStatus =
  | "open"
  | "acknowledged"
  | "resolved"
  | "false_positive";

export type TimeInterval =
  | "hour"
  | "day"
  | "week";

export interface Event {
  id: number | null;
  timestamp: string;
  source: string;
  event_type: EventType;
  severity: Severity;
  source_ip: string | null;
  source_port: number | null;
  destination_ip: string | null;
  destination_port: number | null;
  username: string | null;
  service: string | null;
  message: string | null;
  metadata: Record<string, unknown>;
}

export interface Alert {
  id: number | null;
  timestamp: string;
  rule_id: string;
  title: string;
  description: string;
  severity: Severity;
  status: AlertStatus;
  source_ip: string | null;
  affected_host: string | null;
  mitre_technique: string | null;
  related_events: number[];
}

export interface Correlation {
  id: number | null;
  timestamp: string;
  correlation_rule_id: string;
  source_ip: string | null;
  affected_host: string | null;
  alerts: number[];
}

export interface CorrelationListResponse {
  items: Correlation[];
  total: number;
  limit: number;
  offset: number;
}

export interface EventListResponse {
  items: Event[];
  total: number;
  limit: number;
  offset: number;
}

export interface AlertListResponse {
  items: Alert[];
  total: number;
  limit: number;
  offset: number;
}

export interface DashboardStats {
  total_events: number;
  open_alerts: number;
  critical_alerts: number;
}

export interface EventTimeBucket {
  timestamp: string;
  count: number;
}

export type IncidentStatus =
  | "open"
  | "investigating"
  | "resolved"
  | "closed"
  | "false_positive";

export interface Incident {
  id: number | null;
  timestamp: string;
  title: string;
  description: string;
  severity: Severity;
  status: IncidentStatus;
  source_ip: string | null;
  affected_host: string | null;
  related_alerts: number[];
  related_correlations: number[];
}

export interface IncidentListResponse {
  items: Incident[];
  total: number;
  limit: number;
  offset: number;
}

export interface Host {
  id: string;
  hostname: string;
  ip_address: string;
  events: number;
  alerts: number;
  status: "online" | "offline" | "unknown";
  last_seen: string;
}