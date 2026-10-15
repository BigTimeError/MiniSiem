import { apiFetch } from "./client";

import type {
  Alert,
  AlertListResponse,
  AlertStatus,
  Severity,
} from "../types/siem";

interface AlertParams {
  limit?: number;
  offset?: number;
  status?: AlertStatus;
  severity?: Severity;
  affected_host?: string;
}

export function getAlerts(
  params: AlertParams = {},
): Promise<AlertListResponse> {
  const query = new URLSearchParams();

  if (params.limit !== undefined) {
    query.set("limit", params.limit.toString());
  }

  if (params.offset !== undefined) {
    query.set("offset", params.offset.toString());
  }

  if (params.status) {
    query.set("status", params.status);
  }

  if (params.severity) {
    query.set("severity", params.severity);
  }

  if (params.affected_host) {
    query.set("affected_host", params.affected_host);
  }

  return apiFetch<AlertListResponse>(
    `/alerts?${query.toString()}`,
  );
}

export function getAlert(
  alertId: number,
): Promise<Alert> {
  return apiFetch<Alert>(`/alerts/${alertId}`);
}

export function updateAlertStatus(
  alertId: number,
  status: AlertStatus,
): Promise<Alert> {
  return apiFetch<Alert>(
    `/alerts/${alertId}/status`,
    {
      method: "PATCH",
      body: JSON.stringify({ status }),
    },
  );
}
