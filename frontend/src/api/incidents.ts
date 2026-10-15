import type {
  Incident,
  IncidentListResponse,
  IncidentStatus,
  Severity,
} from "../types/siem";
import { apiFetch } from "./client";

export interface GetIncidentsParams {
  limit?: number;
  offset?: number;
  status?: IncidentStatus;
  severity?: Severity;
  affected_host?: string;
}

export async function getIncidents(
  params: GetIncidentsParams = {},
): Promise<IncidentListResponse> {
  const searchParams =
    new URLSearchParams();

  if (params.limit !== undefined) {
    searchParams.set(
      "limit",
      params.limit.toString(),
    );
  }

  if (params.offset !== undefined) {
    searchParams.set(
      "offset",
      params.offset.toString(),
    );
  }

  if (params.status) {
    searchParams.set(
      "status",
      params.status,
    );
  }

  if (params.severity) {
    searchParams.set(
      "severity",
      params.severity,
    );
  }

  if (params.affected_host) {
    searchParams.set(
      "affected_host",
      params.affected_host,
    );
  }

  return apiFetch<IncidentListResponse>(
      `/incidents?${searchParams.toString()}`,
  );
}


export async function getIncidentById(
  incidentId: number,
): Promise<Incident> {
  return apiFetch<Incident>(
      `/incidents/${incidentId}`,
  );
}

export async function updateIncidentStatus(
  incidentId: number,
  status: IncidentStatus,
): Promise<Incident> {
  return apiFetch<Incident>(
      `/incidents/${incidentId}/status`,
      {
        method: "PATCH",
        body: JSON.stringify({ status }),
      },
    );
}