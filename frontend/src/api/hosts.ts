import { apiFetch } from "./client";
import type {
  AlertListResponse,
  EventListResponse,
  Host,
} from "../types/siem";

interface HostEventParams {
  limit?: number;
  offset?: number;
}

interface HostAlertParams {
  limit?: number;
  offset?: number;
}

export function getHosts(): Promise<Host[]> {
  return apiFetch<Host[]>("/hosts");
}

export function getHost(hostId: string): Promise<Host> {
  return apiFetch<Host>(`/hosts/${hostId}`);
}

export function getHostEvents(
  hostId: string,
  params: HostEventParams = {},
): Promise<EventListResponse> {
  const query = new URLSearchParams();

  if (params.limit !== undefined) {
    query.set("limit", params.limit.toString());
  }

  if (params.offset !== undefined) {
    query.set("offset", params.offset.toString());
  }

  return apiFetch<EventListResponse>(
    `/hosts/${hostId}/events?${query.toString()}`,
  );
}

export function getHostAlerts(
  hostId: string,
  params: HostAlertParams = {},
): Promise<AlertListResponse> {
  const query = new URLSearchParams();

  if (params.limit !== undefined) {
    query.set("limit", params.limit.toString());
  }

  if (params.offset !== undefined) {
    query.set("offset", params.offset.toString());
  }

  return apiFetch<AlertListResponse>(
    `/hosts/${hostId}/alerts?${query.toString()}`,
  );
}
