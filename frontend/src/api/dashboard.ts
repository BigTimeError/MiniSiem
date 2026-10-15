import { apiFetch } from "./client";
import type {
  DashboardStats,
  EventTimeBucket,
  TimeInterval,
} from "../types/siem";

export function getDashboardStats(): Promise<DashboardStats> {
  return apiFetch<DashboardStats>("/dashboard/stats");
}

interface EventOverTimeParams {
  interval?: TimeInterval;
}

export function getEventsOverTime(
  params: EventOverTimeParams = {},
): Promise<EventTimeBucket[]> {
  const query = new URLSearchParams();

  if (params.interval !== undefined) {
    query.set("interval", params.interval);
  }

  return apiFetch<EventTimeBucket[]>(
    `/dashboard/events-over-time?${query.toString()}`,
  );
}

export function getAlertsOverTime(
  params: EventOverTimeParams = {},
): Promise<EventTimeBucket[]> {
  const query = new URLSearchParams();

  if (params.interval !== undefined) {
    query.set("interval", params.interval);
  }

  return apiFetch<EventTimeBucket[]>(
    `/dashboard/alerts-over-time?${query.toString()}`,
  );
}