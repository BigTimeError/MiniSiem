import { apiFetch } from "./client";

import type {
  Event,
  EventListResponse,
  EventType,
} from "../types/siem";

interface EventParams {
  limit?: number;
  offset?: number;
  source_ip?: string;
  destination_ip?: string;
  event_type?: EventType;
}

export function getEvents(
  params: EventParams = {},
): Promise<EventListResponse> {
  const query = new URLSearchParams();

  if (params.limit !== undefined) {
    query.set("limit", params.limit.toString());
  }

  if (params.offset !== undefined) {
    query.set("offset", params.offset.toString());
  }

  if (params.source_ip) {
    query.set("source_ip", params.source_ip);
  }

  if (params.destination_ip) {
    query.set("destination_ip", params.destination_ip);
  }

  if (params.event_type) {
    query.set("event_type", params.event_type);
  }

  return apiFetch<EventListResponse>(
    `/events?${query.toString()}`,
  );
}

export function getEvent(
  eventId: number,
): Promise<Event> {
  return apiFetch<Event>(`/events/${eventId}`);
}

