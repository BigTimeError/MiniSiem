import { apiFetch } from "./client";

import type {
  Correlation,
  CorrelationListResponse,
} from "../types/siem";

interface CorrelationParams {
  limit?: number;
  offset?: number;
  source_ip?: string;
  affected_host?: string;
}

export function getCorrelations(
  params: CorrelationParams = {},
): Promise<CorrelationListResponse> {
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

  if (params.affected_host) {
    query.set("affected_host", params.affected_host);
  }

  return apiFetch<CorrelationListResponse>(
    `/correlations?${query.toString()}`,
  );
}

export function getCorrelation(
  correlationId: number,
): Promise<Correlation> {
  return apiFetch<Correlation>(
    `/correlations/${correlationId}`,
  );
}

export function getCorrelationsCount(): Promise<number> {
  return apiFetch<number>("/correlations/count");
}
