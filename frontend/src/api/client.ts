
import { demoFetch } from "./demo";

const API_URL =
  import.meta.env.VITE_API_URL ?? "http://localhost:8000";

const DEMO_MODE =
  import.meta.env.VITE_DEMO_MODE === "true";

export async function apiFetch<T>(
  path: string,
  options?: RequestInit,
): Promise<T> {
  
  if (DEMO_MODE) {
    return demoFetch<T>(path, options);
  }
  

  const response = await fetch(`${API_URL}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });

  if (!response.ok) {
    throw new Error(`API request failed: ${response.status}`);
  }

  return response.json();
}
