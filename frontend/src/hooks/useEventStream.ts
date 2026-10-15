import { useEffect } from "react";

const API_URL =
  import.meta.env.VITE_API_URL ?? "http://localhost:8000";

const DEMO_MODE =
  import.meta.env.VITE_DEMO_MODE === "true";

export type StreamEventType =
  | "event_created"
  | "alert_created"
  | "correlation_created"
  | "incident_created";

export interface StreamEvent {
  type: StreamEventType;
  data: {
    id: number;
  };
}

type Listener = (event: StreamEvent) => void;

const listeners = new Set<Listener>();

let eventSource: EventSource | null = null;

function startEventStream() {
  if (eventSource) {
    return;
  }

  eventSource = new EventSource(`${API_URL}/stream`);

  eventSource.addEventListener(
    "event_created",
    (event) => {
      const data = JSON.parse(event.data);

      const streamEvent: StreamEvent = {
        type: "event_created",
        data,
      };

      listeners.forEach((listener) => {
        listener(streamEvent);
      });
    },
  );

  eventSource.addEventListener(
    "alert_created",
    (event) => {
      const data = JSON.parse(event.data);

      const streamEvent: StreamEvent = {
        type: "alert_created",
        data,
      };

      listeners.forEach((listener) => {
        listener(streamEvent);
      });
    },
  );

  eventSource.addEventListener(
    "correlation_created",
    (event) => {
      const data = JSON.parse(event.data);

      const streamEvent: StreamEvent = {
        type: "correlation_created",
        data,
      };

      listeners.forEach((listener) => {
        listener(streamEvent);
      });
    },
  );

  eventSource.addEventListener(
    "incident_created",
    (event) => {
      const data = JSON.parse(event.data);

      const streamEvent: StreamEvent = {
        type: "incident_created",
        data,
      };

      listeners.forEach((listener) => {
        listener(streamEvent);
      });
    },
  );

  eventSource.onerror = () => {
    /*
     * EventSource automatically attempts to reconnect.
     * We therefore do not recreate the connection here.
     */
  };
}

function subscribe(listener: Listener) {
   if (DEMO_MODE) {
    return () => {};
  }
  
  listeners.add(listener);

  startEventStream();

  return () => {
    listeners.delete(listener);

    if (listeners.size === 0) {
      eventSource?.close();
      eventSource = null;
    }
  };
}

export function useEventStream(
  listener: Listener,
) {
  useEffect(() => {
    return subscribe(listener);
  }, [listener]);
}
