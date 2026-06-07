import { useEffect, useRef, useCallback, useState } from "react";

interface EventStreamMessage {
  type: "event" | "connected";
  data?: any;
  message?: string;
}

interface UseEventStreamOptions {
  enabled?: boolean;
  maxEvents?: number;
  onEvent?: (event: any) => void;
}

export function useEventStream(options: UseEventStreamOptions = {}) {
  const { enabled = true, maxEvents = 200, onEvent } = options;
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [events, setEvents] = useState<any[]>([]);
  const [isConnected, setIsConnected] = useState(false);

  const connect = useCallback(() => {
    if (!enabled) return;
    // Don't connect if no auth token present
    if (!localStorage.getItem("access_token")) return;
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const host = window.location.host;
    const basePath = import.meta.env.BASE_URL?.replace(/\/$/, "") ?? "";
    const url = `${protocol}//${host}${basePath}/ws/events/live`;

    try {
      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => {
        setIsConnected(true);
        if (reconnectRef.current) clearTimeout(reconnectRef.current);
      };

      ws.onmessage = (msg) => {
        try {
          const parsed: EventStreamMessage = JSON.parse(msg.data);
          if (parsed.type === "event" && parsed.data) {
            setEvents((prev) => {
              const next = [parsed.data, ...prev];
              return next.length > maxEvents ? next.slice(0, maxEvents) : next;
            });
            onEvent?.(parsed.data);
          }
        } catch {}
      };

      ws.onclose = () => {
        wsRef.current = null;
        setIsConnected(false);
        reconnectRef.current = setTimeout(connect, 5000);
      };

      ws.onerror = () => ws.close();
    } catch {}
  }, [enabled, maxEvents, onEvent]);

  useEffect(() => {
    connect();
    return () => {
      if (reconnectRef.current) clearTimeout(reconnectRef.current);
      wsRef.current?.close();
    };
  }, [connect]);

  const clear = useCallback(() => setEvents([]), []);

  return { events, isConnected, clear };
}
