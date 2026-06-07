import { useEffect, useRef, useCallback } from "react";
import { useQueryClient } from "@tanstack/react-query";

interface WsMessage {
  type: "new_alert" | "event" | "connected";
  data?: any;
  message?: string;
}

interface UseWebSocketOptions {
  onNewAlert?: (alert: any) => void;
}

export function useWebSocket(options: UseWebSocketOptions = {}) {
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const queryClient = useQueryClient();
  const onNewAlert = options.onNewAlert;

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;
    // Don't connect if no auth token present
    if (!localStorage.getItem("access_token")) return;

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const host = window.location.host;
    const basePath = import.meta.env.BASE_URL?.replace(/\/$/, "") ?? "";
    const url = `${protocol}//${host}${basePath}/ws/alerts`;

    try {
      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => {
        if (reconnectRef.current) clearTimeout(reconnectRef.current);
      };

      ws.onmessage = (event) => {
        try {
          const msg: WsMessage = JSON.parse(event.data);
          if (msg.type === "new_alert" && msg.data) {
            // Invalidate alert queries to refresh the list
            queryClient.invalidateQueries({ queryKey: ["alerts"] });
            queryClient.invalidateQueries({ queryKey: ["alert-count"] });
            queryClient.invalidateQueries({ queryKey: ["dashboard"] });
            onNewAlert?.(msg.data);
          }
        } catch {}
      };

      ws.onclose = () => {
        wsRef.current = null;
        reconnectRef.current = setTimeout(connect, 5000);
      };

      ws.onerror = () => {
        ws.close();
      };
    } catch {}
  }, [queryClient, onNewAlert]);

  useEffect(() => {
    connect();
    return () => {
      if (reconnectRef.current) clearTimeout(reconnectRef.current);
      wsRef.current?.close();
    };
  }, [connect]);

  return { isConnected: wsRef.current?.readyState === WebSocket.OPEN };
}
