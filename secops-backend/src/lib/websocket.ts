import { WebSocketServer, WebSocket } from "ws";
import type { IncomingMessage } from "http";
import type { Server } from "http";
import { publish, getSubscriber } from "./redis";

let wss: WebSocketServer | null = null;
const alertClients = new Set<WebSocket>();
const eventClients = new Set<WebSocket>();
const notificationClients = new Map<string, Set<WebSocket>>(); // userId -> clients

export function initWebSocket(server: Server): void {
  wss = new WebSocketServer({ noServer: true });

  server.on("upgrade", (req: IncomingMessage, socket, head) => {
    const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
    const path = url.pathname;

    if (path === "/ws/alerts") {
      wss!.handleUpgrade(req, socket, head, (ws) => {
        setupClient(ws, alertClients, "alerts");
      });
    } else if (path === "/ws/events/live") {
      wss!.handleUpgrade(req, socket, head, (ws) => {
        setupClient(ws, eventClients, "events");
      });
    } else if (path === "/ws/notifications") {
      const userId = url.searchParams.get("userId");
      if (!userId) { socket.destroy(); return; }
      wss!.handleUpgrade(req, socket, head, (ws) => {
        if (!notificationClients.has(userId)) notificationClients.set(userId, new Set());
        notificationClients.get(userId)!.add(ws);
        ws.send(JSON.stringify({ type: "connected", channel: "notifications" }));
        ws.on("close", () => { notificationClients.get(userId)?.delete(ws); });
        ws.on("error", () => { notificationClients.get(userId)?.delete(ws); });
        ws.on("pong", () => { (ws as any).isAlive = true; });
        (ws as any).isAlive = true;
      });
    } else {
      socket.destroy();
    }
  });

  // Heartbeat ping to detect dead connections
  const interval = setInterval(() => {
    for (const clientSet of [alertClients, eventClients]) {
      clientSet.forEach((ws) => {
        if ((ws as any).isAlive === false) {
          clientSet.delete(ws);
          ws.terminate();
          return;
        }
        (ws as any).isAlive = false;
        ws.ping();
      });
    }
    // Heartbeat for notification clients
    notificationClients.forEach((clients) => {
      clients.forEach((ws) => {
        if ((ws as any).isAlive === false) {
          clients.delete(ws);
          ws.terminate();
          return;
        }
        (ws as any).isAlive = false;
        ws.ping();
      });
    });
  }, 30_000);

  wss.on("close", () => clearInterval(interval));

  // Subscribe to Redis pub/sub for cross-process delivery
  initRedisSub();
}

function setupClient(ws: WebSocket, clientSet: Set<WebSocket>, channel: string): void {
  clientSet.add(ws);
  ws.send(JSON.stringify({ type: "connected", channel, message: `WebSocket connected to ${channel} feed` }));

  ws.on("close", () => clientSet.delete(ws));
  ws.on("error", () => clientSet.delete(ws));

  ws.on("pong", () => { (ws as any).isAlive = true; });
  (ws as any).isAlive = true;
}

function initRedisSub(): void {
  try {
    const sub = getSubscriber();
    if (!sub) return;

    sub.subscribe("secops:alerts", "secops:events").catch(() => {});

    sub.on("message", (channel: string, message: string) => {
      if (channel === "secops:alerts") {
        sendToClients(alertClients, message);
      } else if (channel === "secops:events") {
        sendToClients(eventClients, message);
      }
    });
  } catch {
    // Redis not available, local-only WebSocket
  }
}

function sendToClients(clients: Set<WebSocket>, payload: string): void {
  clients.forEach((ws) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(payload);
    }
  });
}

export function broadcastAlert(alert: Record<string, any>): void {
  const payload = JSON.stringify({ type: "new_alert", data: alert });

  // Send to local clients
  sendToClients(alertClients, payload);

  // Publish to Redis for other processes
  publish("secops:alerts", { type: "new_alert", data: alert }).catch(() => {});
}

export function broadcastEvent(event: Record<string, any>): void {
  const payload = JSON.stringify({ type: "event", data: event });

  // Send to local event stream clients
  sendToClients(eventClients, payload);

  // Publish to Redis
  publish("secops:events", { type: "event", data: event }).catch(() => {});
}

export function getConnectedCount(): number {
  return alertClients.size + eventClients.size;
}

export function broadcastNotification(userId: string, notification: Record<string, any>): void {
  const payload = JSON.stringify({ type: "notification", data: notification });
  const clients = notificationClients.get(userId);
  if (clients) {
    sendToClients(clients, payload);
  }
  publish("secops:notifications", { type: "notification", userId, data: notification }).catch(() => {});
}
