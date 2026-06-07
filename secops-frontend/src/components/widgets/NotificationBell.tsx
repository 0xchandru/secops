import React, { useEffect, useRef, useState, useCallback } from "react";
import { useQuery, useQueryClient, useMutation } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { notificationsApi, type Notification } from "@/lib/api";
import { useAuthStore } from "@/store/authStore";
import {
  Bell,
  CheckCheck,
  AlertTriangle,
  UserPlus,
  ArrowUpCircle,
  CheckCircle2,
  Shield,
  Info,
  Trash2,
  X,
} from "lucide-react";

const TYPE_CONFIG: Record<
  Notification["type"],
  { icon: React.ElementType; color: string; label: string }
> = {
  alert_created: { icon: AlertTriangle, color: "text-orange-400", label: "New Alert" },
  alert_assigned: { icon: UserPlus, color: "text-blue-400", label: "Assigned" },
  alert_escalated: { icon: ArrowUpCircle, color: "text-red-400", label: "Escalated" },
  alert_resolved: { icon: CheckCircle2, color: "text-green-400", label: "Resolved" },
  rule_match: { icon: Shield, color: "text-purple-400", label: "Rule Match" },
  system: { icon: Info, color: "text-muted-foreground", label: "System" },
};

function timeAgo(dateStr: string): string {
  const seconds = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000);
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export function NotificationBell() {
  const [open, setOpen] = useState(false);
  const panelRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const queryClient = useQueryClient();
  const { user, isAuthenticated } = useAuthStore();
  const [, navigate] = useLocation();
  const wsRef = useRef<WebSocket | null>(null);
  const wsReconnectRef = useRef<ReturnType<typeof setTimeout>>(undefined);

  // Fetch notifications
  const { data } = useQuery({
    queryKey: ["notifications"],
    queryFn: () => notificationsApi.list({ limit: 50 }).then((r) => r.data),
    refetchInterval: 60_000,
    enabled: isAuthenticated,
  });

  const notifications = data?.notifications ?? [];
  const unreadCount = data?.unreadCount ?? 0;

  // Mutations
  const markReadMut = useMutation({
    mutationFn: (id: string) => notificationsApi.markRead(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["notifications"] }),
  });

  const markAllReadMut = useMutation({
    mutationFn: () => notificationsApi.markAllRead(),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["notifications"] }),
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => notificationsApi.delete(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["notifications"] }),
  });

  // WebSocket for real-time notifications
  const connectWs = useCallback(() => {
    if (!isAuthenticated || !user?.userId) return;
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    try {
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      const ws = new WebSocket(
        `${protocol}//${window.location.host}/ws/notifications?userId=${user.userId}`
      );
      wsRef.current = ws;

      ws.onmessage = () => {
        queryClient.invalidateQueries({ queryKey: ["notifications"] });
      };

      ws.onclose = () => {
        wsRef.current = null;
        wsReconnectRef.current = setTimeout(connectWs, 8000);
      };
      ws.onerror = () => ws.close();
    } catch {
      /* noop */
    }
  }, [isAuthenticated, user?.userId, queryClient]);

  useEffect(() => {
    connectWs();
    return () => {
      if (wsReconnectRef.current) clearTimeout(wsReconnectRef.current);
      wsRef.current?.close();
    };
  }, [connectWs]);

  // Close panel on outside click
  useEffect(() => {
    if (!open) return;
    const handler = (e: MouseEvent) => {
      if (
        panelRef.current &&
        !panelRef.current.contains(e.target as Node) &&
        buttonRef.current &&
        !buttonRef.current.contains(e.target as Node)
      ) {
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [open]);

  const handleClick = (n: Notification) => {
    if (!n.read) markReadMut.mutate(n.id);
    if (n.link) {
      navigate(n.link);
      setOpen(false);
    }
  };

  return (
    <div className="relative">
      <button
        ref={buttonRef}
        onClick={() => setOpen((v) => !v)}
        className="relative p-2 rounded-full hover:bg-secondary text-muted-foreground hover:text-foreground transition-colors"
        title="Notifications"
      >
        <Bell className="w-5 h-5" />
        {unreadCount > 0 && (
          <span className="absolute top-1 right-1 min-w-[18px] h-[18px] flex items-center justify-center bg-destructive text-destructive-foreground text-[10px] font-bold rounded-full px-1 animate-pulse">
            {unreadCount > 99 ? "99+" : unreadCount}
          </span>
        )}
      </button>

      {open && (
        <div
          ref={panelRef}
          className="absolute right-0 top-12 w-96 max-h-[480px] bg-card border border-border rounded-xl shadow-2xl z-50 flex flex-col overflow-hidden animate-in fade-in slide-in-from-top-2 duration-200"
        >
          {/* Header */}
          <div className="flex items-center justify-between px-4 py-3 border-b border-border">
            <h3 className="text-sm font-semibold text-foreground">
              Notifications{" "}
              {unreadCount > 0 && (
                <span className="ml-1 text-xs text-muted-foreground">
                  ({unreadCount} unread)
                </span>
              )}
            </h3>
            <div className="flex items-center gap-1">
              {unreadCount > 0 && (
                <button
                  onClick={() => markAllReadMut.mutate()}
                  className="flex items-center gap-1 text-xs text-primary hover:text-primary/80 transition-colors px-2 py-1 rounded hover:bg-secondary"
                  title="Mark all as read"
                >
                  <CheckCheck className="w-3.5 h-3.5" />
                  Read all
                </button>
              )}
              <button
                onClick={() => setOpen(false)}
                aria-label="Close notifications"
                className="p-1 rounded hover:bg-secondary text-muted-foreground hover:text-foreground transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* List */}
          <div className="flex-1 overflow-y-auto">
            {notifications.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                <Bell className="w-8 h-8 mb-2 opacity-40" />
                <p className="text-sm">No notifications yet</p>
              </div>
            ) : (
              notifications.map((n) => {
                const cfg = TYPE_CONFIG[n.type] ?? TYPE_CONFIG.system;
                const Icon = cfg.icon;
                return (
                  <div
                    key={n.id}
                    className={`flex items-start gap-3 px-4 py-3 border-b border-border/50 cursor-pointer transition-colors hover:bg-secondary/50 ${
                      !n.read ? "bg-primary/5" : ""
                    }`}
                    onClick={() => handleClick(n)}
                  >
                    <div
                      className={`mt-0.5 w-8 h-8 rounded-full flex items-center justify-center shrink-0 ${
                        !n.read ? "bg-primary/10" : "bg-secondary"
                      }`}
                    >
                      <Icon className={`w-4 h-4 ${cfg.color}`} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span
                          className={`text-[10px] uppercase tracking-wider font-medium ${cfg.color}`}
                        >
                          {cfg.label}
                        </span>
                        {!n.read && (
                          <span className="w-1.5 h-1.5 rounded-full bg-primary shrink-0" />
                        )}
                      </div>
                      <p className="text-sm font-medium text-foreground truncate mt-0.5">
                        {n.title}
                      </p>
                      {n.message && (
                        <p className="text-xs text-muted-foreground line-clamp-2 mt-0.5">
                          {n.message}
                        </p>
                      )}
                      <p className="text-[10px] text-muted-foreground/60 mt-1">
                        {timeAgo(n.createdAt)}
                      </p>
                    </div>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        deleteMut.mutate(n.id);
                      }}
                      className="p-1 rounded hover:bg-destructive/10 text-muted-foreground/40 hover:text-destructive transition-colors opacity-0 group-hover:opacity-100"
                      title="Delete notification"
                      aria-label="Delete notification"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}
    </div>
  );
}
