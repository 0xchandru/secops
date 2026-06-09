import React, { useEffect, useRef, useState, useCallback } from 'react';
import { Link, useLocation } from 'wouter';
import { useAppStore } from '@/store';
import { useAuthStore } from '@/store/authStore';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { alertsApi } from '@/lib/api';
import { 
  LayoutDashboard, Terminal, AlertTriangle, Shield, 
  Target, Database, Settings, Bell, Users, ClipboardList,
  LogOut, Server, Wifi, WifiOff, ChevronRight
} from 'lucide-react';
import { ROLE_LABELS, ROLE_COLORS } from '@/lib/constants';
import { NotificationBell } from '@/components/widgets/NotificationBell';

const NAV_ITEMS = [
  { href: '/', icon: LayoutDashboard, label: 'Dashboard', permission: 'reports:view' as const },
  { href: '/logs', icon: Terminal, label: 'Log Explorer', permission: 'alerts:view' as const },
  { href: '/alerts', icon: AlertTriangle, label: 'Alert Queue', badge: true, permission: 'alerts:view' as const },
  { href: '/assets', icon: Server, label: 'Asset Inventory', permission: 'alerts:view' as const },
  { href: '/rules', icon: Shield, label: 'Detection Rules', permission: 'rules:view' as const },
  { href: '/mitre', icon: Target, label: 'MITRE ATT&CK', permission: 'reports:view' as const },
  { href: '/ingestion', icon: Database, label: 'Log Ingestion', permission: 'ingest:write' as const },
];

const ADMIN_NAV = [
  { href: '/users', icon: Users, label: 'Users', permission: 'users:manage' as const },
  { href: '/audit', icon: ClipboardList, label: 'Audit Logs', permission: 'audit:view' as const },
  { href: '/settings', icon: Settings, label: 'Settings', permission: 'reports:view' as const },
];

function NavItem({ href, icon: Icon, label, active, badge, badgeCount }: {
  href: string; icon: React.ElementType; label: string; active: boolean;
  badge?: boolean; badgeCount?: number;
}) {
  const [showTooltip, setShowTooltip] = useState(false);

  return (
    <div className="relative group" onMouseEnter={() => setShowTooltip(true)} onMouseLeave={() => setShowTooltip(false)}>
      <Link
        href={href}
        className={`
          relative flex items-center justify-center w-10 h-10 rounded-lg mx-auto transition-all duration-150
          ${active
            ? 'bg-primary/15 text-primary'
            : 'text-muted-foreground hover:bg-secondary hover:text-foreground'
          }
        `}
      >
        {active && (
          <span className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-5 bg-primary rounded-r-full -ml-2" />
        )}
        <Icon className="w-5 h-5" />
        {badge && badgeCount && badgeCount > 0 && (
          <span className="absolute top-1 right-1 w-2 h-2 bg-destructive rounded-full" />
        )}
      </Link>
      {showTooltip && (
        <div className="absolute left-full ml-3 top-1/2 -translate-y-1/2 z-50 pointer-events-none">
          <div className="bg-popover border border-border text-popover-foreground text-xs font-medium px-2.5 py-1.5 rounded-lg shadow-lg whitespace-nowrap flex items-center gap-2">
            {label}
            {badge && badgeCount && badgeCount > 0 && (
              <span className="bg-destructive text-destructive-foreground text-xs font-bold px-1.5 py-0.5 rounded-full leading-none">
                {badgeCount}
              </span>
            )}
          </div>
          <div className="absolute right-full top-1/2 -translate-y-1/2 mr-[-1px] border-4 border-transparent border-r-border" />
        </div>
      )}
    </div>
  );
}

export function MainLayout({ children }: { children: React.ReactNode }) {
  const [location] = useLocation();
  const { can, user, logout, isAuthenticated } = useAuthStore();
  const queryClient = useQueryClient();
  const [wsConnected, setWsConnected] = useState(false);
  const [wsAlertToast, setWsAlertToast] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const wsReconnectRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const { data: newAlertsCount = 0 } = useQuery({
    queryKey: ['alerts-count', 'new'],
    queryFn: () => alertsApi.list({ status: 'new', limit: 1, page: 1 }).then(r => r.data.total),
    refetchInterval: 30_000,
    enabled: isAuthenticated,
  });

  const connectWs = useCallback(() => {
    if (!isAuthenticated || wsRef.current?.readyState === WebSocket.OPEN) return;
    try {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const ws = new WebSocket(`${protocol}//${window.location.host}/ws/alerts`);
      wsRef.current = ws;
      ws.onopen = () => { setWsConnected(true); if (wsReconnectRef.current) clearTimeout(wsReconnectRef.current); };
      ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data);
          if (msg.type === 'new_alert' && msg.data) {
            queryClient.invalidateQueries({ queryKey: ['alerts'] });
            queryClient.invalidateQueries({ queryKey: ['alerts-count'] });
            queryClient.invalidateQueries({ queryKey: ['dashboard'] });
            const title = msg.data.title ?? 'New Alert';
            setWsAlertToast(title);
            setTimeout(() => setWsAlertToast(null), 5000);
          }
        } catch {}
      };
      ws.onclose = () => { setWsConnected(false); wsRef.current = null; wsReconnectRef.current = setTimeout(connectWs, 6000); };
      ws.onerror = () => ws.close();
    } catch {}
  }, [isAuthenticated, queryClient]);

  useEffect(() => {
    connectWs();
    return () => {
      if (wsReconnectRef.current) clearTimeout(wsReconnectRef.current);
      wsRef.current?.close();
    };
  }, [connectWs]);

  const displayName = user?.displayName ?? user?.username ?? 'User';
  const initials = displayName.split(' ').map((p: string) => p[0]).join('').slice(0, 2).toUpperCase();

  return (
    <div className="flex h-screen overflow-hidden bg-background text-foreground">
      {/* Splunk-style compact icon rail */}
      <aside className="w-14 shrink-0 border-r border-border bg-sidebar flex flex-col items-center py-0 z-20">
        {/* Logo */}
        <div className="h-14 flex items-center justify-center border-b border-border w-full shrink-0">
          <div className="w-8 h-8 rounded-lg bg-primary/20 border border-primary/30 flex items-center justify-center">
            <Shield className="w-4 h-4 text-primary" />
          </div>
        </div>

        {/* Primary nav */}
        <nav className="flex-1 flex flex-col gap-1 py-3 w-full px-2 overflow-y-auto">
          {NAV_ITEMS.filter(item => can(item.permission)).map((item) => {
            const active = location === item.href || (item.href !== '/' && location.startsWith(item.href));
            return (
              <NavItem
                key={item.href}
                href={item.href}
                icon={item.icon}
                label={item.label}
                active={active}
                badge={item.badge}
                badgeCount={newAlertsCount}
              />
            );
          })}

          {ADMIN_NAV.some(item => can(item.permission)) && (
            <>
              <div className="border-t border-border/50 my-1 mx-1" />
              {ADMIN_NAV.filter(item => can(item.permission)).map((item) => {
                const active = location.startsWith(item.href);
                return (
                  <NavItem
                    key={item.href}
                    href={item.href}
                    icon={item.icon}
                    label={item.label}
                    active={active}
                  />
                );
              })}
            </>
          )}
        </nav>

        {/* User avatar + logout at bottom */}
        <div className="shrink-0 flex flex-col items-center gap-1 pb-3 px-2 w-full border-t border-border pt-3">
          {/* User avatar with tooltip */}
          <div className="relative group">
            <button
              className="w-10 h-10 rounded-lg bg-primary/20 border border-primary/30 flex items-center justify-center hover:bg-primary/30 transition-colors"
              title={displayName}
            >
              <span className="text-xs font-bold text-primary">{initials}</span>
            </button>
            <div className="absolute left-full ml-3 bottom-0 z-50 pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity">
              <div className="bg-popover border border-border text-popover-foreground text-xs px-2.5 py-2 rounded-lg shadow-lg whitespace-nowrap min-w-32">
                <p className="font-semibold text-foreground">{displayName}</p>
                <p className="text-muted-foreground mt-0.5">{ROLE_LABELS[user?.role ?? 'viewer']}</p>
              </div>
            </div>
          </div>

          {/* Logout */}
          <div className="relative group">
            <button
              onClick={() => logout()}
              className="w-10 h-10 rounded-lg flex items-center justify-center text-muted-foreground hover:bg-destructive/10 hover:text-destructive transition-colors"
            >
              <LogOut className="w-4 h-4" />
            </button>
            <div className="absolute left-full ml-3 bottom-0 z-50 pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity">
              <div className="bg-popover border border-border text-popover-foreground text-xs font-medium px-2.5 py-1.5 rounded-lg shadow-lg whitespace-nowrap">
                Sign out
              </div>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Header */}
        <header className="h-14 shrink-0 border-b border-border bg-card/50 backdrop-blur-md flex items-center justify-between px-4 z-10 sticky top-0">
          <div className="flex items-center bg-input border border-border rounded-lg px-3 py-1.5 w-80 focus-within:ring-2 focus-within:ring-primary/50 transition-shadow">
            <svg className="w-3.5 h-3.5 text-muted-foreground shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <input
              type="text"
              placeholder="Search logs, alerts, IPs..."
              className="bg-transparent border-none outline-none text-sm ml-2 w-full text-foreground placeholder:text-muted-foreground"
            />
          </div>

          <div className="flex items-center gap-3">
            <div
              className="flex items-center gap-1.5 cursor-default"
              title={wsConnected ? 'Live alerts connected' : 'Reconnecting...'}
            >
              {wsConnected ? (
                <><Wifi className="w-3.5 h-3.5 text-green-400" /><span className="text-xs text-green-400 hidden sm:inline">Live</span></>
              ) : (
                <><WifiOff className="w-3.5 h-3.5 text-muted-foreground animate-pulse" /><span className="text-xs text-muted-foreground hidden sm:inline">Offline</span></>
              )}
            </div>
            <div className="w-px h-5 bg-border" />
            <NotificationBell />
            <div className="w-px h-5 bg-border" />
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-full bg-primary/20 border border-primary/30 flex items-center justify-center shrink-0">
                <span className="text-xs font-bold text-primary">{initials}</span>
              </div>
              <div className="hidden sm:block">
                <p className="text-sm font-medium text-foreground leading-tight">{displayName}</p>
                <p className="text-xs text-muted-foreground leading-tight">{ROLE_LABELS[user?.role ?? 'viewer']}</p>
              </div>
            </div>
          </div>

          {/* WebSocket alert toast */}
          {wsAlertToast && (
            <div className="fixed top-16 right-4 z-50 bg-card border border-primary/40 rounded-xl px-4 py-3 shadow-2xl flex items-start gap-3 max-w-xs animate-in slide-in-from-right-4 duration-300">
              <div className="w-7 h-7 rounded-full bg-destructive/10 flex items-center justify-center shrink-0">
                <Bell className="w-3.5 h-3.5 text-destructive" />
              </div>
              <div>
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">New Alert</p>
                <p className="text-sm text-foreground font-medium mt-0.5 line-clamp-2">{wsAlertToast}</p>
              </div>
            </div>
          )}
        </header>

        {/* Page Content */}
        <main className="flex-1 overflow-auto bg-background p-5">
          <div className="max-w-[1600px] mx-auto animate-in fade-in duration-300">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}
