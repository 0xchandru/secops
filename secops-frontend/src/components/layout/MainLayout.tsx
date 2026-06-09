import React, { useEffect, useRef, useState, useCallback } from 'react';
import { Link, useLocation } from 'wouter';
import { useAuthStore } from '@/store/authStore';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { alertsApi } from '@/lib/api';
import {
  LayoutDashboard, Terminal, AlertTriangle, Shield,
  Target, Database, Settings, Bell, Users, ClipboardList,
  LogOut, Server, Wifi, WifiOff,
} from 'lucide-react';
import { ROLE_LABELS } from '@/lib/constants';
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
  { href: '/settings', icon: Settings, label: 'Settings', permission: 'users:manage' as const },
];

function NavItem({ href, icon: Icon, label, active, badge, badgeCount }: {
  href: string; icon: React.ElementType; label: string; active: boolean;
  badge?: boolean; badgeCount?: number;
}) {
  return (
    <Link
      href={href}
      title={label}
      className={`
        flex items-center gap-3 h-10 pl-3 pr-4 rounded-lg mx-1 border-l-2 transition-all duration-150
        ${active
          ? 'border-primary bg-primary/10 text-primary'
          : 'border-transparent text-slate-400 hover:bg-slate-700/50 hover:text-slate-200'
        }
      `}
    >
      <Icon className="w-5 h-5 shrink-0" />
      <span className="text-[13px] font-medium whitespace-nowrap truncate flex-1">{label}</span>
      {badge && badgeCount && badgeCount > 0 && (
        <span className="shrink-0 min-w-[18px] h-[18px] rounded-full bg-red-500 text-white text-[10px] font-bold flex items-center justify-center px-1">
          {badgeCount > 99 ? '99+' : badgeCount}
        </span>
      )}
    </Link>
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
  const [sidebarOpen, setSidebarOpen] = useState(() => {
    try { return localStorage.getItem('sidebarOpen') !== 'false'; } catch { return true; }
  });

  const toggleSidebar = () => {
    setSidebarOpen(prev => {
      const next = !prev;
      try { localStorage.setItem('sidebarOpen', String(next)); } catch { }
      return next;
    });
  };

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
        } catch { }
      };
      ws.onclose = () => { setWsConnected(false); wsRef.current = null; wsReconnectRef.current = setTimeout(connectWs, 6000); };
      ws.onerror = () => ws.close();
    } catch { }
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
      <aside
        className={`shrink-0 border-r border-border bg-sidebar flex flex-col z-30 overflow-hidden transition-[width] duration-200 ease-out ${sidebarOpen ? 'w-56' : 'w-14'}`}
        style={{ willChange: 'width' }}
      >
        {/* Fixed-width inner wrapper — always 224px, clipped by aside overflow */}
        <div className="w-56 flex flex-col flex-1">
          {/* Logo + toggle */}
          <div className="h-14 flex items-center shrink-0 px-3 gap-2 border-b border-border">
            <button
              onClick={toggleSidebar}
              className="w-8 h-8 rounded-lg bg-primary/20 border border-primary/30 flex items-center justify-center shrink-0 hover:bg-primary/30 transition-colors"
              title={sidebarOpen ? 'Collapse sidebar' : 'Expand sidebar'}
            >
              <Shield className="w-4 h-4 text-primary" />
            </button>
            <div className="min-w-0 flex-1">
              <p className="text-sm font-bold text-foreground whitespace-nowrap leading-tight">SecOps Console</p>
              <p className="text-[10px] text-slate-500 whitespace-nowrap">Security Operations</p>
            </div>
          </div>

          {/* Primary nav */}
          <nav className="flex-1 flex flex-col gap-0.5 py-3 overflow-y-auto">
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
                <div className="border-t border-border/40 my-2 mx-3" />
                <p className="px-4 pb-1 text-[10px] font-semibold text-slate-600 uppercase tracking-wider whitespace-nowrap">Admin</p>
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

          {/* User + Logout at bottom */}
          <div className="shrink-0 border-t border-border px-2 py-3 space-y-0.5">
            <div className="flex items-center gap-3 px-2 py-2 rounded-lg">
              <div className="w-8 h-8 rounded-full bg-primary/20 border border-primary/30 flex items-center justify-center shrink-0">
                <span className="text-xs font-bold text-primary">{initials}</span>
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-xs font-semibold text-foreground whitespace-nowrap truncate">{displayName}</p>
                <p className="text-[10px] text-slate-500 whitespace-nowrap">{ROLE_LABELS[user?.role ?? 'viewer']}</p>
              </div>
            </div>
            <button
              onClick={() => logout()}
              className="flex items-center gap-3 w-full h-9 px-3 rounded-lg border-l-2 border-transparent text-slate-500 hover:bg-red-500/10 hover:text-red-400 hover:border-red-500/50 transition-all duration-150"
            >
              <LogOut className="w-4 h-4 shrink-0" />
              <span className="text-[13px] font-medium whitespace-nowrap">Sign Out</span>
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Header */}
        <header className="h-14 shrink-0 border-b border-border bg-card/60 backdrop-blur-md flex items-center justify-between px-4 z-10 sticky top-0">
          <div className="flex items-center bg-input border border-border rounded-lg px-3 py-1.5 w-80 focus-within:ring-1 focus-within:ring-primary/50 transition-shadow">
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
            <div className="flex items-center gap-1.5 cursor-default" title={wsConnected ? 'Live alerts connected' : 'Reconnecting...'}>
              {wsConnected ? (
                <><Wifi className="w-3.5 h-3.5 text-emerald-400" /><span className="text-xs text-emerald-400 hidden sm:inline">Live</span></>
              ) : (
                <><WifiOff className="w-3.5 h-3.5 text-slate-500 animate-pulse" /><span className="text-xs text-slate-500 hidden sm:inline">Offline</span></>
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
            <div className="fixed top-16 right-4 z-50 bg-card border border-primary/30 rounded-xl px-4 py-3 shadow-2xl flex items-start gap-3 max-w-xs animate-in slide-in-from-right-4 duration-300">
              <div className="w-7 h-7 rounded-full bg-red-500/10 flex items-center justify-center shrink-0">
                <Bell className="w-3.5 h-3.5 text-red-400" />
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
