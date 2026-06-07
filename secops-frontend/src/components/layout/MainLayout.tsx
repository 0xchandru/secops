import React, { useEffect, useRef, useState, useCallback } from 'react';
import { Link, useLocation } from 'wouter';
import { useAppStore } from '@/store';
import { useAuthStore } from '@/store/authStore';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { alertsApi } from '@/lib/api';
import { 
  LayoutDashboard, Terminal, AlertTriangle, Shield, 
  Target, Database, Settings, Menu, Bell, Users, ClipboardList,
  LogOut, ChevronRight, Server, Wifi, WifiOff
} from 'lucide-react';
import { ROLE_LABELS, ROLE_COLORS } from '@/lib/constants';
import { NotificationBell } from '@/components/widgets/NotificationBell';

const NAV_ITEMS = [
  { href: '/', icon: LayoutDashboard, label: 'Dashboard', permission: 'reports:view' as const },
  { href: '/logs', icon: Terminal, label: 'Logs Explorer', permission: 'alerts:view' as const },
  { href: '/alerts', icon: AlertTriangle, label: 'Alert Queue', badge: true, permission: 'alerts:view' as const },
  { href: '/assets', icon: Server, label: 'Asset Inventory', permission: 'alerts:view' as const },
  { href: '/rules', icon: Shield, label: 'Detection Rules', permission: 'rules:view' as const },
  { href: '/mitre', icon: Target, label: 'MITRE ATT&CK', permission: 'reports:view' as const },
  { href: '/ingestion', icon: Database, label: 'Log Ingestion', permission: 'ingest:write' as const },
  { href: '/settings', icon: Settings, label: 'Settings', permission: 'reports:view' as const },
];

const ADMIN_NAV = [
  { href: '/users', icon: Users, label: 'User Management', permission: 'users:manage' as const },
  { href: '/audit', icon: ClipboardList, label: 'Audit Logs', permission: 'audit:view' as const },
];

export function MainLayout({ children }: { children: React.ReactNode }) {
  const [location] = useLocation();
  const { sidebarCollapsed, toggleSidebar } = useAppStore();
  const { user, logout, can, isAuthenticated } = useAuthStore();
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
      {/* Sidebar */}
      <aside 
        className={`${sidebarCollapsed ? 'w-20' : 'w-64'} shrink-0 border-r border-border bg-sidebar transition-all duration-300 ease-in-out flex flex-col`}
      >
        <div className="h-16 flex items-center justify-between px-4 border-b border-border">
          {!sidebarCollapsed && (
            <div className="flex items-center gap-2 text-primary font-bold text-lg tracking-tight">
              <Shield className="w-6 h-6" />
              SecOps Console
            </div>
          )}
          {sidebarCollapsed && (
            <Shield className="w-8 h-8 text-primary mx-auto" />
          )}
        </div>

        <nav className="flex-1 py-6 px-3 space-y-1 overflow-y-auto">
          {NAV_ITEMS.filter(item => can(item.permission)).map((item) => {
            const active = location === item.href || (item.href !== '/' && location.startsWith(item.href));
            return (
              <Link 
                key={item.href} 
                href={item.href}
                className={`
                  flex items-center px-3 py-2.5 rounded-xl transition-all duration-200 group relative
                  ${active 
                    ? 'bg-primary/10 text-primary font-medium' 
                    : 'text-muted-foreground hover:bg-secondary hover:text-foreground'
                  }
                  ${sidebarCollapsed ? 'justify-center' : ''}
                `}
                title={sidebarCollapsed ? item.label : undefined}
              >
                <item.icon className={`w-5 h-5 ${active ? 'text-primary' : 'group-hover:text-foreground'}`} />
                {!sidebarCollapsed && (
                  <span className="ml-3 flex-1">{item.label}</span>
                )}
                {!sidebarCollapsed && item.badge && newAlertsCount > 0 && (
                  <span className="bg-destructive text-destructive-foreground text-xs font-bold px-2 py-0.5 rounded-full">
                    {newAlertsCount}
                  </span>
                )}
                {sidebarCollapsed && item.badge && newAlertsCount > 0 && (
                  <span className="absolute top-2 right-2 w-2.5 h-2.5 bg-destructive rounded-full" />
                )}
              </Link>
            );
          })}

          {ADMIN_NAV.some(item => can(item.permission)) && (
            <>
              {!sidebarCollapsed && (
                <div className="px-3 pt-4 pb-1">
                  <p className="text-xs text-muted-foreground/60 uppercase tracking-wider font-medium">
                    {can('users:manage') ? 'Admin' : 'Reports'}
                  </p>
                </div>
              )}
              {sidebarCollapsed && <div className="border-t border-border/50 mx-2 my-2" />}
              {ADMIN_NAV.filter(item => can(item.permission)).map((item) => {
                const active = location.startsWith(item.href);
                return (
                  <Link 
                    key={item.href} 
                    href={item.href}
                    className={`
                      flex items-center px-3 py-2.5 rounded-xl transition-all duration-200 group
                      ${active 
                        ? 'bg-primary/10 text-primary font-medium' 
                        : 'text-muted-foreground hover:bg-secondary hover:text-foreground'
                      }
                      ${sidebarCollapsed ? 'justify-center' : ''}
                    `}
                    title={sidebarCollapsed ? item.label : undefined}
                  >
                    <item.icon className={`w-5 h-5 ${active ? 'text-primary' : ''}`} />
                    {!sidebarCollapsed && <span className="ml-3 flex-1">{item.label}</span>}
                  </Link>
                );
              })}
            </>
          )}
        </nav>
        
        <div className="p-4 border-t border-border space-y-2">
          {!sidebarCollapsed && user && (
            <div className="flex items-center gap-3 px-2 py-1.5 rounded-lg bg-background/50 border border-border/50">
              <div className="w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center border border-primary/30 shrink-0">
                <span className="text-xs font-bold text-primary">{initials}</span>
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-foreground truncate">{displayName}</p>
                <span className={`text-xs px-1.5 py-0.5 rounded border ${ROLE_COLORS[user.role]}`}>
                  {ROLE_LABELS[user.role]}
                </span>
              </div>
            </div>
          )}
          <div className="flex gap-2">
            {!sidebarCollapsed && (
              <button
                onClick={() => logout()}
                className="flex-1 flex items-center justify-center gap-2 py-2 rounded-lg hover:bg-destructive/10 text-muted-foreground hover:text-destructive transition-colors text-sm"
              >
                <LogOut className="w-4 h-4" />
                Sign out
              </button>
            )}
            <button 
              onClick={toggleSidebar}
              className={`flex items-center justify-center p-2 rounded-lg hover:bg-secondary text-muted-foreground hover:text-foreground transition-colors ${sidebarCollapsed ? 'w-full' : ''}`}
            >
              {sidebarCollapsed ? <ChevronRight className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Header */}
        <header className="h-16 shrink-0 border-b border-border bg-card/50 backdrop-blur-md flex items-center justify-between px-6 z-10 sticky top-0">
          <div className="flex items-center bg-input border border-border rounded-lg px-3 py-2 w-96 focus-within:ring-2 focus-within:ring-primary/50 transition-shadow">
            <svg className="w-4 h-4 text-muted-foreground" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <input 
              type="text" 
              placeholder="Search logs, alerts, IPs..." 
              className="bg-transparent border-none outline-none text-sm ml-2 w-full text-foreground placeholder:text-muted-foreground"
            />
          </div>

          <div className="flex items-center gap-4">
            {/* WS status */}
            <div className="flex items-center gap-1.5" title={wsConnected ? 'Live alerts connected' : 'Reconnecting...'}>
              {wsConnected ? (
                <Wifi className="w-4 h-4 text-green-400" />
              ) : (
                <WifiOff className="w-4 h-4 text-muted-foreground animate-pulse" />
              )}
              {!sidebarCollapsed && (
                <span className={`text-xs ${wsConnected ? 'text-green-400' : 'text-muted-foreground'}`}>
                  {wsConnected ? 'Live' : 'Offline'}
                </span>
              )}
            </div>
            <div className="w-px h-6 bg-border" />
            <NotificationBell />
            <div className="w-px h-6 bg-border" />
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center border border-primary/30">
                <span className="text-xs font-bold text-primary">{initials}</span>
              </div>
              <div>
                <p className="text-sm font-medium text-foreground leading-tight">{displayName}</p>
                <p className="text-xs text-muted-foreground leading-tight">{ROLE_LABELS[user?.role ?? 'viewer']}</p>
              </div>
            </div>
          </div>
          
          {/* WebSocket alert toast */}
          {wsAlertToast && (
            <div className="fixed top-20 right-4 z-50 bg-card border border-primary/40 rounded-xl px-4 py-3 shadow-2xl flex items-start gap-3 max-w-xs animate-in slide-in-from-right-4 duration-300">
              <div className="w-8 h-8 rounded-full bg-destructive/10 flex items-center justify-center shrink-0">
                <Bell className="w-4 h-4 text-destructive" />
              </div>
              <div>
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">New Alert</p>
                <p className="text-sm text-foreground font-medium mt-0.5 line-clamp-2">{wsAlertToast}</p>
              </div>
            </div>
          )}
        </header>

        {/* Page Content */}
        <main className="flex-1 overflow-auto bg-background p-6">
          <div className="max-w-7xl mx-auto animate-in fade-in duration-300">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}
