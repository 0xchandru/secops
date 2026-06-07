import React, { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { dashboardApi, rulesApi, normalizeRule } from '@/lib/api';
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, BarChart, Bar,
} from 'recharts';
import { safeFormat, formatIST } from '@/lib/date-utils';
import { ShieldAlert, Activity, Clock, Target, TrendingUp, Database, Cpu, Loader2, Zap, Timer, ChevronDown, Shield } from 'lucide-react';
import { SeverityBadge, StatusBadge } from '@/components/ui/Badge';
import { Link, useLocation } from 'wouter';
import { MITRE_MATRIX } from '@/lib/mitre-taxonomy';
import { useWebSocket } from '@/hooks/useWebSocket';

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
  info: '#6366f1',
};

const SOURCE_COLORS: Record<string, string> = {
  firewall: '#3b82f6',
  ids: '#06b6d4',
  endpoint: '#8b5cf6',
  auth: '#f59e0b',
  dns: '#10b981',
  proxy: '#ec4899',
};

const TIME_RANGES = [
  { value: '1h', label: 'Last 1 Hour' },
  { value: '6h', label: 'Last 6 Hours' },
  { value: '24h', label: 'Last 24 Hours' },
  { value: '7d', label: 'Last 7 Days' },
  { value: '30d', label: 'Last 30 Days' },
] as const;

const tooltipStyle = { backgroundColor: 'hsl(var(--card))', borderColor: 'hsl(var(--border))', borderRadius: '8px', fontSize: '12px' };

function StatCard({ title, value, icon, trend, urgent = false, trendUp, href, onClick }: {
  title: string; value: string | number; icon: React.ReactNode; trend: string; urgent?: boolean; trendUp?: boolean; href?: string; onClick?: () => void;
}) {
  const content = (
    <div className={`bg-card rounded-xl p-5 border ${urgent ? 'border-destructive/40' : 'border-border'} shadow-lg shadow-black/20 flex flex-col relative overflow-hidden hover:-translate-y-0.5 transition-all duration-200 ${href || onClick ? 'cursor-pointer' : ''}`}>
      <div className="flex justify-between items-start mb-4">
        <h3 className="text-muted-foreground font-medium text-sm">{title}</h3>
        <div className={`p-2 ${urgent ? 'bg-destructive/10' : 'bg-secondary'} rounded-lg`}>{icon}</div>
      </div>
      <div className="text-3xl font-bold text-foreground mb-1.5 tracking-tight">{value}</div>
      <div className={`text-xs flex items-center gap-1 ${urgent ? 'text-destructive' : trendUp ? 'text-amber-400' : 'text-muted-foreground'}`}>
        {trendUp && <TrendingUp className="w-3 h-3" />}
        {trend}
      </div>
      {urgent && <div className="absolute -top-4 -right-4 w-20 h-20 bg-destructive/10 rounded-full blur-xl" />}
    </div>
  );
  if (href) return <Link href={href}>{content}</Link>;
  if (onClick) return <div onClick={onClick}>{content}</div>;
  return content;
}

export default function DashboardPage() {
  const [, setLocation] = useLocation();
  const [timeRange, setTimeRange] = useState('24h');

  // Real-time alert updates via WebSocket — auto-invalidates dashboard queries
  useWebSocket();

  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['dashboard-stats', timeRange],
    queryFn: () => dashboardApi.stats(timeRange).then(r => r.data),
    refetchInterval: 60000,
  });

  const { data: rulesData } = useQuery({
    queryKey: ['rules'],
    queryFn: () => rulesApi.list().then(r => r.data.rules.map(normalizeRule)),
  });

  const areaData = useMemo(() => {
    const buckets: Record<string, number> = {};
    for (let i = 23; i >= 0; i--) {
      const h = safeFormat(new Date(Date.now() - i * 3600000), 'HH:00');
      buckets[h] = 0;
    }
    (stats?.alertTrend ?? []).forEach(({ hour, count }) => {
      if (hour in buckets) buckets[hour] = count;
    });
    return Object.entries(buckets).map(([time, alerts]) => ({ time, alerts }));
  }, [stats]);

  const pieData = useMemo(() => (
    ['critical', 'high', 'medium', 'low'].map(s => ({
      name: s.charAt(0).toUpperCase() + s.slice(1),
      value: stats?.alerts?.bySeverity?.[s] ?? 0,
      color: SEVERITY_COLORS[s],
    })).filter(d => d.value > 0)
  ), [stats]);

  const topRulesData = useMemo(() => (
    (rulesData ?? [])
      .map(r => ({ name: r.name.length > 22 ? r.name.slice(0, 22) + '…' : r.name, count: r.triggerCount }))
      .sort((a, b) => b.count - a.count).slice(0, 6)
  ), [rulesData]);

  const sourceData = useMemo(() => (
    Object.entries(stats?.logs?.bySource ?? {}).map(([name, value]) => ({
      name, value: Number(value), color: SOURCE_COLORS[name] ?? '#64748b',
    }))
  ), [stats]);

  const newAlerts = stats?.alerts?.byStatus?.new ?? 0;
  const criticalAlerts = stats?.alerts?.bySeverity?.critical ?? 0;
  const resolvedToday = stats?.alerts?.byStatus?.resolved ?? 0;
  const activeRules = stats?.rules?.active ?? rulesData?.filter(r => r.enabled).length ?? 0;
  const totalRules = rulesData?.length ?? 0;
  const eps = stats?.logs?.eps ?? 0;
  const mttr = stats?.mttr;
  const topHosts = stats?.topTargetedHosts ?? [];

  // MITRE coverage from real rules
  const mitreCoverage = useMemo(() => {
    const covered = new Set<string>();
    (rulesData ?? []).forEach(r => {
      r.mitreIds.forEach((id: string) => {
        covered.add(id.toUpperCase());
        covered.add(id.split('.')[0].toUpperCase());
      });
    });
    const totalTechniques = MITRE_MATRIX.reduce((acc, t) => acc + t.techniques.length, 0);
    const coveredCount = MITRE_MATRIX.reduce((acc, t) => acc + t.techniques.filter(tech => covered.has(tech.id.toUpperCase())).length, 0);
    const pct = totalTechniques > 0 ? Math.round((coveredCount / totalTechniques) * 100) : 0;
    return { covered: coveredCount, total: totalTechniques, pct };
  }, [rulesData]);

  const rangeLabel = TIME_RANGES.find(r => r.value === timeRange)?.label ?? 'Last 24 Hours';

  return (
    <>
      <div className="flex flex-col gap-6">
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div>
            <h1 className="text-3xl font-bold tracking-tight text-foreground">SOC Dashboard</h1>
            <p className="text-muted-foreground mt-1">System health and active threats overview — {formatIST(new Date(), 'MMMM d, yyyy HH:mm')}</p>
          </div>
          <div className="flex items-center gap-3">
            {statsLoading && <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />}
            <div className="relative">
              <select
                value={timeRange}
                onChange={e => setTimeRange(e.target.value)}
                aria-label="Select time range"
                className="appearance-none bg-card border border-border rounded-lg px-4 py-2 pr-8 text-sm font-medium text-foreground focus:outline-none focus:ring-1 focus:ring-primary cursor-pointer"
              >
                {TIME_RANGES.map(r => (
                  <option key={r.value} value={r.value}>{r.label}</option>
                ))}
              </select>
              <ChevronDown className="absolute right-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
            </div>
          </div>
        </div>

        {/* Stats Row */}
        <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-4">
          <StatCard title="New Alerts" value={newAlerts} icon={<ShieldAlert className="text-primary" />} trend={`${stats?.alerts?.last24h ?? 0} in ${rangeLabel.toLowerCase()}`} trendUp href="/alerts" />
          <StatCard title="Critical Threats" value={criticalAlerts} icon={<Activity className="text-destructive" />} trend="Requires attention" urgent href="/alerts?severity=critical" />
          <StatCard title="Resolved Alerts" value={resolvedToday} icon={<Clock className="text-emerald-400" />} trend={`${stats?.alerts?.total ?? 0} total alerts`} href="/alerts" />
          <StatCard title="Active Rules" value={activeRules} icon={<Target className="text-blue-400" />} trend={`of ${totalRules} total`} href="/rules" />
          <StatCard title="Events/Sec" value={eps.toFixed(1)} icon={<Zap className="text-amber-400" />} trend="Real-time EPS" href="/logs" />
          <StatCard title="MTTR" value={mttr != null ? `${Math.round(mttr)}m` : '—'} icon={<Timer className="text-cyan-400" />} trend={mttr != null ? 'Avg resolve time (7d)' : 'No data yet'} />
        </div>

        {/* Charts Row 1 */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 bg-card border border-border rounded-xl p-5 shadow-lg shadow-black/20">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-semibold text-foreground">Alert Volume ({rangeLabel})</h3>
              <span className="text-xs text-muted-foreground bg-secondary px-2 py-1 rounded">{stats?.alerts?.total ?? 0} total</span>
            </div>
            <div className="h-60">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={areaData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorAlerts" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" stroke="hsl(var(--muted-foreground))" fontSize={11} tickLine={false} axisLine={false} interval={3} />
                  <YAxis stroke="hsl(var(--muted-foreground))" fontSize={11} tickLine={false} axisLine={false} />
                  <Tooltip contentStyle={tooltipStyle} itemStyle={{ color: 'hsl(var(--foreground))' }} />
                  <Area type="monotone" dataKey="alerts" stroke="#3b82f6" strokeWidth={2} fillOpacity={1} fill="url(#colorAlerts)" dot={false} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="bg-card border border-border rounded-xl p-5 shadow-lg shadow-black/20 flex flex-col">
            <h3 className="font-semibold mb-2 text-foreground">Alerts by Severity</h3>
            {pieData.length === 0 ? (
              <div className="flex-1 flex items-center justify-center text-muted-foreground text-sm">No alert data yet</div>
            ) : (
              <>
                <div className="flex-1 min-h-40">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={pieData} cx="50%" cy="50%" innerRadius={50} outerRadius={75} paddingAngle={3} dataKey="value">
                        {pieData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} stroke="transparent" />
                        ))}
                      </Pie>
                      <Tooltip contentStyle={tooltipStyle} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="grid grid-cols-2 gap-1.5 mt-2">
                  {pieData.map(d => (
                    <div key={d.name} className="flex items-center gap-2 text-xs text-muted-foreground">
                      <div className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: d.color }} />
                      {d.name}: <span className="text-foreground font-medium ml-auto">{d.value}</span>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        </div>

        {/* Charts Row 2 */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-card border border-border rounded-xl p-5 shadow-lg shadow-black/20">
            <h3 className="font-semibold mb-4 text-foreground">Top Detection Rules</h3>
            {topRulesData.length === 0 ? (
              <div className="flex items-center justify-center h-55 text-muted-foreground text-sm">No rule trigger data yet</div>
            ) : (
              <div className="h-55">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={topRulesData} layout="vertical" margin={{ top: 0, right: 30, left: 0, bottom: 0 }}>
                    <XAxis type="number" stroke="hsl(var(--muted-foreground))" fontSize={11} tickLine={false} axisLine={false} />
                    <YAxis dataKey="name" type="category" width={140} stroke="hsl(var(--muted-foreground))" fontSize={11} tickLine={false} axisLine={false} />
                    <Tooltip cursor={{ fill: 'hsl(var(--secondary))' }} contentStyle={tooltipStyle} />
                    <Bar dataKey="count" fill="#3b82f6" radius={[0, 4, 4, 0]} barSize={14} label={{ position: 'right', fontSize: 10, fill: '#94a3b8' }} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
          </div>

          <div className="bg-card border border-border rounded-xl p-5 shadow-lg shadow-black/20">
            <h3 className="font-semibold mb-4 text-foreground">Log Volume by Source</h3>
            {sourceData.length === 0 ? (
              <div className="flex items-center justify-center h-55 text-muted-foreground text-sm">
                <div className="text-center">
                  <Database className="w-8 h-8 mx-auto mb-2 opacity-30" />
                  <p>No log data ingested yet</p>
                </div>
              </div>
            ) : (
              <div className="h-55">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={sourceData} cx="50%" cy="50%" outerRadius={80} dataKey="value" label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`} labelLine={false} fontSize={11}>
                      {sourceData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} stroke="transparent" />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={tooltipStyle} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            )}
          </div>
        </div>

        {/* Bottom Row */}
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          <div className="lg:col-span-2 bg-card border border-border rounded-xl p-5 shadow-lg shadow-black/20">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-semibold text-foreground">Recent Alerts</h3>
              <Link href="/alerts" className="text-primary text-sm hover:underline">View All →</Link>
            </div>
            {statsLoading ? (
              <div className="flex items-center justify-center py-8 gap-3 text-muted-foreground">
                <Loader2 className="w-5 h-5 animate-spin text-primary" /> Loading…
              </div>
            ) : (stats?.recentAlerts ?? []).length === 0 ? (
              <div className="text-center py-8 text-muted-foreground text-sm">No alerts yet. Ingest logs to trigger detections.</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm text-left">
                  <thead className="text-xs text-muted-foreground border-b border-border">
                    <tr>
                      <th className="pb-3 font-medium">Time</th>
                      <th className="pb-3 font-medium">Title</th>
                      <th className="pb-3 font-medium">Severity</th>
                      <th className="pb-3 font-medium">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/50">
                    {(stats?.recentAlerts ?? []).map(alert => (
                      <tr key={alert.id} className="hover:bg-secondary/50 transition-colors cursor-pointer group">
                        <td className="py-2.5 text-muted-foreground whitespace-nowrap text-xs font-mono pr-3">{safeFormat(alert.createdAt, 'HH:mm:ss')}</td>
                        <td className="py-2.5 text-foreground font-medium pr-4">
                          <Link href={`/alerts/${alert.id}`} className="group-hover:text-primary transition-colors block truncate max-w-55">{alert.title}</Link>
                        </td>
                        <td className="py-2.5 pr-3"><SeverityBadge severity={alert.severity as any} /></td>
                        <td className="py-2.5"><StatusBadge status={alert.status as any} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* System Health */}
          <div className="bg-card border border-border rounded-xl p-5 shadow-lg shadow-black/20">
            <div className="flex items-center gap-2 mb-4">
              <Cpu className="w-4 h-4 text-primary" />
              <h3 className="font-semibold text-foreground">Data Overview</h3>
            </div>
            <div className="space-y-4">
              <div className="pt-2 space-y-3 text-sm">
                {[
                  ['Total Alerts', String(stats?.alerts?.total ?? 0)],
                  ['Open (New)', String(stats?.alerts?.byStatus?.new ?? 0)],
                  ['Investigating', String(stats?.alerts?.byStatus?.investigating ?? 0)],
                  ['Resolved', String(stats?.alerts?.byStatus?.resolved ?? 0)],
                  ['False Positives', String(stats?.alerts?.byStatus?.false_positive ?? 0)],
                  ['Total Logs Ingested', String(stats?.logs?.total ?? 0)],
                  ['Events/Sec (EPS)', eps.toFixed(1)],
                  ['Active Detection Rules', String(activeRules)],
                  ['MTTR (7d avg)', mttr != null ? `${Math.round(mttr)} min` : '—'],
                ].map(([label, val]) => (
                  <div key={label} className="flex justify-between items-center border-b border-border/50 pb-2 last:border-0">
                    <span className="text-muted-foreground text-xs">{label}</span>
                    <span className="text-foreground font-mono text-xs font-medium">{val}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Top Targeted Hosts */}
            {topHosts.length > 0 && (
              <div className="mt-4 pt-4 border-t border-border">
                <h4 className="text-xs font-semibold uppercase text-muted-foreground tracking-wider mb-2">Top Targeted Hosts</h4>
                <div className="space-y-2">
                  {topHosts.slice(0, 5).map((h: { hostname: string; count: number }) => (
                    <div key={h.hostname} className="flex justify-between items-center">
                      <span className="text-xs font-mono text-foreground truncate max-w-35">{h.hostname}</span>
                      <span className="text-xs font-mono text-primary font-medium">{h.count}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* MITRE Coverage Widget */}
          <Link href="/mitre" className="block">
            <div className="bg-card border border-border rounded-xl p-5 shadow-lg shadow-black/20 hover:-translate-y-0.5 transition-all cursor-pointer h-full flex flex-col">
              <div className="flex items-center gap-2 mb-4">
                <Shield className="w-4 h-4 text-purple-400" />
                <h3 className="font-semibold text-foreground">MITRE ATT&CK</h3>
              </div>
              <div className="flex-1 flex flex-col items-center justify-center gap-4">
                <div className="relative w-28 h-28">
                  <svg className="w-28 h-28 -rotate-90" viewBox="0 0 36 36">
                    <circle cx="18" cy="18" r="15.9" fill="none" stroke="hsl(var(--secondary))" strokeWidth="2.5" />
                    <circle cx="18" cy="18" r="15.9" fill="none" stroke="#a855f7" strokeWidth="2.5"
                      strokeDasharray={`${mitreCoverage.pct} ${100 - mitreCoverage.pct}`} strokeLinecap="round" />
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <span className="text-2xl font-bold text-foreground">{mitreCoverage.pct}%</span>
                    <span className="text-[10px] text-muted-foreground">Coverage</span>
                  </div>
                </div>
                <div className="text-center">
                  <div className="text-sm font-semibold text-foreground">{mitreCoverage.covered} / {mitreCoverage.total}</div>
                  <div className="text-xs text-muted-foreground">Techniques Covered</div>
                </div>
              </div>
              <div className="mt-auto pt-3 border-t border-border text-center">
                <span className="text-xs text-primary font-medium">View Matrix →</span>
              </div>
            </div>
          </Link>
        </div>
      </div>
    </>
  );
}
