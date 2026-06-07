import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { ClipboardList, RefreshCw, CheckCircle, XCircle, Search, Download, CalendarDays, Filter } from "lucide-react";
import { auditApi } from "@/lib/api";

interface AuditLog {
  id: string;
  userId: string | null;
  username: string | null;
  action: string;
  resource: string | null;
  resourceId: string | null;
  metadata: Record<string, unknown> | null;
  ipAddress: string | null;
  success: string;
  createdAt: string;
}

const ACTION_COLORS: Record<string, string> = {
  "auth.login": "text-green-400",
  "auth.login_failed": "text-destructive",
  "auth.logout": "text-muted-foreground",
  "users.create": "text-blue-400",
  "users.update": "text-amber-400",
  "users.delete": "text-destructive",
  "users.reset_password": "text-amber-400",
  "alerts.status_update": "text-primary",
  "alerts.add_note": "text-primary",
  "alerts.assign": "text-primary",
  "rules.create": "text-blue-400",
  "rules.update": "text-amber-400",
  "rules.delete": "text-destructive",
  "rules.enable": "text-green-400",
  "rules.disable": "text-amber-400",
  "ingest.log": "text-muted-foreground",
};

const TIME_RANGES: { value: string; label: string }[] = [
  { value: '', label: 'All Time' },
  { value: '1h', label: '1 hour' },
  { value: '24h', label: '24 hours' },
  { value: '7d', label: '7 days' },
  { value: '30d', label: '30 days' },
];

const RANGE_MS: Record<string, number> = { '1h': 3_600_000, '24h': 86_400_000, '7d': 604_800_000, '30d': 2_592_000_000 };

export default function AuditLogPage() {
  const [page, setPage] = useState(1);
  const [actionFilter, setActionFilter] = useState('');
  const [userFilter, setUserFilter] = useState('');
  const [successFilter, setSuccessFilter] = useState<'' | 'true' | 'false'>('');
  const [timeRange, setTimeRange] = useState('');
  const limit = 50;

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['audit-logs', page],
    queryFn: () => auditApi.list({ page: String(page), limit: String(limit) }).then(r => r.data),
  });

  const logs: AuditLog[] = data?.logs ?? [];
  const total = data?.total ?? 0;

  // Unique action types for the dropdown
  const actionTypes = useMemo(() => [...new Set(logs.map(l => l.action))].sort(), [logs]);

  // Client-side filtering
  const filteredLogs = useMemo(() => {
    let result = logs;
    if (actionFilter) result = result.filter(l => l.action === actionFilter);
    if (userFilter) result = result.filter(l => (l.username ?? '').toLowerCase().includes(userFilter.toLowerCase()));
    if (successFilter) result = result.filter(l => l.success === successFilter);
    if (timeRange && RANGE_MS[timeRange]) {
      const cutoff = new Date(Date.now() - RANGE_MS[timeRange]);
      result = result.filter(l => new Date(l.createdAt) >= cutoff);
    }
    return result;
  }, [logs, actionFilter, userFilter, successFilter, timeRange]);

  const totalPages = Math.ceil(total / limit);

  const exportCsv = () => {
    if (filteredLogs.length === 0) return;
    const headers = ['Time', 'User', 'Action', 'Resource', 'IP', 'Status'];
    const rows = filteredLogs.map(l => [
      new Date(l.createdAt).toISOString(),
      l.username ?? 'system',
      l.action,
      l.resource ? `${l.resource}${l.resourceId ? '#' + l.resourceId.slice(0, 8) : ''}` : '—',
      l.ipAddress ?? '—',
      l.success === 'true' ? 'Success' : 'Failed',
    ]);
    const csv = [headers, ...rows].map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = `audit-logs-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click(); URL.revokeObjectURL(url);
  };

  return (
    <>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-primary/10 rounded-lg border border-primary/20">
              <ClipboardList className="w-6 h-6 text-primary" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-foreground">Audit Logs</h1>
              <p className="text-sm text-muted-foreground">Complete record of all system actions and events</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={exportCsv} disabled={filteredLogs.length === 0} className="flex items-center gap-2 px-4 py-2 bg-secondary border border-border rounded-lg text-sm hover:bg-secondary/80 transition-colors disabled:opacity-40">
              <Download className="w-4 h-4" />
              Export CSV
            </button>
            <button onClick={() => refetch()} className="flex items-center gap-2 px-4 py-2 bg-secondary border border-border rounded-lg text-sm hover:bg-secondary/80 transition-colors">
              <RefreshCw className="w-4 h-4" />
              Refresh
            </button>
          </div>
        </div>

        {/* Filter Bar */}
        <div className="flex flex-wrap items-center gap-3 bg-card border border-border rounded-xl px-4 py-3">
          <Filter className="w-4 h-4 text-muted-foreground" />

          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
            <input
              placeholder="Filter by user…"
              value={userFilter}
              onChange={e => setUserFilter(e.target.value)}
              className="pl-8 pr-3 py-1.5 bg-secondary border border-border rounded text-sm w-44 focus:outline-none focus:ring-1 focus:ring-primary"
            />
          </div>

          <select aria-label="Filter by action" value={actionFilter} onChange={e => setActionFilter(e.target.value)} className="px-3 py-1.5 bg-secondary border border-border rounded text-sm focus:outline-none focus:ring-1 focus:ring-primary">
            <option value="">All Actions</option>
            {actionTypes.map(a => <option key={a} value={a}>{a}</option>)}
          </select>

          <select aria-label="Filter by status" value={successFilter} onChange={e => setSuccessFilter(e.target.value as '' | 'true' | 'false')} className="px-3 py-1.5 bg-secondary border border-border rounded text-sm focus:outline-none focus:ring-1 focus:ring-primary">
            <option value="">All Statuses</option>
            <option value="true">Success</option>
            <option value="false">Failed</option>
          </select>

          <div className="flex items-center gap-1.5">
            <CalendarDays className="w-3.5 h-3.5 text-muted-foreground" />
            <select aria-label="Filter by time range" value={timeRange} onChange={e => setTimeRange(e.target.value)} className="px-3 py-1.5 bg-secondary border border-border rounded text-sm focus:outline-none focus:ring-1 focus:ring-primary">
              {TIME_RANGES.map(r => <option key={r.value} value={r.value}>{r.label}</option>)}
            </select>
          </div>

          {(actionFilter || userFilter || successFilter || timeRange) && (
            <button onClick={() => { setActionFilter(''); setUserFilter(''); setSuccessFilter(''); setTimeRange(''); }} className="text-xs text-primary hover:underline ml-auto">Clear filters</button>
          )}
        </div>

        {/* Table */}
        <div className="bg-card border border-border rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-border flex items-center justify-between">
            <p className="text-sm text-muted-foreground">
              {filteredLogs.length !== logs.length
                ? <>{filteredLogs.length} of {total.toLocaleString()} events</>
                : <>{total.toLocaleString()} total events</>}
            </p>
            <div className="flex items-center gap-2">
              <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page <= 1} className="px-3 py-1 text-sm bg-secondary border border-border rounded disabled:opacity-40 hover:bg-secondary/80 transition-colors">Prev</button>
              <span className="text-sm text-muted-foreground">{page} / {totalPages || 1}</span>
              <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page >= totalPages} className="px-3 py-1 text-sm bg-secondary border border-border rounded disabled:opacity-40 hover:bg-secondary/80 transition-colors">Next</button>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-secondary/30">
                  <th className="text-left px-4 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Time</th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">User</th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Action</th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Resource</th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">IP Address</th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Status</th>
                </tr>
              </thead>
              <tbody>
                {isLoading ? (
                  <tr><td colSpan={6} className="text-center py-12 text-muted-foreground">Loading…</td></tr>
                ) : filteredLogs.length === 0 ? (
                  <tr><td colSpan={6} className="text-center py-12 text-muted-foreground">No audit logs match filters</td></tr>
                ) : filteredLogs.map(log => (
                  <tr key={log.id} className="border-b border-border/40 hover:bg-secondary/20 transition-colors">
                    <td className="px-4 py-3 text-muted-foreground whitespace-nowrap">
                      {new Date(log.createdAt).toLocaleString()}
                    </td>
                    <td className="px-4 py-3 font-medium text-foreground">{log.username ?? "system"}</td>
                    <td className="px-4 py-3">
                      <code className={`text-xs font-mono ${ACTION_COLORS[log.action] ?? "text-foreground"}`}>
                        {log.action}
                      </code>
                    </td>
                    <td className="px-4 py-3 text-muted-foreground">
                      {log.resource ?? "—"}
                      {log.resourceId && <span className="ml-1 text-xs opacity-60">#{log.resourceId.slice(0, 8)}</span>}
                    </td>
                    <td className="px-4 py-3 text-muted-foreground font-mono text-xs">{log.ipAddress ?? "—"}</td>
                    <td className="px-4 py-3">
                      {log.success === "true"
                        ? <CheckCircle className="w-4 h-4 text-green-400" />
                        : <XCircle className="w-4 h-4 text-destructive" />}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </>
  );
}
