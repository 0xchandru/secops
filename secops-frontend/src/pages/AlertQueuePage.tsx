import React, { useState, useMemo, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { alertsApi, usersApi, normalizeAlert } from '@/lib/api';
import { useAuthStore } from '@/store/authStore';
import { format } from 'date-fns';
import { safeFormat, timeAgo } from '@/lib/date-utils';
import { getAvailableActions } from '@/lib/alert-actions';

import { SeverityBadge, StatusBadge } from '@/components/ui/Badge';
import { ThreatBadge } from '@/components/threat/ThreatBadge';
import {
  Search, ShieldAlert, CheckSquare, Clock, Target, UserCheck,
  XCircle, CheckCircle2, AlertTriangle, Square, Loader2, Download, Layers,
  CalendarDays, Bell, Eye, TrendingUp, Shield, Zap, Activity, Play,
  RefreshCw, Filter, X
} from 'lucide-react';
import { Link } from 'wouter';
import type { AlertStatus, Severity } from '@/lib/types';
import ActionConfirmDialog from '@/components/ui/ActionConfirmDialog';
import type { ConfirmVariant } from '@/components/ui/ActionConfirmDialog';
import AssignDialog from '@/components/ui/AssignDialog';
import EscalateDialog from '@/components/ui/EscalateDialog';
import { ROLE_LABELS, ROLE_COLORS } from '@/lib/constants';
import { useWebSocket } from '@/hooks/useWebSocket';

/* ─── Constants ──────────────────────────────────────────────────────────── */

const STATUSES: AlertStatus[] = ['new', 'investigating', 'escalated', 'resolved', 'false_positive'];
const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];
const TIME_RANGES = [
  { value: '', label: 'All Time' },
  { value: '1h', label: 'Last 1 hour' },
  { value: '6h', label: 'Last 6 hours' },
  { value: '24h', label: 'Last 24 hours' },
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
] as const;
type GroupBy = 'none' | 'rule' | 'mitre';

const SEVERITY_COLORS: Record<string, { bar: string; bg: string; text: string; ring: string }> = {
  critical: { bar: 'bg-red-500', bg: 'bg-red-500/5', text: 'text-red-400', ring: 'ring-red-500/20' },
  high:     { bar: 'bg-orange-500', bg: 'bg-orange-500/5', text: 'text-orange-400', ring: 'ring-orange-500/20' },
  medium:   { bar: 'bg-yellow-500', bg: 'bg-yellow-500/5', text: 'text-yellow-400', ring: 'ring-yellow-500/20' },
  low:      { bar: 'bg-green-500', bg: 'bg-green-500/5', text: 'text-green-400', ring: 'ring-green-500/20' },
  info:     { bar: 'bg-indigo-500', bg: 'bg-indigo-500/5', text: 'text-indigo-400', ring: 'ring-indigo-500/20' },
};

const STATUS_ICONS: Record<string, { icon: React.ElementType; color: string }> = {
  all:            { icon: ShieldAlert, color: 'text-primary' },
  new:            { icon: Bell, color: 'text-blue-400' },
  investigating:  { icon: Search, color: 'text-amber-400' },
  escalated:      { icon: TrendingUp, color: 'text-red-400' },
  resolved:       { icon: CheckCircle2, color: 'text-emerald-400' },
  false_positive: { icon: XCircle, color: 'text-gray-400' },
};

/* ─── AlertRow Component ─────────────────────────────────────────────────── */

function AlertRow({ alert, assigneeName, selectedIds, toggleSelect, currentUserId, handleQuickAction, onAssign, onEscalate }: {
  alert: any; assigneeName: string | undefined; selectedIds: Set<string>;
  toggleSelect: (id: string) => void; currentUserId: string;
  handleQuickAction: (e: React.MouseEvent, id: string, status: AlertStatus) => void;
  onAssign: (alertId: string) => void; onEscalate: (alertId: string) => void;
}) {
  const sevColor = SEVERITY_COLORS[alert.severity] || SEVERITY_COLORS.info;
  const isSelected = selectedIds.has(alert.id);
  const actions = getAvailableActions({ status: alert.status, assignedTo: alert.assignee, currentUserId });

  return (
    <tr className={`hover:bg-secondary/40 transition-all group ${isSelected ? 'bg-primary/5 ring-1 ring-inset ring-primary/20' : ''}`}>
      {/* Checkbox */}
      <td className="pl-2 pr-1 py-3.5" onClick={e => { e.preventDefault(); e.stopPropagation(); toggleSelect(alert.id); }}>
        <button className="text-muted-foreground hover:text-foreground p-1">
          {isSelected ? <CheckSquare className="w-4 h-4 text-primary" /> : <Square className="w-4 h-4" />}
        </button>
      </td>

      {/* Severity bar + title */}
      <td className="px-0 py-3.5">
        <div className="flex items-stretch gap-3">
          <div className={`w-1 rounded-full ${sevColor.bar} shrink-0 self-stretch min-h-10`} />
          <div className="min-w-0 flex-1">
            <Link href={`/alerts/${alert.id}`} className="hover:text-primary transition-colors block">
              <span className="text-sm font-medium text-foreground truncate block max-w-80">{alert.title}</span>
            </Link>
            <div className="flex items-center gap-2 mt-1 flex-wrap">
              <span className="font-mono text-[10px] text-muted-foreground bg-secondary/60 px-1.5 py-0.5 rounded">
                {alert.id.slice(0, 8)}
              </span>
              {alert.ruleName && (
                <span className="text-[10px] text-muted-foreground flex items-center gap-1">
                  <Shield className="w-2.5 h-2.5" /> {alert.ruleName}
                </span>
              )}
            </div>
          </div>
        </div>
      </td>

      {/* Severity */}
      <td className="px-3 py-3.5"><SeverityBadge severity={alert.severity} /></td>

      {/* Status */}
      <td className="px-3 py-3.5"><StatusBadge status={alert.status} /></td>

      {/* MITRE */}
      <td className="px-3 py-3.5">
        <div className="flex gap-1 flex-wrap">
          {alert.mitreIds.slice(0, 2).map((id: string) => (
            <span key={id} className="text-[10px] font-mono bg-purple-500/10 border border-purple-500/20 px-1.5 py-0.5 rounded text-purple-400">{id}</span>
          ))}
          {alert.mitreIds.length > 2 && (
            <span className="text-[10px] text-muted-foreground">+{alert.mitreIds.length - 2}</span>
          )}
        </div>
      </td>

      {/* Threat Score */}
      <td className="px-3 py-3.5">
        <ThreatBadge score={(alert as any).maxIocScore} riskLevel={(alert as any).maxIocRiskLevel} />
      </td>

      {/* Age */}
      <td className="px-3 py-3.5 text-xs whitespace-nowrap">
        <div className="flex flex-col gap-0.5">
          <span className="text-muted-foreground flex items-center gap-1">
            <Clock className="w-3 h-3" />{safeFormat(alert.createdAt, 'MMM dd, HH:mm')}
          </span>
          <span className="text-[10px] text-muted-foreground/60">{timeAgo(alert.createdAt)}</span>
        </div>
      </td>

      {/* Assignee */}
      <td className="px-3 py-3.5">
        {assigneeName ? (
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 rounded-full bg-primary/20 border border-primary/30 flex items-center justify-center text-xs font-bold text-primary shrink-0">
              {assigneeName.charAt(0).toUpperCase()}
            </div>
            <span className="text-xs text-foreground truncate max-w-20">{assigneeName}</span>
          </div>
        ) : (
          <span className="text-muted-foreground/40 text-xs">—</span>
        )}
      </td>

      {/* Actions */}
      <td className="px-3 py-3.5 text-right">
        <div className="flex items-center justify-end gap-1">
          {actions.canInvestigate && (
            <button onClick={e => handleQuickAction(e, alert.id, 'investigating')} title="Start Investigation"
              className="p-1.5 text-amber-400 hover:bg-amber-400/10 rounded-lg transition-colors">
              <Play className="w-3.5 h-3.5" />
            </button>
          )}
          {actions.canResolve && (
            <button onClick={e => handleQuickAction(e, alert.id, 'resolved')} title="Resolve"
              className="p-1.5 text-emerald-400 hover:bg-emerald-400/10 rounded-lg transition-colors">
              <CheckCircle2 className="w-3.5 h-3.5" />
            </button>
          )}
          {actions.canFalsePositive && (
            <button onClick={e => handleQuickAction(e, alert.id, 'false_positive')} title="False Positive"
              className="p-1.5 text-gray-400 hover:bg-gray-400/10 rounded-lg transition-colors">
              <XCircle className="w-3.5 h-3.5" />
            </button>
          )}
          {actions.canEscalate && (
            <button onClick={e => { e.preventDefault(); e.stopPropagation(); onEscalate(alert.id); }} title="Escalate"
              className="p-1.5 text-red-400 hover:bg-red-400/10 rounded-lg transition-colors">
              <TrendingUp className="w-3.5 h-3.5" />
            </button>
          )}
          {actions.canAssign && (
            <button onClick={e => { e.preventDefault(); e.stopPropagation(); onAssign(alert.id); }} title="Assign"
              className="p-1.5 text-primary hover:bg-primary/10 rounded-lg transition-colors">
              <UserCheck className="w-3.5 h-3.5" />
            </button>
          )}
          <Link href={`/alerts/${alert.id}`}
            className="px-2.5 py-1.5 bg-primary/10 text-primary hover:bg-primary/20 font-medium rounded-lg transition-colors text-xs flex items-center gap-1">
            <Eye className="w-3 h-3" /> View
          </Link>
        </div>
      </td>
    </tr>
  );
}

/* ─── Main Component ─────────────────────────────────────────────────────── */

export default function AlertQueuePage() {
  const qc = useQueryClient();
  const { can, user: authUser } = useAuthStore();
  const canClose  = can('alerts:close');
  const canAssign = can('alerts:assign');
  const canTriage = can('alerts:triage');
  const currentUserId = authUser?.userId ?? '';

  useWebSocket();

  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [timeRange, setTimeRange] = useState('');
  const [groupBy, setGroupBy] = useState<GroupBy>('none');
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [bulkAssignOpen, setBulkAssignOpen] = useState(false);
  const [toast, setToast] = useState<string | null>(null);
  const [bulkConfirm, setBulkConfirm] = useState<{
    open: boolean; status: AlertStatus; variant: ConfirmVariant;
    title: string; description: string; confirmLabel: string; requireComment: boolean;
  }>({ open: false, status: 'new', variant: 'info', title: '', description: '', confirmLabel: 'Confirm', requireComment: false });
  const [rowAssignAlertId, setRowAssignAlertId] = useState<string | null>(null);
  const [rowEscalateAlertId, setRowEscalateAlertId] = useState<string | null>(null);

  const showToast = useCallback((msg: string) => { setToast(msg); setTimeout(() => setToast(null), 3000); }, []);

  const queryParams = useMemo(() => {
    const p: Record<string, string> = { limit: '200' };
    if (statusFilter !== 'all') p.status = statusFilter;
    if (severityFilter !== 'all') p.severity = severityFilter;
    if (searchTerm.length >= 2) p.search = searchTerm;
    if (timeRange) p.from = timeRange;
    return p;
  }, [statusFilter, severityFilter, searchTerm, timeRange]);

  const { data, isLoading, isFetching, isError, refetch } = useQuery({
    queryKey: ['alerts', queryParams],
    queryFn: () => alertsApi.list(queryParams).then(r => r.data),
    refetchInterval: 30000,
  });

  // Separate query for unfiltered counts (ignores status filter)
  const countParams = useMemo(() => {
    const p: Record<string, string> = { limit: '500' };
    if (severityFilter !== 'all') p.severity = severityFilter;
    if (searchTerm.length >= 2) p.search = searchTerm;
    if (timeRange) p.from = timeRange;
    return p;
  }, [severityFilter, searchTerm, timeRange]);

  const { data: countData } = useQuery({
    queryKey: ['alerts-counts', countParams],
    queryFn: () => alertsApi.list(countParams).then(r => r.data),
    refetchInterval: 30000,
  });

  const { data: usersData } = useQuery({
    queryKey: ['users'],
    queryFn: () => usersApi.list().then(r => r.data.users),
    enabled: canAssign,
  });

  const analysts = useMemo(() =>
    (usersData ?? []).filter((u: any) => u.status === 'active' && u.role !== 'viewer'),
    [usersData]
  );

  const alerts = useMemo(() =>
    (data?.alerts ?? []).map(normalizeAlert),
    [data]
  );

  // Compute counts from unfiltered countData (ignores status filter)
  const allAlerts = useMemo(() =>
    (countData?.alerts ?? []).map(normalizeAlert),
    [countData]
  );

  const counts = useMemo(() => ({
    all: allAlerts.length,
    new: allAlerts.filter(a => a.status === 'new').length,
    investigating: allAlerts.filter(a => a.status === 'investigating').length,
    escalated: allAlerts.filter(a => a.status === 'escalated').length,
    resolved: allAlerts.filter(a => a.status === 'resolved').length,
    false_positive: allAlerts.filter(a => a.status === 'false_positive').length,
  }), [allAlerts]);

  const severityCounts = useMemo(() => ({
    critical: alerts.filter(a => a.severity === 'critical').length,
    high: alerts.filter(a => a.severity === 'high').length,
    medium: alerts.filter(a => a.severity === 'medium').length,
    low: alerts.filter(a => a.severity === 'low').length,
  }), [alerts]);

  /* ── Mutations ── */

  /* ── Unified Action Mutations (DB-driven RBAC) ── */

  const actionMutation = useMutation({
    mutationFn: ({ id, action, payload }: { id: string; action: string; payload?: Record<string, any> }) =>
      alertsApi.executeAction(id, action, payload),
    onSuccess: (_, { action }) => {
      qc.invalidateQueries({ queryKey: ['alerts'] });
      if (action === 'escalate') setRowEscalateAlertId(null);
      if (action === 'assign' || action === 'unassign') setRowAssignAlertId(null);
      const labels: Record<string, string> = {
        investigate: 'Investigation started — alert assigned to you',
        resolve: 'Alert resolved',
        false_positive: 'Alert dismissed as false positive',
        escalate: 'Alert escalated',
        assign: 'Alert assigned',
        unassign: 'Assignment cleared',
        reopen: 'Alert re-opened',
      };
      showToast(labels[action] ?? `Action "${action}" completed`);
    },
    onError: (err: any) => {
      const msg = err?.response?.data?.error || 'Action failed';
      showToast(msg);
    },
  });

  // Convenience wrappers that delegate to the unified mutation
  const statusMutation = {
    mutate: ({ id, status }: { id: string; status: AlertStatus }) => {
      const actionMap: Record<string, string> = {
        investigating: 'investigate', resolved: 'resolve', false_positive: 'false_positive', new: 'reopen',
      };
      actionMutation.mutate({ id, action: actionMap[status] ?? status });
    },
    isPending: actionMutation.isPending,
  };

  const investigateMutation = {
    mutate: (id: string) => actionMutation.mutate({ id, action: 'investigate' }),
    isPending: actionMutation.isPending,
  };

  const escalateMutation = {
    mutate: ({ id, targetId, reason }: { id: string; targetId: string; reason: string }) =>
      actionMutation.mutate({ id, action: 'escalate', payload: { escalateTo: targetId, reason } }),
    isPending: actionMutation.isPending,
  };

  const assignMutation = {
    mutate: ({ id, userId }: { id: string; userId: string }) =>
      actionMutation.mutate({ id, action: 'assign', payload: { assignedTo: userId } }),
    isPending: actionMutation.isPending,
  };

  const clearAssignMutation = {
    mutate: (id: string) => actionMutation.mutate({ id, action: 'unassign' }),
    isPending: actionMutation.isPending,
  };

  const { data: escalationTargets } = useQuery({
    queryKey: ['escalation-targets'],
    queryFn: () => usersApi.escalationTargets().then(r => r.data.targets),
    enabled: canTriage || canClose,
  });

  const bulkMutation = useMutation({
    mutationFn: ({ ids, status }: { ids: string[]; status: AlertStatus }) => alertsApi.bulkUpdate(ids, status),
    onSuccess: (_, { status }) => {
      qc.invalidateQueries({ queryKey: ['alerts'] });
      setSelectedIds(new Set());
      showToast(`${selectedIds.size} alerts set to "${status.replace('_', ' ')}"`);
    },
  });

  /* ── Handlers ── */

  const toggleSelect = (id: string) => {
    setSelectedIds(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; });
  };
  const selectAll = () => setSelectedIds(new Set(alerts.map(a => a.id)));
  const clearSelection = () => setSelectedIds(new Set());
  const isAllSelected = alerts.length > 0 && alerts.every(a => selectedIds.has(a.id));

  const bulkUpdate = (status: AlertStatus) => {
    if (selectedIds.size === 0) return;
    const configs: Record<string, { variant: ConfirmVariant; title: string; description: string; confirmLabel: string; requireComment: boolean }> = {
      investigating: { variant: 'warn', title: 'Bulk: Set Investigating', description: `Set ${selectedIds.size} alert(s) to Investigating.`, confirmLabel: 'Investigate All', requireComment: false },
      resolved: { variant: 'info', title: 'Bulk: Resolve Alerts', description: `Resolve ${selectedIds.size} alert(s). Provide resolution notes.`, confirmLabel: 'Resolve All', requireComment: true },
      false_positive: { variant: 'destructive', title: 'Bulk: Mark False Positive', description: `Dismiss ${selectedIds.size} alert(s) as false positives.`, confirmLabel: 'Dismiss All', requireComment: true },
    };
    const cfg = configs[status];
    if (cfg) {
      setBulkConfirm({ open: true, status, ...cfg });
    } else {
      bulkMutation.mutate({ ids: Array.from(selectedIds), status });
    }
  };

  const handleBulkConfirm = () => {
    bulkMutation.mutate({ ids: Array.from(selectedIds), status: bulkConfirm.status });
    setBulkConfirm(prev => ({ ...prev, open: false }));
  };

  const bulkAssign = (userId: string) => {
    selectedIds.forEach(id => assignMutation.mutate({ id, userId }));
    setSelectedIds(new Set());
    setBulkAssignOpen(false);
    showToast(`Assigning ${selectedIds.size} alert(s)`);
  };

  const [quickConfirm, setQuickConfirm] = useState<{
    open: boolean; id: string; status: AlertStatus; variant: ConfirmVariant;
    title: string; description: string; confirmLabel: string; requireComment: boolean;
  }>({ open: false, id: '', status: 'new', variant: 'info', title: '', description: '', confirmLabel: 'Confirm', requireComment: false });

  const handleQuickAction = (e: React.MouseEvent, id: string, status: AlertStatus) => {
    e.preventDefault(); e.stopPropagation();
    const configs: Record<string, { variant: ConfirmVariant; title: string; description: string; confirmLabel: string; requireComment: boolean }> = {
      investigating: { variant: 'warn', title: 'Start Investigation', description: 'Set this alert to Investigating and signal active triage.', confirmLabel: 'Investigate', requireComment: false },
      resolved: { variant: 'info', title: 'Resolve Alert', description: 'Mark this alert as resolved. Provide resolution notes.', confirmLabel: 'Resolve', requireComment: true },
      false_positive: { variant: 'destructive', title: 'Mark as False Positive', description: 'Dismiss this alert as a false positive. Provide justification.', confirmLabel: 'Dismiss', requireComment: true },
    };
    const cfg = configs[status];
    if (cfg) {
      setQuickConfirm({ open: true, id, status, ...cfg });
    } else {
      statusMutation.mutate({ id, status });
    }
  };

  const handleQuickConfirm = (comment?: string) => {
    if (comment) alertsApi.addNote(quickConfirm.id, comment, 'note');
    if (quickConfirm.status === 'investigating') {
      investigateMutation.mutate(quickConfirm.id);
    } else {
      statusMutation.mutate({ id: quickConfirm.id, status: quickConfirm.status });
    }
    setQuickConfirm(prev => ({ ...prev, open: false }));
  };

  const getAssigneeName = (assigneeId: string | undefined) => {
    if (!assigneeId) return undefined;
    const u = analysts.find((a: any) => a.id === assigneeId);
    return u?.displayName || u?.username || assigneeId.slice(0, 8);
  };

  const exportCsv = () => {
    if (alerts.length === 0) return;
    const headers = ['ID', 'Title', 'Severity', 'Status', 'MITRE IDs', 'Created', 'Assignee', 'Rule'];
    const rows = alerts.map((a: any) => [
      a.id,
      `"${(a.title ?? '').replace(/"/g, '""')}"`,
      a.severity,
      a.status,
      (a.mitreIds ?? []).join('; '),
      a.createdAt.toISOString(),
      getAssigneeName(a.assignee) ?? '',
      a.ruleName ?? '',
    ]);
    const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `alerts-${format(new Date(), 'yyyy-MM-dd-HHmmss')}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const hasActiveFilters = severityFilter !== 'all' || timeRange !== '' || searchTerm.length >= 2;

  const clearAllFilters = () => {
    setStatusFilter('all');
    setSeverityFilter('all');
    setSearchTerm('');
    setTimeRange('');
    setGroupBy('none');
    setSelectedIds(new Set());
  };

  /* ── Grouping ── */

  const groupedAlerts = useMemo(() => {
    if (groupBy === 'none') return null;
    const groups: Record<string, typeof alerts> = {};
    for (const a of alerts) {
      const key = groupBy === 'rule'
        ? (a.ruleName || 'Unknown Rule')
        : ((a.mitreIds ?? [])[0] || 'No MITRE');
      (groups[key] ??= []).push(a);
    }
    return Object.entries(groups).sort((a, b) => b[1].length - a[1].length);
  }, [alerts, groupBy]);

  /* ── Render ── */

  return (
    <>
      {/* Toast */}
      {toast && (
        <div className="fixed top-6 right-6 z-50 bg-card border border-primary/30 text-foreground px-4 py-3 rounded-xl shadow-2xl text-sm font-medium flex items-center gap-2 animate-in slide-in-from-top-4 duration-200">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" /> {toast}
        </div>
      )}

      <div className="flex flex-col gap-6 max-w-360 mx-auto">
        {/* ── Header & Stats ───────────────────────────────────────────── */}
        <div className="flex flex-col gap-5">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <h1 className="text-3xl font-bold tracking-tight text-foreground flex items-center gap-3">
                <ShieldAlert className="w-7 h-7 text-primary" /> Alert Queue
              </h1>
              <p className="text-muted-foreground mt-1 text-sm flex items-center gap-2">
                Triage and respond to security incidents
                {isFetching && !isLoading && (
                  <span className="flex items-center gap-1 text-primary text-xs">
                    <RefreshCw className="w-3 h-3 animate-spin" /> Syncing
                  </span>
                )}
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button onClick={() => refetch()}
                className="inline-flex items-center gap-1.5 px-3 py-2 text-sm font-medium rounded-xl border border-border bg-card hover:bg-secondary/80 text-muted-foreground hover:text-foreground transition-colors">
                <RefreshCw className="w-4 h-4" /> Refresh
              </button>
              <button onClick={exportCsv} disabled={alerts.length === 0}
                className="inline-flex items-center gap-1.5 px-3 py-2 text-sm font-medium rounded-xl border border-border bg-card hover:bg-secondary/80 text-foreground disabled:opacity-40 disabled:cursor-not-allowed transition-colors">
                <Download className="w-4 h-4" /> Export CSV
              </button>
            </div>
          </div>

          {/* Summary Cards */}
          <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
            <div className="bg-card border border-border rounded-xl p-4 shadow-sm">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Total</span>
                <ShieldAlert className="w-4 h-4 text-primary" />
              </div>
              <div className="text-2xl font-bold text-foreground">{counts.all}</div>
            </div>
            {(['critical', 'high', 'medium', 'low'] as const).map(sev => {
              const sc = SEVERITY_COLORS[sev];
              return (
                <button key={sev} onClick={() => setSeverityFilter(severityFilter === sev ? 'all' : sev)}
                  className={`bg-card border rounded-xl p-4 shadow-sm text-left transition-all ${
                    severityFilter === sev ? `${sc.bg} border-current/30 ring-2 ${sc.ring}` : 'border-border hover:border-border/80'
                  }`}>
                  <div className="flex items-center justify-between mb-2">
                    <span className={`text-xs font-medium uppercase tracking-wider ${sc.text}`}>{sev}</span>
                    <div className={`w-2.5 h-2.5 rounded-full ${sc.bar}`} />
                  </div>
                  <div className={`text-2xl font-bold ${severityCounts[sev] > 0 ? sc.text : 'text-muted-foreground/30'}`}>
                    {severityCounts[sev]}
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* ── Status Tabs ──────────────────────────────────────────────── */}
        <div className="flex items-center gap-1 bg-secondary/30 p-1.5 rounded-xl border border-border w-fit flex-wrap">
          {(['all', ...STATUSES] as const).map(f => {
            const si = STATUS_ICONS[f] || STATUS_ICONS.all;
            const Icon = si.icon;
            return (
              <button
                key={f}
                onClick={() => { setStatusFilter(f); setSelectedIds(new Set()); }}
                className={`px-3.5 py-2 rounded-lg text-sm font-medium transition-all flex items-center gap-2 ${
                  statusFilter === f
                    ? 'bg-card text-foreground shadow-sm border border-border/50'
                    : 'text-muted-foreground hover:text-foreground'
                }`}>
                <Icon className={`w-3.5 h-3.5 ${statusFilter === f ? si.color : ''}`} />
                <span className="hidden sm:inline">{f.replace('_', ' ').replace(/^\w/, c => c.toUpperCase())}</span>
                <span className={`text-xs px-1.5 py-0.5 rounded-full font-bold ${
                  statusFilter === f ? 'bg-primary/15 text-primary' : 'bg-secondary text-muted-foreground'
                }`}>
                  {counts[f as keyof typeof counts] ?? 0}
                </span>
              </button>
            );
          })}
        </div>

        {/* ── Filter Bar ───────────────────────────────────────────────── */}
        <div className="flex gap-3 flex-wrap items-center">
          <div className="relative flex-1 min-w-64">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
            <input
              type="text"
              placeholder="Search by title, rule, technique, IP…"
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
              className="w-full bg-input border border-border rounded-xl pl-10 pr-4 py-2.5 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary/30 focus:border-primary transition-all"
            />
            {searchTerm && (
              <button onClick={() => setSearchTerm('')} title="Clear search" className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
                <X className="w-4 h-4" />
              </button>
            )}
          </div>
          <select
            aria-label="Filter by severity"
            value={severityFilter}
            onChange={e => { setSeverityFilter(e.target.value); setSelectedIds(new Set()); }}
            className="bg-input border border-border rounded-xl px-3 py-2.5 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary/30 appearance-none pr-8"
          >
            <option value="all">All Severities</option>
            {SEVERITIES.map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
          </select>
          <div className="relative">
            <CalendarDays className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground pointer-events-none" />
            <select
              aria-label="Filter by time range"
              value={timeRange}
              onChange={e => { setTimeRange(e.target.value); setSelectedIds(new Set()); }}
              className="bg-input border border-border rounded-xl pl-9 pr-8 py-2.5 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary/30 appearance-none"
            >
              {TIME_RANGES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
            </select>
          </div>
          <div className="relative">
            <Layers className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground pointer-events-none" />
            <select
              aria-label="Group alerts by"
              value={groupBy}
              onChange={e => setGroupBy(e.target.value as GroupBy)}
              className="bg-input border border-border rounded-xl pl-9 pr-8 py-2.5 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary/30 appearance-none"
            >
              <option value="none">No Grouping</option>
              <option value="rule">Group by Rule</option>
              <option value="mitre">Group by MITRE</option>
            </select>
          </div>
          {hasActiveFilters && (
            <button onClick={clearAllFilters}
              className="flex items-center gap-1.5 px-3 py-2.5 text-xs font-medium text-muted-foreground hover:text-foreground bg-secondary border border-border rounded-xl transition-colors">
              <Filter className="w-3.5 h-3.5" /> Clear Filters
            </button>
          )}
        </div>

        {/* ── Active Filter Tags ── */}
        {hasActiveFilters && (
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs text-muted-foreground">Active filters:</span>
            {severityFilter !== 'all' && (
              <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-lg text-xs font-medium ${SEVERITY_COLORS[severityFilter]?.bg || ''} ${SEVERITY_COLORS[severityFilter]?.text || ''} border border-current/20`}>
                {severityFilter}
                <button onClick={() => setSeverityFilter('all')} title="Remove severity filter" className="hover:opacity-70"><X className="w-3 h-3" /></button>
              </span>
            )}
            {timeRange && (
              <span className="inline-flex items-center gap-1 px-2 py-1 rounded-lg text-xs font-medium bg-primary/10 text-primary border border-primary/20">
                {TIME_RANGES.find(t => t.value === timeRange)?.label}
                <button onClick={() => setTimeRange('')} title="Remove time filter" className="hover:opacity-70"><X className="w-3 h-3" /></button>
              </span>
            )}
            {searchTerm.length >= 2 && (
              <span className="inline-flex items-center gap-1 px-2 py-1 rounded-lg text-xs font-medium bg-secondary border border-border text-foreground">
                "{searchTerm}"
                <button onClick={() => setSearchTerm('')} title="Remove search filter" className="hover:opacity-70"><X className="w-3 h-3" /></button>
              </span>
            )}
          </div>
        )}

        {/* ── Alert Table ──────────────────────────────────────────────── */}
        <div className="bg-card border border-border rounded-xl shadow-lg shadow-black/10 flex flex-col overflow-hidden">
          {/* Bulk Action Bar */}
          {selectedIds.size > 0 && (
            <div className="px-4 py-3 bg-primary/5 border-b border-primary/20 flex items-center gap-4 text-sm">
              <div className="flex items-center gap-2">
                <div className="w-6 h-6 rounded-full bg-primary/20 flex items-center justify-center text-xs font-bold text-primary">
                  {selectedIds.size}
                </div>
                <span className="text-primary font-medium">selected</span>
              </div>
              <div className="flex gap-2 ml-auto flex-wrap">
                {canTriage && (
                  <button onClick={() => bulkUpdate('investigating')}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-amber-500/10 text-amber-400 border border-amber-500/20 rounded-lg hover:bg-amber-500/20 transition-colors text-xs font-medium">
                    <Play className="w-3.5 h-3.5" /> Investigate
                  </button>
                )}
                {canClose && (
                  <>
                    <button onClick={() => bulkUpdate('resolved')}
                      className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded-lg hover:bg-emerald-500/20 transition-colors text-xs font-medium">
                      <CheckCircle2 className="w-3.5 h-3.5" /> Resolve
                    </button>
                    <button onClick={() => bulkUpdate('false_positive')}
                      className="flex items-center gap-1.5 px-3 py-1.5 bg-secondary text-muted-foreground border border-border rounded-lg hover:bg-secondary/80 transition-colors text-xs font-medium">
                      <XCircle className="w-3.5 h-3.5" /> False Positive
                    </button>
                  </>
                )}
                {canAssign && analysts.length > 0 && (
                  <button
                    onClick={() => setBulkAssignOpen(true)}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-primary/10 text-primary border border-primary/20 rounded-lg hover:bg-primary/20 transition-colors text-xs font-medium">
                    <UserCheck className="w-3.5 h-3.5" /> Assign
                  </button>
                )}
                <button onClick={clearSelection} className="text-xs text-muted-foreground hover:text-foreground px-2 py-1.5 hover:bg-secondary rounded-lg transition-colors">
                  Clear
                </button>
              </div>
            </div>
          )}

          <div className="overflow-x-auto">
            {isError ? (
              <div className="flex flex-col items-center justify-center py-20 gap-4 text-center">
                <div className="w-14 h-14 rounded-full bg-destructive/10 flex items-center justify-center">
                  <AlertTriangle className="w-7 h-7 text-destructive" />
                </div>
                <p className="text-sm text-muted-foreground">Failed to load alerts</p>
                <button onClick={() => refetch()} className="text-sm text-primary hover:underline font-medium">Try again</button>
              </div>
            ) : isLoading ? (
              <div className="flex items-center justify-center py-20 gap-3 text-muted-foreground">
                <Loader2 className="w-6 h-6 animate-spin text-primary" /> Loading alerts…
              </div>
            ) : alerts.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-20 gap-4">
                <div className="w-16 h-16 rounded-full bg-secondary flex items-center justify-center">
                  <ShieldAlert className="w-8 h-8 text-muted-foreground/30" />
                </div>
                <p className="text-sm text-muted-foreground">No alerts match your current filters</p>
                {hasActiveFilters && (
                  <button onClick={clearAllFilters} className="text-sm text-primary hover:underline font-medium flex items-center gap-1">
                    <X className="w-3.5 h-3.5" /> Clear all filters
                  </button>
                )}
              </div>
            ) : (
              <table className="w-full text-sm text-left">
                <thead className="text-[10px] text-muted-foreground bg-secondary/30 border-b border-border uppercase tracking-wider">
                  <tr>
                    <th className="pl-2 pr-1 py-3 w-8">
                      <button onClick={isAllSelected ? clearSelection : selectAll} className="text-muted-foreground hover:text-foreground p-1">
                        {isAllSelected ? <CheckSquare className="w-4 h-4 text-primary" /> : <Square className="w-4 h-4" />}
                      </button>
                    </th>
                    <th className="px-3 py-3 font-medium">Alert</th>
                    <th className="px-3 py-3 font-medium">Severity</th>
                    <th className="px-3 py-3 font-medium">Status</th>
                    <th className="px-3 py-3 font-medium">MITRE</th>
                    <th className="px-3 py-3 font-medium">Threat Score</th>
                    <th className="px-3 py-3 font-medium">Created</th>
                    <th className="px-3 py-3 font-medium">Assignee</th>
                    <th className="px-3 py-3 font-medium text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/30">
                  {groupedAlerts ? (
                    groupedAlerts.map(([groupLabel, groupAlerts]) => (
                      <React.Fragment key={groupLabel}>
                        <tr className="bg-secondary/40">
                          <td colSpan={9} className="px-4 py-2.5">
                            <div className="flex items-center gap-2 text-xs font-semibold text-foreground">
                              <Layers className="w-3.5 h-3.5 text-primary" />
                              {groupLabel}
                              <span className="ml-1 text-muted-foreground font-normal px-1.5 py-0.5 bg-secondary rounded-full text-[10px]">
                                {groupAlerts.length}
                              </span>
                            </div>
                          </td>
                        </tr>
                        {groupAlerts.map(alert => (
                          <AlertRow key={alert.id} alert={alert} assigneeName={getAssigneeName(alert.assignee)}
                            selectedIds={selectedIds} toggleSelect={toggleSelect}
                            currentUserId={currentUserId}
                            handleQuickAction={handleQuickAction}
                            onAssign={id => setRowAssignAlertId(id)}
                            onEscalate={id => setRowEscalateAlertId(id)} />
                        ))}
                      </React.Fragment>
                    ))
                  ) : (
                    alerts.map(alert => (
                      <AlertRow key={alert.id} alert={alert} assigneeName={getAssigneeName(alert.assignee)}
                        selectedIds={selectedIds} toggleSelect={toggleSelect}
                        currentUserId={currentUserId}
                        handleQuickAction={handleQuickAction}
                        onAssign={id => setRowAssignAlertId(id)}
                        onEscalate={id => setRowEscalateAlertId(id)} />
                    ))
                  )}
                </tbody>
              </table>
            )}
          </div>

          {/* Footer */}
          <div className="px-4 py-3 border-t border-border bg-secondary/20 text-xs text-muted-foreground flex items-center justify-between">
            <div className="flex items-center gap-2">
              Showing <span className="text-foreground font-medium">{alerts.length}</span> of <span className="text-foreground font-medium">{data?.total ?? 0}</span> alerts
              {groupedAlerts && <span className="text-primary">• {groupedAlerts.length} group{groupedAlerts.length !== 1 ? 's' : ''}</span>}
            </div>
            <div className="flex items-center gap-1.5 text-primary">
              <Activity className="w-3 h-3" />
              <span>Auto-refresh 30s</span>
            </div>
          </div>
        </div>
      </div>

      {/* Bulk action confirmation */}
      <ActionConfirmDialog
        open={bulkConfirm.open}
        onOpenChange={open => setBulkConfirm(prev => ({ ...prev, open }))}
        variant={bulkConfirm.variant}
        title={bulkConfirm.title}
        description={bulkConfirm.description}
        entities={`${selectedIds.size} alert${selectedIds.size === 1 ? '' : 's'}`}
        confirmLabel={bulkConfirm.confirmLabel}
        requireComment={bulkConfirm.requireComment}
        isPending={bulkMutation.isPending}
        onConfirm={handleBulkConfirm}
      />

      {/* Per-row Assign Dialog */}
      <AssignDialog
        open={!!rowAssignAlertId}
        onOpenChange={o => { if (!o) setRowAssignAlertId(null); }}
        users={analysts.map((a: any) => ({
          id: a.id,
          username: a.username,
          displayName: a.displayName,
          role: a.role,
          status: a.status,
        }))}
        currentAssigneeId={rowAssignAlertId ? alerts.find(a => a.id === rowAssignAlertId)?.assignee : undefined}
        alertTitle={rowAssignAlertId ? alerts.find(a => a.id === rowAssignAlertId)?.title : undefined}
        isPending={assignMutation.isPending}
        onAssign={(userId) => {
          if (rowAssignAlertId) assignMutation.mutate({ id: rowAssignAlertId, userId });
        }}
        onClearAssignment={() => {
          if (rowAssignAlertId) clearAssignMutation.mutate(rowAssignAlertId);
        }}
        isClearPending={clearAssignMutation.isPending}
      />

      {/* Per-row Escalate Dialog */}
      <EscalateDialog
        open={!!rowEscalateAlertId}
        onOpenChange={o => { if (!o) setRowEscalateAlertId(null); }}
        targets={(escalationTargets ?? []).map((u: any) => ({
          id: u.id,
          username: u.username,
          displayName: u.displayName,
          role: u.role,
        }))}
        currentAssigneeRole={(() => {
          if (!rowEscalateAlertId) return undefined;
          const al = alerts.find(a => a.id === rowEscalateAlertId);
          if (!al?.assignee) return undefined;
          const assignee = analysts.find((a: any) => a.id === al.assignee);
          return assignee?.role;
        })()}
        alertTitle={rowEscalateAlertId ? alerts.find(a => a.id === rowEscalateAlertId)?.title : undefined}
        isPending={escalateMutation.isPending}
        onEscalate={(targetId, reason) => {
          if (rowEscalateAlertId) escalateMutation.mutate({ id: rowEscalateAlertId, targetId, reason });
        }}
      />

      {/* Bulk Assign Dialog */}
      <AssignDialog
        open={bulkAssignOpen}
        onOpenChange={setBulkAssignOpen}
        users={analysts.map((a: any) => ({
          id: a.id,
          username: a.username,
          displayName: a.displayName,
          role: a.role,
          status: a.status,
        }))}
        alertTitle={`${selectedIds.size} alert${selectedIds.size === 1 ? '' : 's'}`}
        isPending={assignMutation.isPending}
        onAssign={(userId) => bulkAssign(userId)}
      />

      {/* Per-row Quick Action Confirm Dialog */}
      <ActionConfirmDialog
        open={quickConfirm.open}
        onOpenChange={open => setQuickConfirm(prev => ({ ...prev, open }))}
        variant={quickConfirm.variant}
        title={quickConfirm.title}
        description={quickConfirm.description}
        entities="1 alert"
        confirmLabel={quickConfirm.confirmLabel}
        requireComment={quickConfirm.requireComment}
        isPending={statusMutation.isPending || investigateMutation.isPending}
        onConfirm={handleQuickConfirm}
      />
    </>
  );
}
