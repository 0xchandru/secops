import React, { useState, useMemo, useCallback, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { alertsApi, usersApi, normalizeAlert, threatlensApi } from '@/lib/api';
import type { ThreatLensResult } from '@/lib/api';
import { useAuthStore } from '@/store/authStore';
import { safeFormat, timeAgo } from '@/lib/date-utils';
import { actionsFromBackend } from '@/lib/alert-actions';
import type { AlertAction } from '@/lib/alert-actions';

import { SeverityBadge, StatusBadge } from '@/components/ui/Badge';
import { useRoute, Link } from 'wouter';
import {
  ArrowLeft, Bot, Target, Clock, CheckCircle2, XCircle, AlertTriangle,
  UserPlus, TrendingUp, MessageSquare, Shield, Lock, Loader2,
  FileSearch, Activity, ListTree, Server, Globe, Terminal, Tag, Cpu, Network,
  ChevronDown, ChevronUp, Fingerprint, Copy, ExternalLink,
  Eye, Zap, BarChart3, Play, Bell, Gauge, Search
} from 'lucide-react';
import type { AlertStatus } from '@/lib/types';
import ActionConfirmDialog from '@/components/ui/ActionConfirmDialog';
import type { ConfirmVariant } from '@/components/ui/ActionConfirmDialog';
import AssetDetailDialog from '@/components/ui/AssetDetailDialog';
import RuleDetailDialog from '@/components/ui/RuleDetailDialog';
import AssignDialog from '@/components/ui/AssignDialog';
import EscalateDialog from '@/components/ui/EscalateDialog';
import { ROLE_LABELS, ROLE_COLORS, ROLE_HIERARCHY } from '@/lib/constants';
import { format, isValid } from 'date-fns';

/* ─── Constants ──────────────────────────────────────────────────────────── */

const TABS = [
  { id: 'overview',       label: 'Overview',          icon: Eye },
  { id: 'evidence',       label: 'Evidence',          icon: FileSearch },
  { id: 'investigation',  label: 'Investigation',     icon: Zap },
  { id: 'timeline',       label: 'Timeline',          icon: Clock },
  { id: 'related',        label: 'Related Events',    icon: ListTree },
] as const;
type TabId = (typeof TABS)[number]['id'];

const CHECKLIST_ITEMS = [
  { label: 'Review the triggering event in the Logs Explorer', priority: 'high' },
  { label: 'Examine affected host for lateral movement indicators', priority: 'high' },
  { label: 'Check user account activity for anomalies', priority: 'medium' },
  { label: 'Identify all network connections from source IP', priority: 'medium' },
  { label: 'Search for related alerts in the last 24 hours', priority: 'medium' },
  { label: 'Document IOCs and add to threat intelligence feed', priority: 'low' },
  { label: 'Determine blast radius of potential compromise', priority: 'high' },
  { label: 'Escalate if external compromise is confirmed', priority: 'low' },
];

const SEVERITY_COLORS: Record<string, { bg: string; border: string; text: string; glow: string; bar: string }> = {
  critical: { bg: 'bg-red-500/5', border: 'border-red-500/30', text: 'text-red-400', glow: 'shadow-red-500/10', bar: 'bg-red-500' },
  high:     { bg: 'bg-orange-500/5', border: 'border-orange-500/30', text: 'text-orange-400', glow: 'shadow-orange-500/10', bar: 'bg-orange-500' },
  medium:   { bg: 'bg-yellow-500/5', border: 'border-yellow-500/30', text: 'text-yellow-400', glow: 'shadow-yellow-500/10', bar: 'bg-yellow-500' },
  low:      { bg: 'bg-green-500/5', border: 'border-green-500/30', text: 'text-green-400', glow: 'shadow-green-500/10', bar: 'bg-green-500' },
  info:     { bg: 'bg-indigo-500/5', border: 'border-indigo-500/30', text: 'text-indigo-400', glow: 'shadow-indigo-500/10', bar: 'bg-indigo-500' },
};

const STATUS_FLOW: Record<string, { icon: React.ElementType; color: string }> = {
  new:            { icon: Bell, color: 'text-blue-400' },
  investigating:  { icon: Search, color: 'text-amber-400' },
  escalated:      { icon: TrendingUp, color: 'text-red-400' },
  resolved:       { icon: CheckCircle2, color: 'text-emerald-400' },
  false_positive: { icon: XCircle, color: 'text-gray-400' },
};

/* ─── IOC Extraction ─────────────────────────────────────────────────────── */

const IP_RE = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|info|biz|dev|co|gov|edu|mil|int|xyz|top|app|cloud)\b/gi;
const MD5_RE = /\b[a-f0-9]{32}\b/gi;
const SHA256_RE = /\b[a-f0-9]{64}\b/gi;
const SHA1_RE = /\b[a-f0-9]{40}\b/gi;

function extractIOCs(obj: Record<string, unknown>): { type: string; value: string }[] {
  const text = JSON.stringify(obj);
  const seen = new Set<string>();
  const iocs: { type: string; value: string }[] = [];
  const add = (type: string, value: string) => {
    const key = `${type}:${value.toLowerCase()}`;
    if (!seen.has(key)) { seen.add(key); iocs.push({ type, value }); }
  };
  for (const m of text.matchAll(SHA256_RE)) add('SHA-256', m[0]);
  for (const m of text.matchAll(SHA1_RE)) if (!m[0].match(/^[a-f0-9]{64}$/i)) add('SHA-1', m[0]);
  for (const m of text.matchAll(MD5_RE)) if (!m[0].match(/^[a-f0-9]{40}$/i) && !m[0].match(/^[a-f0-9]{64}$/i)) add('MD5', m[0]);
  for (const m of text.matchAll(IP_RE)) {
    if (!m[0].startsWith('0.') && !m[0].startsWith('127.') && m[0] !== '255.255.255.255') add('IP', m[0]);
  }
  for (const m of text.matchAll(DOMAIN_RE)) add('Domain', m[0]);
  return iocs;
}

/* ─── Component ──────────────────────────────────────────────────────────── */

export default function AlertDetailPage() {
  const [, params] = useRoute('/alerts/:id');
  const qc = useQueryClient();
  const { can, user: authUser } = useAuthStore();
  const [note, setNote] = useState('');
  const [toast, setToast] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabId>('overview');
  const [expandedEvent, setExpandedEvent] = useState<string | null>(null);
  const [confirmDialog, setConfirmDialog] = useState<{
    open: boolean; status: AlertStatus; variant: ConfirmVariant;
    title: string; description: string; confirmLabel: string; requireComment: boolean;
  }>({ open: false, status: 'new', variant: 'info', title: '', description: '', confirmLabel: 'Confirm', requireComment: false });
  const [escalateOpen, setEscalateOpen] = useState(false);
  const [assetLookup, setAssetLookup] = useState<{ hostname?: string; ip?: string } | null>(null);
  const [showRuleDialog, setShowRuleDialog] = useState(false);
  const [assignDialogOpen, setAssignDialogOpen] = useState(false);
  const [copiedId, setCopiedId] = useState(false);
  const [timelineFilter, setTimelineFilter] = useState<string>('all');

  // Persistent checklist state (per alert)
  const checklistKey = `checklist:${params?.id}`;
  const [checkedItems, setCheckedItems] = useState<boolean[]>(() => {
    try { return JSON.parse(localStorage.getItem(checklistKey) ?? '[]'); } catch { return []; }
  });
  useEffect(() => {
    if (checkedItems.length > 0) localStorage.setItem(checklistKey, JSON.stringify(checkedItems));
  }, [checkedItems, checklistKey]);
  const toggleChecklist = useCallback((i: number) => {
    setCheckedItems(prev => { const next = [...prev]; next[i] = !next[i]; return next; });
  }, []);

  const canTriage = can('alerts:triage');
  const canClose = can('alerts:close');
  const canAssign = can('alerts:assign');
  const canNote = can('alerts:note');
  const alertId = params?.id;

  /* ─── Queries ──────────────────────────────────────────────────────────── */

  const { data: alertRaw, isLoading, isError, refetch } = useQuery({
    queryKey: ['alert', alertId],
    queryFn: () => alertsApi.getById(alertId!).then(r => r.data.alert),
    enabled: !!alertId,
  });

  const { data: usersData } = useQuery({
    queryKey: ['users'],
    queryFn: () => usersApi.list().then(r => r.data.users),
    enabled: canAssign,
  });

  const { data: relatedEventsData, isLoading: relatedLoading } = useQuery({
    queryKey: ['alert-related', alertId],
    queryFn: () => alertsApi.relatedEvents(alertId!, 10, 5).then(r => r.data),
    enabled: !!alertId && (activeTab === 'related' || activeTab === 'overview'),
  });

  const analysts = useMemo(() =>
    (usersData ?? []).filter((u: any) => u.status === 'active' && u.role !== 'viewer'),
    [usersData]
  );

  const alert = useMemo(() => alertRaw ? normalizeAlert(alertRaw) : null, [alertRaw]);

  const showToast = useCallback((msg: string) => { setToast(msg); setTimeout(() => setToast(null), 3000); }, []);

  /* ─── Backend-driven Actions Query ──────────────────────────────────── */

  const { data: backendActions } = useQuery({
    queryKey: ['alert-actions', alertId],
    queryFn: () => alertsApi.getActions(alertId!).then(r => r.data.actions as AlertAction[]),
    enabled: !!alertId,
  });

  /* ─── Unified Action Mutation ──────────────────────────────────────── */

  const actionMutation = useMutation({
    mutationFn: ({ action, payload }: { action: string; payload?: Record<string, any> }) =>
      alertsApi.executeAction(alertId!, action, payload),
    onSuccess: (_, { action }) => {
      qc.invalidateQueries({ queryKey: ['alert', alertId] });
      qc.invalidateQueries({ queryKey: ['alert-actions', alertId] });
      qc.invalidateQueries({ queryKey: ['alerts'] });
      const labels: Record<string, string> = {
        investigate: 'Investigation started — alert assigned to you',
        resolve: 'Alert resolved',
        false_positive: 'Alert dismissed as false positive',
        escalate: 'Alert escalated',
        assign: 'Alert assigned',
        unassign: 'Assignment cleared',
        reopen: 'Alert re-opened',
        add_note: 'Note added to timeline',
      };
      showToast(labels[action] ?? `Action "${action}" completed`);
    },
    onError: (err: any) => {
      const msg = err?.response?.data?.error || 'Action failed';
      showToast(msg);
    },
  });

  // Convenience wrappers for backward-compatible handler calls
  const statusMutation = {
    mutate: (status: AlertStatus) => {
      const actionMap: Record<string, string> = {
        investigating: 'investigate', resolved: 'resolve', false_positive: 'false_positive', new: 'reopen',
      };
      actionMutation.mutate({ action: actionMap[status] ?? status });
    },
    isPending: actionMutation.isPending,
  };

  const investigateMutation = {
    mutate: () => actionMutation.mutate({ action: 'investigate' }),
    isPending: actionMutation.isPending,
  };

  const assignMutation = {
    mutate: (userId: string) => actionMutation.mutate({ action: 'assign', payload: { assignedTo: userId } }),
    isPending: actionMutation.isPending,
  };

  const noteMutation = {
    mutate: (content: string) => {
      actionMutation.mutate({ action: 'add_note', payload: { content, type: 'note' } });
      setNote('');
    },
    isPending: actionMutation.isPending,
  };

  const escalateMutation = {
    mutate: ({ targetId, reason }: { targetId: string; reason: string }) => {
      actionMutation.mutate({ action: 'escalate', payload: { escalateTo: targetId, reason } });
      setEscalateOpen(false);
    },
    isPending: actionMutation.isPending,
  };

  const clearAssignMutation = {
    mutate: () => actionMutation.mutate({ action: 'unassign' }),
    isPending: actionMutation.isPending,
  };

  const { data: escalationTargets } = useQuery({
    queryKey: ['escalation-targets', authUser?.role],
    queryFn: () => usersApi.escalationTargets(authUser?.role).then(r => r.data.targets),
    enabled: canTriage || canClose,
  });

  /* ─── Helpers ──────────────────────────────────────────────────────────── */

  const openStatusConfirm = (status: AlertStatus) => {
    const configs: Record<string, { variant: ConfirmVariant; title: string; description: string; confirmLabel: string; requireComment: boolean }> = {
      investigating: { variant: 'warn', title: 'Start Investigation', description: 'Set the alert to Investigating and signal active triage.', confirmLabel: 'Investigate', requireComment: false },
      resolved: { variant: 'info', title: 'Resolve Alert', description: 'Mark this alert as resolved. Provide resolution notes.', confirmLabel: 'Resolve', requireComment: true },
      false_positive: { variant: 'destructive', title: 'Mark as False Positive', description: 'Dismiss as false positive. Provide justification.', confirmLabel: 'Dismiss', requireComment: true },
      new: { variant: 'info', title: 'Re-open Alert', description: 'Set alert back to New for re-triage.', confirmLabel: 'Re-open', requireComment: false },
    };
    const cfg = configs[status];
    if (cfg) setConfirmDialog({ open: true, status, ...cfg });
  };

  const handleStatusConfirm = (comment?: string) => {
    if (comment) alertsApi.addNote(alertId!, comment, 'note');
    if (confirmDialog.status === 'investigating') {
      investigateMutation.mutate();
    } else {
      statusMutation.mutate(confirmDialog.status);
    }
    setConfirmDialog(prev => ({ ...prev, open: false }));
  };

  const getAssigneeName = (uuid: string | undefined) => {
    if (!uuid) return undefined;
    const u = analysts.find((a: any) => a.id === uuid);
    return u?.displayName || u?.username;
  };

  const copyAlertId = () => {
    if (!alertId) return;
    navigator.clipboard.writeText(alertId);
    setCopiedId(true);
    setTimeout(() => setCopiedId(false), 2000);
  };

  /* ─── Loading / Error ──────────────────────────────────────────────────── */

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64 gap-3 text-muted-foreground">
        <Loader2 className="w-6 h-6 animate-spin text-primary" /> Loading alert…
      </div>
    );
  }

  if (isError) {
    return (
      <div className="flex flex-col items-center justify-center h-64 gap-4">
        <AlertTriangle className="w-12 h-12 text-destructive opacity-50" />
        <p className="text-muted-foreground">Failed to load alert details</p>
        <button onClick={() => refetch()} className="text-sm text-primary hover:underline">Try again</button>
      </div>
    );
  }

  if (!alert) {
    return (
      <div className="flex flex-col items-center justify-center h-64 gap-4">
        <AlertTriangle className="w-12 h-12 text-muted-foreground opacity-30" />
        <p className="text-muted-foreground">Alert not found.</p>
        <Link href="/alerts" className="text-primary hover:underline text-sm">← Back to Queue</Link>
      </div>
    );
  }

  /* ─── Derived ──────────────────────────────────────────────────────────── */

  const assigneeId = alertRaw?.assignedTo;
  const assigneeName = getAssigneeName(assigneeId);
  const actions = actionsFromBackend(
    backendActions ?? [],
    assigneeId ?? null,
    authUser?.userId ?? ''
  );
  const ctx = alertRaw?.context ?? {};
  const relatedEvents = relatedEventsData?.events ?? [];
  const sevColor = SEVERITY_COLORS[alert.severity] || SEVERITY_COLORS.info;
  const iocs = extractIOCs({ ...(alertRaw?.context ?? {}), sourceIp: alertRaw?.sourceIp, destIp: alertRaw?.destIp, hostname: alertRaw?.hostname });
  const checklistProgress = checkedItems.filter(Boolean).length;
  const checklistTotal = CHECKLIST_ITEMS.length;

  const filteredTimeline = (() => {
    const events = [...alert.timeline].reverse();
    if (timelineFilter === 'all') return events;
    return events.filter(ev => {
      const e = ev as any;
      if (timelineFilter === 'notes') return e.type === 'note';
      if (timelineFilter === 'status') return e.type === 'status_change';
      if (timelineFilter === 'escalation') return e.type === 'escalation';
      if (timelineFilter === 'assignment') return e.type === 'assignment';
      return true;
    });
  })();

  /* ─── Render ───────────────────────────────────────────────────────────── */

  return (
    <>
      {/* Toast notification */}
      {toast && (
        <div className="fixed top-6 right-6 z-50 bg-card border border-primary/30 text-foreground px-4 py-3 rounded-xl shadow-2xl text-sm font-medium flex items-center gap-2 animate-in slide-in-from-top-4 duration-200">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" /> {toast}
        </div>
      )}

      <div className="flex flex-col gap-0 max-w-360 mx-auto">
        {/* Top nav */}
        <div className="flex items-center justify-between mb-4">
          <Link href="/alerts" className="text-muted-foreground hover:text-foreground flex items-center gap-2 text-sm transition-colors">
            <ArrowLeft className="w-4 h-4" /> Alert Queue
          </Link>
          <button onClick={copyAlertId} className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs text-muted-foreground hover:text-foreground bg-secondary border border-border rounded-lg transition-colors" title="Copy Alert ID">
            {copiedId ? <CheckCircle2 className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
            {copiedId ? 'Copied!' : alertId?.slice(0, 8)}
          </button>
        </div>

        {/* ── Severity-Themed Header Banner ──────────────────────────────── */}
        <div className={`${sevColor.bg} border ${sevColor.border} rounded-2xl p-6 mb-6 relative overflow-hidden shadow-lg ${sevColor.glow}`}>
          <div className={`absolute top-0 left-0 w-full h-1 ${sevColor.bar}`} />

          <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-3 flex-wrap">
                <span className="font-mono text-xs text-muted-foreground bg-background/80 px-2.5 py-1 rounded-md border border-border/50">
                  {alertRaw?.alertCode ?? alert.id.slice(0, 8)}
                </span>
                <SeverityBadge severity={alert.severity} />
                <StatusBadge status={alert.status} />
                {alertRaw?.mitreTechniqueId && (
                  <span className="px-2 py-0.5 rounded-md bg-purple-500/10 border border-purple-500/20 text-purple-400 text-xs font-mono font-medium">
                    {alertRaw.mitreTechniqueId}
                  </span>
                )}
              </div>

              <h1 className="text-2xl font-bold tracking-tight text-foreground mb-2">{alert.title}</h1>

              <div className="flex items-center gap-4 flex-wrap text-sm text-muted-foreground">
                <span className="flex items-center gap-1.5">
                  <Shield className="w-3.5 h-3.5 text-primary" />
                  Rule: {alertRaw?.ruleId ? (
                    <button onClick={() => setShowRuleDialog(true)} className="text-primary font-medium hover:underline">{alert.ruleName}</button>
                  ) : (
                    <span className="text-foreground font-medium">{alert.ruleName}</span>
                  )}
                </span>
                <span className="flex items-center gap-1.5">
                  <Clock className="w-3.5 h-3.5" />
                  {timeAgo(alert.createdAt)}
                </span>
                {alertRaw?.sourceHost && (
                  <span className="flex items-center gap-1.5">
                    <Server className="w-3.5 h-3.5" />
                    <button onClick={() => setAssetLookup({ hostname: alertRaw.sourceHost })} className="font-mono text-primary hover:underline">{alertRaw.sourceHost}</button>
                  </span>
                )}
                {assigneeName && (
                  <span className="flex items-center gap-1.5">
                    <UserPlus className="w-3.5 h-3.5" />
                    Assigned to <span className="text-foreground font-medium">{assigneeName}</span>
                  </span>
                )}
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex items-center gap-2 flex-wrap shrink-0">
              {actions.canInvestigate && (
                <button onClick={() => openStatusConfirm('investigating')} disabled={investigateMutation.isPending}
                  className="flex items-center gap-1.5 px-4 py-2.5 rounded-xl text-sm font-semibold border transition-all bg-amber-500/10 border-amber-500/30 text-amber-400 hover:bg-amber-500/20 hover:shadow-lg hover:shadow-amber-500/10">
                  <Play className="w-4 h-4" /> Investigate
                </button>
              )}
              {actions.canResolve && (
                <button onClick={() => openStatusConfirm('resolved')} disabled={statusMutation.isPending}
                  className="flex items-center gap-1.5 px-4 py-2.5 rounded-xl text-sm font-semibold border transition-all bg-emerald-500/10 border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/20 hover:shadow-lg hover:shadow-emerald-500/10">
                  <CheckCircle2 className="w-4 h-4" /> Resolve
                </button>
              )}
              {actions.canFalsePositive && (
                <button onClick={() => openStatusConfirm('false_positive')} disabled={statusMutation.isPending}
                  className="flex items-center gap-1.5 px-4 py-2.5 rounded-xl text-sm font-semibold border transition-all bg-secondary border-border text-muted-foreground hover:text-foreground hover:border-border/80">
                  <XCircle className="w-4 h-4" /> False Positive
                </button>
              )}
              {actions.canEscalate && (
                <button onClick={() => setEscalateOpen(true)} disabled={statusMutation.isPending}
                  className="flex items-center gap-1.5 px-4 py-2.5 bg-red-500/10 border border-red-500/30 text-red-400 rounded-xl text-sm font-semibold hover:bg-red-500/20 hover:shadow-lg hover:shadow-red-500/10 transition-all">
                  <TrendingUp className="w-4 h-4" /> Escalate
                </button>
              )}
              {actions.canReopen && (
                <button onClick={() => openStatusConfirm('new')} disabled={statusMutation.isPending}
                  className="flex items-center gap-1.5 px-4 py-2.5 rounded-xl text-sm font-semibold border transition-all bg-blue-500/10 border-blue-500/30 text-blue-400 hover:bg-blue-500/20">
                  Re-open
                </button>
              )}
              {actions.isReadOnly && alert.status === 'investigating' && !actions.isOwner && (
                <span className="flex items-center gap-1.5 px-4 py-2.5 rounded-xl text-sm font-medium bg-secondary border border-border text-muted-foreground">
                  <Lock className="w-3.5 h-3.5" /> Being investigated{assigneeName ? ` by ${assigneeName}` : ''}
                </span>
              )}
            </div>
          </div>

          {/* Status Flow */}
          <div className="flex items-center gap-1 mt-5 pt-4 border-t border-border/30">
            {Object.entries(STATUS_FLOW).map(([key, { icon: Icon, color }], i) => {
              const isActive = alert.status === key;
              const isPast = Object.keys(STATUS_FLOW).indexOf(alert.status) > i;
              return (
                <React.Fragment key={key}>
                  {i > 0 && <div className={`h-px flex-1 max-w-16 ${isPast ? 'bg-primary/50' : 'bg-border/50'}`} />}
                  <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium transition-all ${
                    isActive ? `${color} bg-background/60 border border-current/20 shadow-sm` : isPast ? 'text-primary/60' : 'text-muted-foreground/40'
                  }`}>
                    <Icon className="w-3 h-3" />
                    <span className="hidden sm:inline capitalize">{key.replace('_', ' ')}</span>
                  </div>
                </React.Fragment>
              );
            })}
          </div>
        </div>

        {/* ── Main Layout: Tabs + Sidebar ────────────────────────────────── */}
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
          {/* Left Content */}
          <div className="xl:col-span-9 flex flex-col gap-0">
            {/* Tab Bar */}
            <div className="flex items-center gap-1 border-b border-border mb-6 overflow-x-auto">
              {TABS.map(tab => (
                <button key={tab.id} onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-all -mb-px whitespace-nowrap ${
                    activeTab === tab.id ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground hover:border-border'
                  }`}>
                  <tab.icon className="w-4 h-4" />
                  {tab.label}
                  {tab.id === 'timeline' && alert.timeline.length > 0 && (
                    <span className="text-[10px] bg-primary/15 text-primary px-1.5 py-0.5 rounded-full font-bold">{alert.timeline.length}</span>
                  )}
                  {tab.id === 'related' && relatedEventsData && relatedEventsData.total > 0 && (
                    <span className="text-[10px] bg-primary/15 text-primary px-1.5 py-0.5 rounded-full font-bold">{relatedEventsData.total}</span>
                  )}
                  {tab.id === 'evidence' && iocs.length > 0 && (
                    <span className="text-[10px] bg-amber-500/15 text-amber-400 px-1.5 py-0.5 rounded-full font-bold">{iocs.length}</span>
                  )}
                  {tab.id === 'investigation' && checklistProgress > 0 && (
                    <span className="text-[10px] bg-emerald-500/15 text-emerald-400 px-1.5 py-0.5 rounded-full font-bold">{checklistProgress}/{checklistTotal}</span>
                  )}
                </button>
              ))}
            </div>

            {/* ─── Overview Tab ─────────────────────────────────────────── */}
            {activeTab === 'overview' && (
              <div className="space-y-6">
                {/* Threat Context */}
                <div className={`${sevColor.bg} border ${sevColor.border} rounded-xl p-5 relative overflow-hidden`}>
                  <div className={`absolute top-0 left-0 w-1 h-full ${sevColor.bar}`} />
                  <div className="flex items-center gap-2 mb-3">
                    <Bot className={`w-4 h-4 ${sevColor.text}`} />
                    <span className={`text-sm font-semibold uppercase tracking-wider ${sevColor.text}`}>Threat Context</span>
                  </div>
                  <p className="text-foreground leading-relaxed text-sm">{alert.description || 'No additional context available for this alert.'}</p>
                </div>

                {/* Stats */}
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                  <div className="bg-card border border-border rounded-xl p-4 shadow-sm">
                    <div className="flex items-center gap-2 mb-2">
                      <Gauge className={`w-4 h-4 ${sevColor.text}`} />
                      <span className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Severity</span>
                    </div>
                    <div className={`text-3xl font-bold ${sevColor.text}`}>
                      {alertRaw?.severityScore ?? '—'}<span className="text-sm text-muted-foreground font-normal">/100</span>
                    </div>
                  </div>
                  <div className="bg-card border border-border rounded-xl p-4 shadow-sm">
                    <div className="flex items-center gap-2 mb-2">
                      <ListTree className="w-4 h-4 text-primary" />
                      <span className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Related Events</span>
                    </div>
                    <div className="text-3xl font-bold text-foreground">{relatedEventsData?.total ?? '—'}</div>
                  </div>
                  <div className="bg-card border border-border rounded-xl p-4 shadow-sm">
                    <div className="flex items-center gap-2 mb-2">
                      <Fingerprint className="w-4 h-4 text-amber-400" />
                      <span className="text-xs text-muted-foreground font-medium uppercase tracking-wider">IOCs Found</span>
                    </div>
                    <div className="text-3xl font-bold text-foreground">{iocs.length}</div>
                  </div>
                  <div className="bg-card border border-border rounded-xl p-4 shadow-sm">
                    <div className="flex items-center gap-2 mb-2">
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      <span className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Checklist</span>
                    </div>
                    <div className="text-3xl font-bold text-foreground">
                      {checklistProgress}<span className="text-sm text-muted-foreground font-normal">/{checklistTotal}</span>
                    </div>
                    <div className="mt-2 h-1.5 bg-secondary rounded-full overflow-hidden">
                      <div className="h-full bg-emerald-500 rounded-full transition-all duration-300" style={{ width: `${(checklistProgress / checklistTotal) * 100}%` }} />
                    </div>
                  </div>
                </div>

                {/* MITRE ATT&CK */}
                {(alertRaw?.mitreTechniqueId || alert.mitreIds.length > 0) && (
                  <div className="bg-card border border-border rounded-xl p-5 shadow-sm">
                    <h3 className="text-sm font-semibold text-foreground mb-4 flex items-center gap-2">
                      <Target className="w-4 h-4 text-purple-400" /> MITRE ATT&CK Coverage
                    </h3>
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                      {alertRaw?.mitreTactic && (
                        <div className="bg-purple-500/5 border border-purple-500/20 rounded-lg p-3.5">
                          <div className="text-[10px] text-purple-400/70 uppercase tracking-wider mb-1 font-medium">Tactic</div>
                          <div className="text-sm text-foreground font-medium">{alertRaw.mitreTactic}</div>
                        </div>
                      )}
                      {alertRaw?.mitreTechniqueId && (
                        <div className="bg-purple-500/5 border border-purple-500/20 rounded-lg p-3.5">
                          <div className="text-[10px] text-purple-400/70 uppercase tracking-wider mb-1 font-medium">Technique</div>
                          <div className="font-mono text-purple-300 font-bold text-sm">{alertRaw.mitreTechniqueId}</div>
                          {alertRaw.mitreTechniqueName && <div className="text-xs text-muted-foreground mt-0.5">{alertRaw.mitreTechniqueName}</div>}
                        </div>
                      )}
                      {alertRaw?.mitreSubtechniqueId && (
                        <div className="bg-purple-500/5 border border-purple-500/20 rounded-lg p-3.5">
                          <div className="text-[10px] text-purple-400/70 uppercase tracking-wider mb-1 font-medium">Sub-technique</div>
                          <div className="font-mono text-purple-300 font-bold text-sm">{alertRaw.mitreSubtechniqueId}</div>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Event Context */}
                {Object.keys(ctx).length > 0 && (
                  <div className="bg-card border border-border rounded-xl p-5 shadow-sm">
                    <h3 className="text-sm font-semibold text-foreground mb-4 flex items-center gap-2">
                      <Activity className="w-4 h-4 text-primary" /> Event Context
                    </h3>
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                      {[
                        { icon: Network, color: 'text-blue-400', label: 'Source IP', value: ctx.srcIp, clickable: true, lookup: { ip: ctx.srcIp } },
                        { icon: Network, color: 'text-amber-400', label: 'Destination IP', value: ctx.dstIp, clickable: true, lookup: { ip: ctx.dstIp } },
                        { icon: Shield, color: 'text-purple-400', label: 'User', value: ctx.userName },
                        { icon: Cpu, color: 'text-cyan-400', label: 'Process', value: ctx.processName },
                        { icon: Globe, color: 'text-emerald-400', label: 'GeoIP', value: ctx.geoCountry ? `${ctx.geoCity ? ctx.geoCity + ', ' : ''}${ctx.geoCountry}` : null },
                        { icon: Server, color: 'text-orange-400', label: 'Hostname', value: alertRaw?.hostname || alertRaw?.sourceHost },
                      ].filter(f => f.value).map(field => (
                        <div key={field.label} className="flex items-center gap-3 p-3 bg-background/80 rounded-lg border border-border/50 group hover:border-primary/20 transition-colors">
                          <field.icon className={`w-4 h-4 ${field.color} shrink-0`} />
                          <div className="min-w-0 flex-1">
                            <div className="text-[10px] text-muted-foreground uppercase tracking-wider">{field.label}</div>
                            {field.clickable ? (
                              <button onClick={() => setAssetLookup(field.lookup as any)} className="font-mono text-sm text-primary hover:underline truncate block">{String(field.value)}</button>
                            ) : (
                              <div className="font-mono text-sm text-foreground truncate">{String(field.value)}</div>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                    {ctx.processCommandLine && (
                      <div className="mt-4">
                        <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1.5 font-medium flex items-center gap-1">
                          <Terminal className="w-3 h-3" /> Command Line
                        </div>
                        <pre className="text-xs font-mono bg-[#0a0e1a] border border-border rounded-lg p-3 text-green-400 overflow-x-auto whitespace-pre-wrap break-all">
                          {ctx.processCommandLine}
                        </pre>
                      </div>
                    )}
                  </div>
                )}

                {/* Affected Assets + Tags */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  {alert.affectedAssets.length > 0 && (
                    <div className="bg-card border border-border rounded-xl p-5 shadow-sm">
                      <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
                        <Server className="w-4 h-4 text-amber-400" /> Affected Assets
                        <span className="text-xs text-muted-foreground font-normal ml-auto">{alert.affectedAssets.length}</span>
                      </h3>
                      <div className="flex flex-wrap gap-2">
                        {alert.affectedAssets.map(asset => (
                          <button key={asset} onClick={() => setAssetLookup({ hostname: asset })} className="flex items-center gap-2 px-3 py-2 bg-background border border-border rounded-lg hover:border-primary/30 hover:bg-primary/5 transition-all group">
                            <div className="w-2 h-2 rounded-full bg-amber-500 shrink-0" />
                            <span className="font-mono text-sm text-foreground group-hover:text-primary">{asset}</span>
                            <ExternalLink className="w-3 h-3 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                  {alertRaw?.tags?.length > 0 && (
                    <div className="bg-card border border-border rounded-xl p-5 shadow-sm">
                      <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
                        <Tag className="w-4 h-4 text-primary" /> Tags
                      </h3>
                      <div className="flex flex-wrap gap-2">
                        {alertRaw.tags.map((tag: string) => (
                          <span key={tag} className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-primary/5 text-primary text-xs border border-primary/20 font-medium">
                            <Tag className="w-3 h-3" />{tag}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* ─── Evidence Tab ─────────────────────────────────────────── */}
            {activeTab === 'evidence' && (
              <div className="space-y-6">
                {/* IOCs */}
                <div className="bg-card border border-border rounded-xl shadow-sm overflow-hidden">
                  <div className="px-5 py-4 border-b border-border flex items-center justify-between">
                    <h3 className="text-sm font-semibold flex items-center gap-2">
                      <Fingerprint className="w-4 h-4 text-amber-400" /> Indicators of Compromise
                    </h3>
                    <span className="text-xs text-muted-foreground">{iocs.length} indicator{iocs.length !== 1 ? 's' : ''}</span>
                  </div>
                  {iocs.length === 0 ? (
                    <div className="p-8 text-center text-muted-foreground">
                      <Fingerprint className="w-8 h-8 mx-auto mb-2 opacity-20" />
                      <p className="text-sm">No IOCs automatically extracted from this alert.</p>
                    </div>
                  ) : (
                    <div className="divide-y divide-border/30">
                      {iocs.map(ioc => (
                        <div key={`${ioc.type}:${ioc.value}`} className="flex items-center gap-3 px-5 py-3 hover:bg-secondary/30 transition-colors group">
                          <span className={`text-[10px] px-2 py-0.5 rounded-md font-bold uppercase tracking-wider shrink-0 w-16 text-center ${
                            ioc.type === 'IP' ? 'bg-blue-500/10 border border-blue-500/20 text-blue-400' :
                            ioc.type === 'Domain' ? 'bg-purple-500/10 border border-purple-500/20 text-purple-400' :
                            'bg-amber-500/10 border border-amber-500/20 text-amber-400'
                          }`}>{ioc.type}</span>
                          <span className="font-mono text-sm text-foreground break-all flex-1">{ioc.value}</span>
                          <button
                            onClick={() => { navigator.clipboard.writeText(ioc.value); showToast(`Copied ${ioc.type}: ${ioc.value.slice(0, 20)}…`); }}
                            className="text-muted-foreground hover:text-primary opacity-0 group-hover:opacity-100 transition-all shrink-0 p-1.5 rounded-lg hover:bg-primary/10"
                            title="Copy to clipboard">
                            <Copy className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Raw Event Fields */}
                {Object.keys(ctx).length > 0 && (
                  <div className="bg-card border border-border rounded-xl p-5 shadow-sm">
                    <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
                      <Activity className="w-4 h-4 text-primary" /> Raw Event Fields
                    </h3>
                    <div className="bg-background rounded-lg border border-border/50 divide-y divide-border/30">
                      {Object.entries(ctx).filter(([, v]) => v != null && v !== '').map(([key, value]) => (
                        <div key={key} className="flex items-center px-4 py-2.5 hover:bg-secondary/20 transition-colors group">
                          <span className="text-xs text-muted-foreground font-mono w-48 shrink-0">{key}</span>
                          <span className="text-sm text-foreground font-mono flex-1 break-all">{String(value)}</span>
                          <button
                            onClick={() => { navigator.clipboard.writeText(String(value)); showToast(`Copied ${key}`); }}
                            className="text-muted-foreground hover:text-primary opacity-0 group-hover:opacity-100 transition-all shrink-0 p-1 rounded"
                            title="Copy value">
                            <Copy className="w-3 h-3" />
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Network Evidence */}
                {(ctx.srcIp || ctx.dstIp) && (
                  <div className="bg-card border border-border rounded-xl p-5 shadow-sm">
                    <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
                      <Network className="w-4 h-4 text-blue-400" /> Network Evidence
                    </h3>
                    <div className="flex items-center justify-center gap-6 py-4">
                      {ctx.srcIp && (
                        <button onClick={() => setAssetLookup({ ip: ctx.srcIp })} className="flex flex-col items-center gap-2 p-4 bg-blue-500/5 border border-blue-500/20 rounded-xl hover:bg-blue-500/10 transition-colors group">
                          <div className="w-12 h-12 rounded-full bg-blue-500/10 border border-blue-500/30 flex items-center justify-center">
                            <Server className="w-5 h-5 text-blue-400" />
                          </div>
                          <span className="font-mono text-sm text-blue-400 group-hover:underline">{ctx.srcIp}</span>
                          <span className="text-[10px] text-muted-foreground">Source</span>
                        </button>
                      )}
                      {ctx.srcIp && ctx.dstIp && (
                        <div className="flex items-center gap-2">
                          <div className="w-12 h-px bg-primary/40" />
                          <Activity className="w-4 h-4 text-primary animate-pulse" />
                          <div className="w-12 h-px bg-primary/40" />
                        </div>
                      )}
                      {ctx.dstIp && (
                        <button onClick={() => setAssetLookup({ ip: ctx.dstIp })} className="flex flex-col items-center gap-2 p-4 bg-red-500/5 border border-red-500/20 rounded-xl hover:bg-red-500/10 transition-colors group">
                          <div className="w-12 h-12 rounded-full bg-red-500/10 border border-red-500/30 flex items-center justify-center">
                            <Server className="w-5 h-5 text-red-400" />
                          </div>
                          <span className="font-mono text-sm text-red-400 group-hover:underline">{ctx.dstIp}</span>
                          <span className="text-[10px] text-muted-foreground">Destination</span>
                        </button>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* ─── Investigation Tab ───────────────────────────────────── */}
            {activeTab === 'investigation' && (
              <div className="space-y-6">
                {/* Checklist */}
                <div className="bg-card border border-border rounded-xl p-5 shadow-sm">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-sm font-semibold flex items-center gap-2">
                      <BarChart3 className="w-4 h-4 text-primary" /> Investigation Progress
                    </h3>
                    <span className="text-xs font-mono text-primary">{Math.round((checklistProgress / checklistTotal) * 100)}%</span>
                  </div>
                  <div className="h-2 bg-secondary rounded-full overflow-hidden mb-4">
                    <div className="h-full bg-linear-to-r from-primary to-emerald-500 rounded-full transition-all duration-500 ease-out" style={{ width: `${(checklistProgress / checklistTotal) * 100}%` }} />
                  </div>
                  <div className="space-y-1.5">
                    {CHECKLIST_ITEMS.map((item, i) => (
                      <label key={i} className={`flex items-center gap-3 p-2.5 rounded-lg cursor-pointer group transition-all ${
                        checkedItems[i] ? 'bg-emerald-500/5 border border-emerald-500/10' : 'hover:bg-secondary/50 border border-transparent'
                      }`}>
                        <input type="checkbox" checked={!!checkedItems[i]} onChange={() => toggleChecklist(i)}
                          className="w-4 h-4 rounded border-border accent-primary shrink-0" />
                        <span className={`text-sm flex-1 ${checkedItems[i] ? 'line-through text-muted-foreground/50' : 'text-foreground'}`}>
                          {item.label}
                        </span>
                        <span className={`text-[10px] px-1.5 py-0.5 rounded uppercase font-bold tracking-wider ${
                          item.priority === 'high' ? 'text-red-400 bg-red-500/10' :
                          item.priority === 'medium' ? 'text-amber-400 bg-amber-500/10' :
                          'text-green-400 bg-green-500/10'
                        }`}>{item.priority}</span>
                      </label>
                    ))}
                  </div>
                </div>

                {/* Notes */}
                <div className="bg-card border border-border rounded-xl p-5 shadow-sm">
                  <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
                    <MessageSquare className="w-4 h-4 text-primary" /> Investigation Notes
                  </h3>
                  {canNote ? (
                    <>
                      <textarea value={note} onChange={e => setNote(e.target.value)}
                        placeholder="Describe findings, actions taken, IOCs discovered, remediation steps..."
                        className="w-full bg-input border border-border rounded-lg p-4 text-sm text-foreground focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-all h-32 resize-none"
                        maxLength={1000} />
                      <div className="flex items-center justify-between mt-3">
                        <span className="text-xs text-muted-foreground">{note.length}/1000</span>
                        <button
                          onClick={() => note.trim() && noteMutation.mutate(note.trim())}
                          disabled={!note.trim() || actionMutation.isPending}
                          className="px-5 py-2.5 bg-primary text-primary-foreground font-semibold rounded-xl hover:bg-primary/90 transition-all shadow-lg shadow-primary/20 text-sm disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2">
                          {actionMutation.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
                          Add Note
                        </button>
                      </div>
                    </>
                  ) : (
                    <div className="flex items-center gap-2 text-muted-foreground text-sm py-6 justify-center">
                      <Lock className="w-4 h-4 opacity-50" /> Your role does not permit adding investigation notes.
                    </div>
                  )}
                </div>

                {/* Resolution Notes */}
                {alertRaw?.resolutionNotes && (
                  <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-xl p-5">
                    <div className="flex items-center gap-2 mb-3 text-emerald-400 font-semibold text-sm">
                      <CheckCircle2 className="w-4 h-4" /> Resolution Notes
                    </div>
                    <p className="text-sm text-foreground leading-relaxed">{alertRaw.resolutionNotes}</p>
                  </div>
                )}

                {/* Existing Notes */}
                {alert.timeline.filter((e: any) => e.note).length > 0 && (
                  <div className="bg-card border border-border rounded-xl shadow-sm overflow-hidden">
                    <div className="px-5 py-4 border-b border-border">
                      <h3 className="text-sm font-semibold flex items-center gap-2">
                        <MessageSquare className="w-4 h-4 text-primary" /> Previous Notes
                      </h3>
                    </div>
                    <div className="divide-y divide-border/30">
                      {[...alert.timeline].reverse().filter((e: any) => e.note).map(entry => (
                        <div key={entry.id} className="px-5 py-4">
                          <div className="flex items-center gap-2 mb-2">
                            {entry.user && <span className="text-xs text-primary font-medium">{entry.user}</span>}
                            <span className="text-[10px] text-muted-foreground font-mono">{safeFormat(entry.timestamp, 'MMM d, HH:mm')}</span>
                          </div>
                          <p className="text-sm text-foreground leading-relaxed whitespace-pre-wrap">{entry.note}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* ─── Timeline Tab ─────────────────────────────────────────── */}
            {activeTab === 'timeline' && (
              <div className="space-y-4">
                <div className="flex items-center gap-2 flex-wrap">
                  {['all', 'notes', 'status', 'escalation', 'assignment'].map(f => (
                    <button key={f} onClick={() => setTimelineFilter(f)}
                      className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                        timelineFilter === f ? 'bg-primary/10 border border-primary/30 text-primary' : 'bg-secondary border border-border text-muted-foreground hover:text-foreground'
                      }`}>
                      {f === 'all' ? 'All Events' : f.charAt(0).toUpperCase() + f.slice(1)}
                    </button>
                  ))}
                  <span className="text-xs text-muted-foreground ml-auto">{filteredTimeline.length} events</span>
                </div>

                <div className="bg-card border border-border rounded-xl p-5 shadow-sm">
                  {filteredTimeline.length === 0 ? (
                    <div className="flex flex-col items-center justify-center h-32 text-muted-foreground">
                      <Clock className="w-8 h-8 opacity-20 mb-2" />
                      <p className="text-sm">No timeline events{timelineFilter !== 'all' ? ' matching filter' : ''}</p>
                    </div>
                  ) : (
                    <div className="relative pl-8">
                      <div className="absolute left-3 top-1 bottom-1 w-px bg-linear-to-b from-primary/60 via-border to-transparent" />
                      <div className="space-y-4">
                        {filteredTimeline.map((event, i) => {
                          const ev = event as any;
                          const isEscalation = ev.type === 'escalation' || event.action?.toLowerCase().includes('escalat');
                          const isAssignment = ev.type === 'assignment' || event.action?.toLowerCase().includes('assign');
                          const isStatusChange = ev.type === 'status_change' || event.action?.toLowerCase().includes('status');
                          const isNote = ev.type === 'note' || event.action?.toLowerCase().includes('note');
                          const isOverride = ev.isOverride === true;

                          const dotColor = isEscalation ? 'bg-red-500 border-red-500/50 shadow-red-500/30'
                            : isAssignment ? 'bg-purple-500 border-purple-500/50 shadow-purple-500/30'
                            : isStatusChange ? 'bg-amber-500 border-amber-500/50 shadow-amber-500/30'
                            : isNote ? 'bg-blue-500 border-blue-500/50 shadow-blue-500/30'
                            : i === 0 ? 'bg-primary border-primary/50 shadow-primary/30'
                            : 'bg-muted-foreground/30 border-border';

                          const TimelineIcon = isEscalation ? TrendingUp : isAssignment ? UserPlus : isStatusChange ? Activity : MessageSquare;
                          const iconColor = isEscalation ? 'text-red-400' : isAssignment ? 'text-purple-400' : isStatusChange ? 'text-amber-400' : isNote ? 'text-blue-400' : 'text-primary';
                          const bgColor = isOverride
                            ? 'border-orange-500/20 hover:border-orange-500/30 bg-orange-500/5'
                            : isEscalation ? 'border-red-500/10 hover:border-red-500/20'
                            : isAssignment ? 'border-purple-500/10 hover:border-purple-500/20'
                            : isStatusChange ? 'border-amber-500/10 hover:border-amber-500/20'
                            : 'border-border/50 hover:border-primary/20';

                          return (
                            <div key={event.id} className="relative">
                              <div className={`absolute -left-5.5 top-3.5 w-3.5 h-3.5 rounded-full border-2 shadow-sm ${dotColor}`} />
                              <div className={`bg-background/50 border rounded-xl p-4 transition-colors ${bgColor}`}>
                                <div className="flex items-start justify-between gap-2 mb-1">
                                  <span className="font-medium text-sm text-foreground flex items-center gap-2">
                                    <TimelineIcon className={`w-4 h-4 ${iconColor}`} />
                                    {event.action}
                                    {isOverride && (
                                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-orange-500/15 text-orange-400 border border-orange-500/30 font-semibold uppercase tracking-wide">
                                        Override
                                      </span>
                                    )}
                                  </span>
                                  <div className="flex items-center gap-2">
                                    <span className="font-mono text-[10px] text-muted-foreground whitespace-nowrap">{safeFormat(event.timestamp, 'MMM d, HH:mm:ss')}</span>
                                    <span className="text-[10px] text-muted-foreground/50">{timeAgo(event.timestamp)}</span>
                                  </div>
                                </div>

                                {/* State Transition Badge */}
                                {isStatusChange && ev.previousStatus && ev.newStatus && (
                                  <div className="flex items-center gap-1.5 mb-2 mt-1">
                                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-secondary text-muted-foreground border border-border capitalize">{ev.previousStatus.replace(/_/g, ' ')}</span>
                                    <span className="text-[10px] text-muted-foreground">→</span>
                                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-primary/10 text-primary border border-primary/20 capitalize font-medium">{ev.newStatus.replace(/_/g, ' ')}</span>
                                  </div>
                                )}

                                {/* Actor + Target */}
                                {event.user && (
                                  <div className="text-xs text-primary mb-2 font-medium flex items-center gap-1 flex-wrap">
                                    <span>by {event.user}</span>
                                    {(isAssignment || isEscalation) && ev.targetUser && (
                                      <span className="text-muted-foreground"> → <span className="text-foreground font-medium">{ev.targetUser}</span></span>
                                    )}
                                    {isEscalation && ev.targetRole && (
                                      <span className={`ml-1 text-[10px] px-1.5 py-0.5 rounded ${ROLE_COLORS[ev.targetRole] || 'bg-secondary text-muted-foreground border border-border'}`}>
                                        {ROLE_LABELS[ev.targetRole] || ev.targetRole}
                                      </span>
                                    )}
                                  </div>
                                )}

                                {/* Note / Reason Content */}
                                {event.note && (
                                  <div className="text-sm text-muted-foreground bg-secondary/40 p-3 rounded-lg border border-border/30 leading-relaxed whitespace-pre-wrap mt-2">
                                    {event.note}
                                  </div>
                                )}
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* ─── Related Events Tab ──────────────────────────────────── */}
            {activeTab === 'related' && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <p className="text-xs text-muted-foreground flex items-center gap-1.5">
                    <Clock className="w-3 h-3" /> Events within ±10 minute window
                  </p>
                  <span className="text-xs font-mono text-primary">{relatedEventsData?.total ?? 0} events</span>
                </div>

                <div className="bg-card border border-border rounded-xl shadow-sm overflow-hidden">
                  {relatedLoading ? (
                    <div className="flex items-center justify-center h-40 text-muted-foreground gap-3">
                      <Loader2 className="w-5 h-5 animate-spin text-primary" /> Loading related events…
                    </div>
                  ) : relatedEvents.length === 0 ? (
                    <div className="flex flex-col items-center justify-center h-40 text-muted-foreground">
                      <ListTree className="w-8 h-8 opacity-20 mb-2" />
                      <p className="text-sm">No related events found</p>
                    </div>
                  ) : (
                    <div className="divide-y divide-border/30">
                      {relatedEvents.map((ev: any) => {
                        const isExpanded = expandedEvent === ev.id;
                        const evSeverity = ev.severity || 'info';
                        const evSevColor = SEVERITY_COLORS[evSeverity] || SEVERITY_COLORS.info;
                        return (
                          <div key={ev.id} className="group">
                            <button onClick={() => setExpandedEvent(isExpanded ? null : ev.id)}
                              className="w-full flex items-center gap-3 px-5 py-3.5 hover:bg-secondary/30 text-left transition-colors">
                              <div className={`w-1.5 h-8 rounded-full ${evSevColor.bar} shrink-0`} />
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2 flex-wrap mb-0.5">
                                  <span className="font-mono text-[10px] text-muted-foreground">
                                    {(() => { const d = new Date(ev.timestamp ?? ev.parsedTimestamp ?? ev.createdAt); return isValid(d) ? format(d, 'HH:mm:ss.SSS') : '—'; })()}
                                  </span>
                                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-secondary text-foreground capitalize font-medium">{ev.source ?? 'unknown'}</span>
                                  {ev.severity && <SeverityBadge severity={ev.severity} />}
                                  {ev.sourceHost && <span className="font-mono text-[10px] text-primary">{ev.sourceHost}</span>}
                                  {ev.sourceIp && <span className="font-mono text-[10px] text-muted-foreground">{ev.sourceIp}</span>}
                                </div>
                                <p className="text-sm text-foreground truncate">{ev.message ?? ev.raw?.substring(0, 120) ?? 'No message'}</p>
                              </div>
                              {isExpanded ? <ChevronUp className="w-4 h-4 text-muted-foreground shrink-0" /> : <ChevronDown className="w-4 h-4 text-muted-foreground shrink-0" />}
                            </button>
                            {isExpanded && (
                              <div className="border-t border-border/30 bg-[#0a0e1a] px-5 py-4">
                                <pre className="text-xs font-mono text-green-400/80 overflow-x-auto whitespace-pre-wrap break-all">
                                  {JSON.stringify(ev, null, 2)}
                                </pre>
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* ── Right Sidebar ────────────────────────────────────────────── */}
          <div className="xl:col-span-3 space-y-5">
            {/* Properties */}
            <div className="bg-card border border-border rounded-xl shadow-sm overflow-hidden">
              <div className="px-4 py-3 bg-secondary/30 border-b border-border">
                <h3 className="font-semibold text-foreground text-xs uppercase tracking-wider">Properties</h3>
              </div>
              <div className="p-4 space-y-3.5">
                {[
                  { label: 'Created', value: safeFormat(alert.createdAt, 'PP pp'), sub: timeAgo(alert.createdAt) },
                  { label: 'Updated', value: safeFormat(alert.updatedAt, 'PP pp'), sub: timeAgo(alert.updatedAt) },
                  ...(alertRaw?.source ? [{ label: 'Source', value: alertRaw.source }] : []),
                  ...(alertRaw?.dedupKey ? [{ label: 'Dedup Key', value: alertRaw.dedupKey }] : []),
                ].map(({ label, value, sub }: any) => (
                  <div key={label}>
                    <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-0.5">{label}</div>
                    <div className="text-foreground font-mono text-xs break-all">{value}</div>
                    {sub && <div className="text-[10px] text-muted-foreground/60 mt-0.5">{sub}</div>}
                  </div>
                ))}
                <div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-0.5">Detection Rule</div>
                  <button onClick={() => setShowRuleDialog(true)} className="text-primary hover:underline text-sm font-medium">{alert.ruleName}</button>
                </div>
              </div>
            </div>

            {/* Assignment */}
            <div className="bg-card border border-border rounded-xl shadow-sm overflow-hidden">
              <div className="px-4 py-3 bg-secondary/30 border-b border-border">
                <h3 className="font-semibold text-foreground text-xs uppercase tracking-wider flex items-center gap-1.5">
                  <UserPlus className="w-3 h-3 text-primary" /> Assignment
                </h3>
              </div>
              <div className="p-4">
                {assigneeName ? (
                  <div className="flex items-center gap-2.5 p-2.5 rounded-lg bg-primary/10 border border-primary/30 mb-3">
                    <div className="w-7 h-7 rounded-full bg-primary flex items-center justify-center text-xs font-bold text-white shrink-0">
                      {assigneeName.charAt(0).toUpperCase()}
                    </div>
                    <div className="flex-1 min-w-0">
                      <span className="text-sm text-primary font-medium block truncate">{assigneeName}</span>
                      {(() => {
                        const assignee = analysts.find((a: any) => a.id === assigneeId);
                        if (!assignee) return null;
                        const rc = ROLE_COLORS[assignee.role];
                        return (
                          <span className={`inline-block text-[10px] px-1.5 py-0.5 rounded font-medium mt-0.5 ${rc || 'bg-secondary text-muted-foreground border border-border'}`}>
                            {ROLE_LABELS[assignee.role] || assignee.role?.replace('_', ' ')}
                          </span>
                        );
                      })()}
                    </div>
                    <CheckCircle2 className="w-3.5 h-3.5 text-primary shrink-0" />
                  </div>
                ) : (
                  <div className="flex items-center gap-2 p-3 rounded-lg bg-secondary/30 border border-border/50 mb-3">
                    <UserPlus className="w-4 h-4 text-muted-foreground/50" />
                    <span className="text-xs text-muted-foreground italic">Unassigned</span>
                  </div>
                )}
                {canAssign ? (
                  <button onClick={() => setAssignDialogOpen(true)}
                    className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg bg-primary/10 border border-primary/30 text-primary text-sm font-medium hover:bg-primary/20 transition-all">
                    <UserPlus className="w-4 h-4" />
                    {assigneeName ? 'Reassign' : 'Assign Analyst'}
                  </button>
                ) : (
                  <div className="flex items-center gap-1.5 text-[10px] text-muted-foreground/60 justify-center mt-1">
                    <Lock className="w-3 h-3" /> SOC L2 or higher can assign
                  </div>
                )}
              </div>
            </div>

            {/* Quick Actions */}
            <div className="bg-card border border-border rounded-xl shadow-sm overflow-hidden">
              <div className="px-4 py-3 bg-secondary/30 border-b border-border">
                <h3 className="font-semibold text-xs uppercase tracking-wider text-muted-foreground">Quick Actions</h3>
              </div>
              <div className="p-2">
                <Link href="/logs" className="flex items-center gap-2.5 px-3 py-2.5 text-sm text-muted-foreground hover:text-foreground hover:bg-secondary rounded-lg transition-all">
                  <Terminal className="w-4 h-4 text-primary" /> Open Log Explorer
                </Link>
                <Link href="/mitre" className="flex items-center gap-2.5 px-3 py-2.5 text-sm text-muted-foreground hover:text-foreground hover:bg-secondary rounded-lg transition-all">
                  <Target className="w-4 h-4 text-purple-400" /> View MITRE Framework
                </Link>
                <Link href="/assets" className="flex items-center gap-2.5 px-3 py-2.5 text-sm text-muted-foreground hover:text-foreground hover:bg-secondary rounded-lg transition-all">
                  <Server className="w-4 h-4 text-amber-400" /> Asset Inventory
                </Link>
                <Link href="/rules" className="flex items-center gap-2.5 px-3 py-2.5 text-sm text-muted-foreground hover:text-foreground hover:bg-secondary rounded-lg transition-all">
                  <Shield className="w-4 h-4 text-cyan-400" /> Detection Rules
                </Link>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ── Dialogs ──────────────────────────────────────────────────────── */}
      <ActionConfirmDialog
        open={confirmDialog.open}
        onOpenChange={open => setConfirmDialog(prev => ({ ...prev, open }))}
        variant={confirmDialog.variant}
        title={confirmDialog.title}
        description={confirmDialog.description}
        entities={alert.title}
        confirmLabel={confirmDialog.confirmLabel}
        requireComment={confirmDialog.requireComment}
        commentPlaceholder={confirmDialog.requireComment ? 'Provide justification or resolution notes…' : undefined}
        isPending={statusMutation.isPending}
        onConfirm={handleStatusConfirm}
      />

      <EscalateDialog
        open={escalateOpen}
        onOpenChange={setEscalateOpen}
        targets={(escalationTargets ?? []).map((u: any) => ({
          id: u.id,
          username: u.username,
          displayName: u.displayName,
          role: u.role,
        }))}
        currentAssigneeRole={(() => {
          const assignee = analysts.find((a: any) => a.id === assigneeId);
          return assignee?.role;
        })()}
        alertTitle={alert.title}
        isPending={escalateMutation.isPending}
        onEscalate={(targetId, reason) => escalateMutation.mutate({ targetId, reason })}
      />

      <AssignDialog
        open={assignDialogOpen}
        onOpenChange={setAssignDialogOpen}
        users={analysts.map((a: any) => ({
          id: a.id,
          username: a.username,
          displayName: a.displayName,
          role: a.role,
          status: a.status,
        }))}
        currentAssigneeId={assigneeId}
        alertTitle={alert.title}
        isPending={assignMutation.isPending}
        onAssign={(userId) => { assignMutation.mutate(userId); setAssignDialogOpen(false); }}
        onClearAssignment={() => { clearAssignMutation.mutate(); setAssignDialogOpen(false); }}
        isClearPending={clearAssignMutation.isPending}
      />

      <AssetDetailDialog
        open={!!assetLookup}
        onOpenChange={(o) => { if (!o) setAssetLookup(null); }}
        hostname={assetLookup?.hostname}
        ip={assetLookup?.ip}
      />

      <RuleDetailDialog
        open={showRuleDialog}
        onOpenChange={setShowRuleDialog}
        ruleId={alertRaw?.ruleId ?? ''}
        ruleName={alert.ruleName}
      />
    </>
  );
}
