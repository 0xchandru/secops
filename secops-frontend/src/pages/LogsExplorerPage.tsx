import React, { useState, useMemo, useCallback, useRef, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { logsApi, eventsApi, normalizeLog } from '@/lib/api';
import { useEventStream } from '@/hooks/useEventStream';
import { format } from 'date-fns';
import { safeFormat, timeAgo } from '@/lib/date-utils';
import { SeverityBadge } from '@/components/ui/Badge';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';
import {
  Search, X, Eye, ChevronUp, ChevronDown, ChevronsLeft, ChevronLeft, ChevronRight,
  ChevronsRight, SlidersHorizontal, Loader2, Database, Radio, BarChart3, Shield, Globe,
  Tag, CalendarDays, Columns, Download, RefreshCw, AlertTriangle, Activity, Zap,
  Copy, Check, Clock, Save, History, ChevronRight as ChevronR, PanelLeftClose, PanelLeft,
  Hash, Terminal, Bookmark, Trash2, Play, Bell, Filter, Code2, Cpu
} from 'lucide-react';
import { rulesApi } from '@/lib/api';
import type { LogEntry } from '@/lib/types';

/* ─── Constants ──────────────────────────────────────────────────────────── */

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
const PAGE_SIZE = 50;

type SortKey = 'timestamp' | 'severity' | 'source' | 'eventType' | 'category';
type SortDir = 'asc' | 'desc';
const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const SEVERITY_COLORS: Record<string, { bar: string; bg: string; text: string; dot: string }> = {
  critical: { bar: 'bg-red-500', bg: 'bg-red-500/5', text: 'text-red-400', dot: 'bg-red-500' },
  high:     { bar: 'bg-orange-500', bg: 'bg-orange-500/5', text: 'text-orange-400', dot: 'bg-orange-500' },
  medium:   { bar: 'bg-yellow-500', bg: 'bg-yellow-500/5', text: 'text-yellow-400', dot: 'bg-yellow-500' },
  low:      { bar: 'bg-green-500', bg: 'bg-green-500/5', text: 'text-green-400', dot: 'bg-green-500' },
  info:     { bar: 'bg-indigo-500', bg: 'bg-indigo-500/5', text: 'text-indigo-400', dot: 'bg-indigo-500' },
};

const TIME_RANGES: { value: string; label: string }[] = [
  { value: '', label: 'All Time' },
  { value: '15m', label: '15 min' },
  { value: '1h', label: '1 hour' },
  { value: '6h', label: '6 hours' },
  { value: '24h', label: '24 hours' },
  { value: '7d', label: '7 days' },
  { value: '30d', label: '30 days' },
];

type ColumnKey = 'timestamp' | 'source' | 'severity' | 'category' | 'eventType' | 'sourceIp' | 'destIp' | 'riskScore' | 'message';
const ALL_COLUMNS: { key: ColumnKey; label: string; sortable: boolean }[] = [
  { key: 'timestamp', label: 'Timestamp', sortable: true },
  { key: 'source', label: 'Source', sortable: true },
  { key: 'severity', label: 'Severity', sortable: true },
  { key: 'category', label: 'Category', sortable: true },
  { key: 'eventType', label: 'Event Type', sortable: true },
  { key: 'sourceIp', label: 'Source IP', sortable: false },
  { key: 'destIp', label: 'Dest IP', sortable: false },
  { key: 'riskScore', label: 'Risk', sortable: false },
  { key: 'message', label: 'Message', sortable: false },
];
const DEFAULT_COLUMNS: ColumnKey[] = ['timestamp', 'source', 'severity', 'category', 'eventType', 'sourceIp', 'destIp', 'riskScore', 'message'];

const FACET_FIELDS = [
  { key: 'source', label: 'Source', icon: Database },
  { key: 'severity', label: 'Severity', icon: AlertTriangle },
  { key: 'category', label: 'Category', icon: Tag },
  { key: 'eventType', label: 'Event Type', icon: Zap },
  { key: 'action', label: 'Action', icon: Activity },
  { key: 'sourceIp', label: 'Source IP', icon: Globe },
  { key: 'destIp', label: 'Dest IP', icon: Globe },
  { key: 'hostname', label: 'Hostname', icon: Terminal },
  { key: 'username', label: 'Username', icon: Shield },
  { key: 'protocol', label: 'Protocol', icon: Hash },
  { key: 'outcome', label: 'Outcome', icon: Check },
  { key: 'geoCountry', label: 'Country', icon: Globe },
  { key: 'processName', label: 'Process', icon: Zap },
  { key: 'httpMethod', label: 'HTTP Method', icon: Globe },
];

const FIELD_LABELS: Record<string, string> = {
  source: 'source', severity: 'severity', category: 'category', eventType: 'event_type',
  action: 'action', sourceIp: 'srcIp', destIp: 'dstIp', hostname: 'hostname',
  username: 'user', protocol: 'protocol', outcome: 'outcome', geoCountry: 'geoCountry',
  processName: 'process', httpMethod: 'httpMethod',
};

const SOURCETYPE_BADGE: Record<string, { label: string; cls: string }> = {
  syslog: { label: 'SYSLOG', cls: 'bg-blue-500/10 text-blue-400 border-blue-500/20' },
  windows_eventlog: { label: 'WINDOWS', cls: 'bg-purple-500/10 text-purple-400 border-purple-500/20' },
  cef: { label: 'CEF', cls: 'bg-orange-500/10 text-orange-400 border-orange-500/20' },
  leef: { label: 'LEEF', cls: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20' },
  ecs: { label: 'ECS', cls: 'bg-green-500/10 text-green-400 border-green-500/20' },
  cloudtrail: { label: 'CLOUDTRAIL', cls: 'bg-amber-500/10 text-amber-400 border-amber-500/20' },
  xml: { label: 'XML', cls: 'bg-rose-500/10 text-rose-400 border-rose-500/20' },
  firewall: { label: 'FIREWALL', cls: 'bg-red-500/10 text-red-400 border-red-500/20' },
  apache: { label: 'APACHE', cls: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' },
  nginx: { label: 'NGINX', cls: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' },
  vpc_flow: { label: 'VPC FLOW', cls: 'bg-teal-500/10 text-teal-400 border-teal-500/20' },
  dns: { label: 'DNS', cls: 'bg-indigo-500/10 text-indigo-400 border-indigo-500/20' },
  json: { label: 'JSON', cls: 'bg-sky-500/10 text-sky-400 border-sky-500/20' },
  generic: { label: 'GENERIC', cls: 'bg-secondary text-muted-foreground border-border' },
};

const SCHEDULE_INTERVALS = [
  { value: '5m', label: 'Every 5 min' },
  { value: '15m', label: 'Every 15 min' },
  { value: '1h', label: 'Every hour' },
  { value: '6h', label: 'Every 6 hours' },
  { value: '24h', label: 'Daily' },
];

// Maps detail panel display name → facet filter key for click-to-filter
const DETAIL_FIELD_TO_FILTER: Record<string, string> = {
  'Source': 'source', 'Severity': 'severity', 'Category': 'category', 'Event Type': 'eventType',
  'Action': 'action', 'Source IP': 'sourceIp', 'Dest IP': 'destIp', 'Hostname': 'hostname',
  'Username': 'username', 'Protocol': 'protocol', 'Outcome': 'outcome', 'Src Country': 'geoCountry',
  'Process Name': 'processName', 'Method': 'httpMethod',
};

interface SavedSearch { id: string; name: string; query: string; timeRange: string; createdAt: string; }

function loadColumns(): ColumnKey[] {
  try {
    const stored = localStorage.getItem('secops:log-columns');
    if (stored) {
      const parsed = JSON.parse(stored) as ColumnKey[];
      if (Array.isArray(parsed) && parsed.length > 0) return parsed;
    }
  } catch { /* ignore */ }
  return DEFAULT_COLUMNS;
}

function loadSavedSearches(): SavedSearch[] {
  try {
    const stored = localStorage.getItem('secops:saved-searches');
    if (stored) return JSON.parse(stored);
  } catch { /* ignore */ }
  return [];
}

function loadRecentSearches(): string[] {
  try {
    const stored = localStorage.getItem('secops:recent-searches');
    if (stored) return JSON.parse(stored);
  } catch { /* ignore */ }
  return [];
}

function saveSavedSearches(searches: SavedSearch[]) {
  localStorage.setItem('secops:saved-searches', JSON.stringify(searches));
}

function saveRecentSearch(query: string) {
  const recent = loadRecentSearches();
  const filtered = recent.filter(q => q !== query);
  const updated = [query, ...filtered].slice(0, 20);
  localStorage.setItem('secops:recent-searches', JSON.stringify(updated));
}

/* ─── Main Component ─────────────────────────────────────────────────────── */

export default function LogsExplorerPage() {
  const [searchTerm, setSearchTerm] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [selectedLog, setSelectedLog] = useState<LogEntry | null>(null);
  const [page, setPage] = useState(1);
  const [sort, setSort] = useState<{ key: SortKey; dir: SortDir }>({ key: 'timestamp', dir: 'desc' });
  const [showFilters, setShowFilters] = useState(false);
  const [histogramInterval, setHistogramInterval] = useState<string>('1h');
  const [liveTail, setLiveTail] = useState(false);
  const [timeRange, setTimeRange] = useState('');
  const [visibleColumns, setVisibleColumns] = useState<ColumnKey[]>(loadColumns);
  const [showColumnPicker, setShowColumnPicker] = useState(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  // Field sidebar & saved searches
  const [showFieldSidebar, setShowFieldSidebar] = useState(true);
  const [expandedFacet, setExpandedFacet] = useState<string | null>('source');
  const [savedSearches, setSavedSearches] = useState<SavedSearch[]>(loadSavedSearches);
  const [recentSearches] = useState<string[]>(loadRecentSearches);
  const [showSearchPanel, setShowSearchPanel] = useState(false);
  const [saveSearchName, setSaveSearchName] = useState('');
  const [showSaveDialog, setShowSaveDialog] = useState(false);
  const [activeFieldFilters, setActiveFieldFilters] = useState<Map<string, { value: string; negate: boolean }>>(new Map());

  const searchRef = useRef<HTMLTextAreaElement>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout>>(undefined);
  const [fieldSearch, setFieldSearch] = useState('');

  // Inline row expansion (Splunk-style)
  const [expandedLogId, setExpandedLogId] = useState<string | null>(null);

  // Save as Alert dialog
  const [showSaveAlertDialog, setShowSaveAlertDialog] = useState(false);
  const [saveAlertName, setSaveAlertName] = useState('');
  const [saveAlertDesc, setSaveAlertDesc] = useState('');
  const [saveAlertInterval, setSaveAlertInterval] = useState('15m');
  const [saveAlertThreshold, setSaveAlertThreshold] = useState(1);
  const [saveAlertSeverity, setSaveAlertSeverity] = useState('medium');
  const [saveAlertLoading, setSaveAlertLoading] = useState(false);
  const [saveAlertError, setSaveAlertError] = useState<string | null>(null);
  const [saveAlertSuccess, setSaveAlertSuccess] = useState(false);

  const { events: liveEvents, isConnected: liveConnected, clear: clearLive } = useEventStream();

  /* ── Search Logic ── */

  const effectiveSearch = useMemo(() => {
    const parts: string[] = [];
    if (debouncedSearch.trim()) parts.push(debouncedSearch.trim());
    activeFieldFilters.forEach(({ value, negate }, field) => {
      const splField = FIELD_LABELS[field] ?? field;
      parts.push(negate ? `${splField}!="${value}"` : `${splField}="${value}"`);
    });
    return parts.join(' ');
  }, [debouncedSearch, activeFieldFilters]);

  const handleSearchChange = useCallback((val: string) => {
    setSearchTerm(val);
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      setDebouncedSearch(val);
      setPage(1);
    }, 500);
  }, []);

  const executeSearch = useCallback(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    setDebouncedSearch(searchTerm);
    setPage(1);
    if (searchTerm.trim()) saveRecentSearch(searchTerm.trim());
    setShowSearchPanel(false);
  }, [searchTerm]);

  const handleSearchKeyDown = useCallback((e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      executeSearch();
    }
  }, [executeSearch]);

  const loadSearch = useCallback((query: string) => {
    setSearchTerm(query);
    setDebouncedSearch(query);
    setPage(1);
    setShowSearchPanel(false);
  }, []);

  const saveCurrentSearch = useCallback(() => {
    if (!saveSearchName.trim() || !searchTerm.trim()) return;
    const newSearch: SavedSearch = {
      id: crypto.randomUUID(),
      name: saveSearchName.trim(),
      query: searchTerm.trim(),
      timeRange,
      createdAt: new Date().toISOString(),
    };
    const updated = [newSearch, ...savedSearches];
    setSavedSearches(updated);
    saveSavedSearches(updated);
    setSaveSearchName('');
    setShowSaveDialog(false);
  }, [saveSearchName, searchTerm, timeRange, savedSearches]);

  const deleteSavedSearch = useCallback((id: string) => {
    const updated = savedSearches.filter(s => s.id !== id);
    setSavedSearches(updated);
    saveSavedSearches(updated);
  }, [savedSearches]);

  const saveSplAsAlert = useCallback(async () => {
    if (!saveAlertName.trim() || !searchTerm.trim()) return;
    setSaveAlertLoading(true);
    setSaveAlertError(null);
    setSaveAlertSuccess(false);
    try {
      await rulesApi.create({
        name: saveAlertName.trim(),
        description: saveAlertDesc.trim() || `SPL Alert: ${searchTerm.trim().slice(0, 200)}`,
        severity: saveAlertSeverity,
        ruleType: 'spl_saved_search',
        splQuery: searchTerm.trim(),
        splThreshold: saveAlertThreshold,
        scheduleInterval: saveAlertInterval,
        enabled: true,
      });
      setSaveAlertSuccess(true);
      setTimeout(() => {
        setShowSaveAlertDialog(false);
        setSaveAlertName('');
        setSaveAlertDesc('');
        setSaveAlertSuccess(false);
      }, 1500);
    } catch (err: any) {
      setSaveAlertError(err?.response?.data?.error ?? 'Failed to save alert');
    } finally {
      setSaveAlertLoading(false);
    }
  }, [saveAlertName, saveAlertDesc, searchTerm, saveAlertSeverity, saveAlertThreshold, saveAlertInterval]);

  const addFieldFilter = useCallback((field: string, value: string, negate = false) => {
    setActiveFieldFilters(prev => {
      const next = new Map(prev);
      next.set(negate ? `!${field}` : field, { value, negate });
      return next;
    });
    setPage(1);
  }, []);

  const removeFieldFilter = useCallback((field: string) => {
    setActiveFieldFilters(prev => {
      const next = new Map(prev);
      next.delete(field);
      next.delete(`!${field}`);
      return next;
    });
    setPage(1);
  }, []);

  /* ── Queries ── */

  const { data: filterOptions } = useQuery({
    queryKey: ['log-filters'],
    queryFn: () => logsApi.filters().then(r => r.data),
    staleTime: 60_000,
  });
  const dynamicSources = filterOptions?.sources ?? [];
  const dynamicCategories = filterOptions?.categories ?? [];

  const histogramParams = useMemo(() => {
    const p: { interval: string; hours?: number } = { interval: histogramInterval };
    if (timeRange) {
      const match = /^(\d+)([mhd])$/.exec(timeRange);
      if (match) {
        const amount = Number(match[1]);
        const unit = match[2];
        p.hours = unit === 'm' ? amount / 60 : unit === 'h' ? amount : amount * 24;
      }
    }
    return p;
  }, [histogramInterval, timeRange]);

  const { data: histogramData } = useQuery({
    queryKey: ['event-histogram', histogramParams],
    queryFn: () => eventsApi.histogram(histogramParams).then(r => r.data),
    refetchInterval: 30000,
  });

  const facetParams = useMemo(() => ({
    fields: FACET_FIELDS.map(f => f.key),
    limit: 15,
    from: timeRange || undefined,
    q: effectiveSearch || undefined,
  }), [timeRange, effectiveSearch]);

  const { data: facetData } = useQuery({
    queryKey: ['log-facets', facetParams],
    queryFn: () => logsApi.facets(facetParams).then(r => r.data),
    staleTime: 15_000,
  });
  const facets = facetData?.facets ?? {};

  // Detect whether the current search uses SPL pipes — if so, route to /logs/spl
  const hasSplPipes = useMemo(() => {
    const q = effectiveSearch.trim();
    return q.includes('|') && q.length >= 3;
  }, [effectiveSearch]);

  const queryParams = useMemo(() => {
    const p: Record<string, string | number> = { page, limit: PAGE_SIZE };
    if (!hasSplPipes && effectiveSearch.length >= 2) p.q = effectiveSearch;
    if (timeRange) p.from = timeRange;
    return p;
  }, [page, effectiveSearch, timeRange, hasSplPipes]);

  const splParams = useMemo(() => ({
    query: effectiveSearch,
    from: timeRange || undefined,
    limit: PAGE_SIZE,
  }), [effectiveSearch, timeRange]);

  const { data: splData, isLoading: splLoading, isFetching: splFetching, refetch: splRefetch } = useQuery({
    queryKey: ['logs-spl', splParams],
    queryFn: () => logsApi.spl(splParams).then(r => r.data),
    enabled: hasSplPipes,
  });

  const { data: regularData, isLoading: regularLoading, isFetching: regularFetching, refetch: regularRefetch } = useQuery({
    queryKey: ['logs', queryParams],
    queryFn: () => logsApi.list(queryParams).then(r => r.data),
    enabled: !hasSplPipes,
  });

  const data = hasSplPipes ? splData : regularData;
  const isLoading = hasSplPipes ? splLoading : regularLoading;
  const isFetching = hasSplPipes ? splFetching : regularFetching;
  const refetch = hasSplPipes ? splRefetch : regularRefetch;

  const logs = useMemo(() => (data?.logs ?? []).map(normalizeLog), [data]);

  const sortedLogs = useMemo(() => {
    return [...logs].sort((a, b) => {
      let cmp = 0;
      if (sort.key === 'timestamp') cmp = a.timestamp.getTime() - b.timestamp.getTime();
      else if (sort.key === 'severity') cmp = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
      else if (sort.key === 'source') cmp = a.source.localeCompare(b.source);
      else if (sort.key === 'eventType') cmp = a.eventType.localeCompare(b.eventType);
      else if (sort.key === 'category') cmp = (a.category ?? '').localeCompare(b.category ?? '');
      return sort.dir === 'asc' ? cmp : -cmp;
    });
  }, [logs, sort]);

  const totalPages = Math.ceil((data?.total ?? 0) / PAGE_SIZE);

  const severityCounts = useMemo(() => ({
    critical: logs.filter(l => l.severity === 'critical').length,
    high: logs.filter(l => l.severity === 'high').length,
    medium: logs.filter(l => l.severity === 'medium').length,
    low: logs.filter(l => l.severity === 'low').length,
    info: logs.filter(l => l.severity === 'info').length,
  }), [logs]);

  /* ── Handlers ── */

  const handleSort = (key: SortKey) => {
    setSort(prev => prev.key === key ? { key, dir: prev.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: 'desc' });
  };

  const toggleColumn = (col: ColumnKey) => {
    setVisibleColumns(prev => {
      const next = prev.includes(col) ? prev.filter(c => c !== col) : [...prev, col];
      if (next.length === 0) return prev;
      localStorage.setItem('secops:log-columns', JSON.stringify(next));
      return next;
    });
  };

  const copyToClipboard = (text: string, field: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const hasActiveFilters = activeFieldFilters.size > 0 || debouncedSearch.length >= 2 || timeRange !== '';

  const clearAllFilters = () => {
    setSearchTerm('');
    setDebouncedSearch('');
    setActiveFieldFilters(new Map());
    setTimeRange('');
    setPage(1);
  };

  const exportCsv = () => {
    if (sortedLogs.length === 0) return;
    const headers = visibleColumns.map(c => ALL_COLUMNS.find(ac => ac.key === c)!.label);
    const rows = sortedLogs.map(log => visibleColumns.map(c => {
      if (c === 'timestamp') return safeFormat(log.timestamp, 'yyyy-MM-dd HH:mm:ss');
      const val = log[c as keyof typeof log];
      return val != null ? String(val) : '';
    }));
    const csv = [headers, ...rows].map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `logs-export-${format(new Date(), 'yyyyMMdd-HHmmss')}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const SortIcon = ({ col }: { col: SortKey }) => (
    sort.key === col
      ? sort.dir === 'asc' ? <ChevronUp className="w-3 h-3 text-primary" /> : <ChevronDown className="w-3 h-3 text-primary" />
      : <ChevronUp className="w-3 h-3 opacity-20" />
  );

  // Auto-resize textarea
  useEffect(() => {
    if (searchRef.current) {
      searchRef.current.style.height = 'auto';
      searchRef.current.style.height = Math.min(searchRef.current.scrollHeight, 120) + 'px';
    }
  }, [searchTerm]);

  /* ── Render ── */

  return (
    <>
      <div className="flex flex-col gap-5 max-w-450 mx-auto">
        {/* ── Header ───────────────────────────────────────────────────── */}
        <div className="flex flex-col gap-4">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <h1 className="text-3xl font-bold tracking-tight text-foreground flex items-center gap-3">
                <Database className="w-7 h-7 text-primary" /> Logs Explorer
              </h1>
              <p className="text-muted-foreground mt-1 text-sm flex items-center gap-2">
                Search and investigate raw security events
                {hasSplPipes ? (
                  <span className="flex items-center gap-1.5 font-mono text-xs bg-amber-500/10 text-amber-400 border border-amber-500/20 px-2 py-0.5 rounded-md">
                    <Terminal className="w-3 h-3" /> SPL — {data?.total.toLocaleString() ?? '…'} result{data?.total !== 1 ? 's' : ''}
                  </span>
                ) : (
                  data && <span className="font-mono text-xs text-primary">{data.total.toLocaleString()} total events</span>
                )}
                {isFetching && !isLoading && (
                  <span className="flex items-center gap-1 text-primary text-xs">
                    <RefreshCw className="w-3 h-3 animate-spin" /> Syncing
                  </span>
                )}
              </p>
            </div>
            <div className="flex items-center gap-2 flex-wrap">
              <button onClick={() => refetch()}
                className="inline-flex items-center gap-1.5 px-3 py-2 text-sm font-medium rounded-xl border border-border bg-card hover:bg-secondary/80 text-muted-foreground hover:text-foreground transition-colors">
                <RefreshCw className="w-4 h-4" /> Refresh
              </button>
              <button onClick={() => setShowFieldSidebar(!showFieldSidebar)}
                className={`inline-flex items-center gap-1.5 px-3 py-2 text-sm font-medium rounded-xl border transition-colors ${showFieldSidebar ? 'bg-primary/10 border-primary/30 text-primary' : 'border-border bg-card text-muted-foreground hover:text-foreground hover:bg-secondary/80'}`}>
                {showFieldSidebar ? <PanelLeftClose className="w-4 h-4" /> : <PanelLeft className="w-4 h-4" />}
                Fields
              </button>
              <div className="relative">
                <button
                  onClick={() => setShowColumnPicker(!showColumnPicker)}
                  className={`inline-flex items-center gap-1.5 px-3 py-2 text-sm font-medium rounded-xl border transition-colors ${showColumnPicker ? 'bg-primary/10 border-primary/30 text-primary' : 'border-border bg-card text-muted-foreground hover:text-foreground hover:bg-secondary/80'}`}>
                  <Columns className="w-4 h-4" /> Columns
                </button>
                {showColumnPicker && (
                  <div className="absolute right-0 top-full mt-1 bg-card border border-border rounded-xl shadow-xl p-2 z-30 min-w-44">
                    {ALL_COLUMNS.map(col => (
                      <label key={col.key} className="flex items-center gap-2.5 px-3 py-2 text-xs text-foreground hover:bg-secondary/50 rounded-lg cursor-pointer transition-colors">
                        <input type="checkbox" checked={visibleColumns.includes(col.key)} onChange={() => toggleColumn(col.key)} className="accent-primary rounded" />
                        {col.label}
                      </label>
                    ))}
                  </div>
                )}
              </div>
              <button onClick={exportCsv} disabled={sortedLogs.length === 0}
                className="inline-flex items-center gap-1.5 px-3 py-2 text-sm font-medium rounded-xl border border-border bg-card hover:bg-secondary/80 text-foreground disabled:opacity-40 disabled:cursor-not-allowed transition-colors">
                <Download className="w-4 h-4" /> Export
              </button>
              <button onClick={() => setShowFilters(!showFilters)}
                className={`inline-flex items-center gap-1.5 px-3 py-2 text-sm font-medium rounded-xl border transition-colors ${showFilters ? 'bg-primary/10 border-primary/30 text-primary' : 'border-border bg-card text-muted-foreground hover:text-foreground hover:bg-secondary/80'}`}>
                <SlidersHorizontal className="w-4 h-4" /> Filters
              </button>
            </div>
          </div>
        </div>

        {/* ── SPL Search Bar (Multi-line) ──────────────────────────────── */}
        <div className="bg-card border border-border rounded-xl shadow-sm">
          <div className="flex items-stretch">
            <div className="flex-1 relative">
              <div className="absolute left-3.5 top-3 text-muted-foreground pointer-events-none">
                <Terminal className="w-4 h-4" />
              </div>
              <textarea
                ref={searchRef}
                placeholder={'SPL Search — e.g.\nsource=syslog severity=high srcIp="10.0.0.1"\naction=login_failure OR action=login_success\n| where riskScore>70'}
                value={searchTerm}
                onChange={e => handleSearchChange(e.target.value)}
                onKeyDown={handleSearchKeyDown}
                onFocus={() => setShowSearchPanel(true)}
                rows={1}
                className="w-full bg-transparent pl-10 pr-20 py-3 text-sm text-foreground font-mono focus:outline-none resize-none min-h-10.5 max-h-30 leading-relaxed"
              />
              <div className="absolute right-2 top-2 flex items-center gap-1">
                {searchTerm && (
                  <button onClick={() => { setSearchTerm(''); setDebouncedSearch(''); setActiveFieldFilters(new Map()); setPage(1); }}
                    title="Clear"
                    className="p-1.5 text-muted-foreground hover:text-foreground rounded-lg hover:bg-secondary/80 transition-colors">
                    <X className="w-3.5 h-3.5" />
                  </button>
                )}
                {searchTerm.trim() && (
                  <>
                    <button onClick={() => setShowSaveDialog(true)}
                      title="Save search"
                      className="p-1.5 text-muted-foreground hover:text-primary rounded-lg hover:bg-primary/10 transition-colors">
                      <Bookmark className="w-3.5 h-3.5" />
                    </button>
                    <button onClick={() => { setSaveAlertName(''); setSaveAlertDesc(''); setSaveAlertError(null); setSaveAlertSuccess(false); setShowSaveAlertDialog(true); }}
                      title="Save as Alert (SPL saved search)"
                      className="p-1.5 text-muted-foreground hover:text-amber-400 rounded-lg hover:bg-amber-400/10 transition-colors">
                      <Bell className="w-3.5 h-3.5" />
                    </button>
                  </>
                )}
                <button onClick={executeSearch}
                  title="Run search (Enter)"
                  className="p-1.5 bg-primary text-white rounded-lg hover:bg-primary/90 transition-colors">
                  <Play className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
            <div className="border-l border-border flex items-center px-3 gap-2 shrink-0">
              <CalendarDays className="w-4 h-4 text-muted-foreground" />
              <select value={timeRange} onChange={e => { setTimeRange(e.target.value); setPage(1); }} aria-label="Time range"
                className="bg-transparent text-sm text-foreground focus:outline-none appearance-none cursor-pointer pr-4">
                {TIME_RANGES.map(r => <option key={r.value} value={r.value}>{r.label}</option>)}
              </select>
            </div>
          </div>

          {/* Syntax hint bar */}
          <div className="border-t border-border/50 px-4 py-1.5 flex items-center gap-4 text-[10px] text-muted-foreground/70">
            <span><kbd className="px-1 py-0.5 bg-secondary rounded text-[9px] font-mono">Enter</kbd> Run</span>
            <span><kbd className="px-1 py-0.5 bg-secondary rounded text-[9px] font-mono">Shift+Enter</kbd> New line</span>
            <span className="text-muted-foreground/50">|</span>
            <span>field=value</span>
            <span>field!=value</span>
            <span>field&gt;N</span>
            <span>NOT field=val</span>
            <span>term1 OR term2</span>
            <span>&quot;exact phrase&quot;</span>
          </div>

          {/* Save search dialog */}
          {showSaveDialog && (
            <div className="border-t border-border px-4 py-3 flex items-center gap-3 bg-secondary/20">
              <Save className="w-4 h-4 text-primary shrink-0" />
              <input
                autoFocus
                placeholder="Search name..."
                value={saveSearchName}
                onChange={e => setSaveSearchName(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter') saveCurrentSearch(); if (e.key === 'Escape') setShowSaveDialog(false); }}
                className="flex-1 bg-input border border-border rounded-lg px-3 py-1.5 text-sm text-foreground focus:outline-none focus:border-primary"
              />
              <button onClick={saveCurrentSearch} disabled={!saveSearchName.trim()} className="px-3 py-1.5 bg-primary text-white text-sm font-medium rounded-lg hover:bg-primary/90 disabled:opacity-40 transition-colors">Save</button>
              <button onClick={() => setShowSaveDialog(false)} className="text-sm text-muted-foreground hover:text-foreground">Cancel</button>
            </div>
          )}
        </div>

        {/* ── Search History / Saved Searches Dropdown ─────────────────── */}
        {showSearchPanel && (savedSearches.length > 0 || recentSearches.length > 0) && (
          <>
            <div className="fixed inset-0 z-20" onClick={() => setShowSearchPanel(false)} />
            <div className="relative z-30 -mt-4">
              <div className="absolute top-0 left-0 right-0 bg-card border border-border rounded-xl shadow-2xl max-h-72 overflow-y-auto">
                {savedSearches.length > 0 && (
                  <div className="p-3">
                    <div className="text-[10px] font-semibold uppercase text-muted-foreground tracking-wider mb-2 flex items-center gap-1.5">
                      <Bookmark className="w-3 h-3" /> Saved Searches
                    </div>
                    {savedSearches.map(s => (
                      <div key={s.id} className="flex items-center gap-2 px-2 py-2 hover:bg-secondary/50 rounded-lg group cursor-pointer transition-colors">
                        <button onClick={() => { loadSearch(s.query); if (s.timeRange) setTimeRange(s.timeRange); }} className="flex-1 text-left">
                          <div className="text-sm font-medium text-foreground">{s.name}</div>
                          <div className="text-xs text-muted-foreground font-mono truncate">{s.query}</div>
                        </button>
                        <button title="Delete saved search" onClick={(e) => { e.stopPropagation(); deleteSavedSearch(s.id); }}
                          className="p-1 text-muted-foreground hover:text-destructive opacity-0 group-hover:opacity-100 transition-all">
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
                {recentSearches.length > 0 && (
                  <div className="p-3 border-t border-border/50">
                    <div className="text-[10px] font-semibold uppercase text-muted-foreground tracking-wider mb-2 flex items-center gap-1.5">
                      <History className="w-3 h-3" /> Recent Searches
                    </div>
                    {recentSearches.slice(0, 8).map((q, i) => (
                      <button key={i} onClick={() => loadSearch(q)}
                        className="w-full text-left px-2 py-1.5 hover:bg-secondary/50 rounded-lg text-sm text-muted-foreground font-mono truncate transition-colors">
                        {q}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </>
        )}

        {/* Active Filter Tags */}
        {hasActiveFilters && (
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs text-muted-foreground">Active:</span>
            {[...activeFieldFilters.entries()].map(([key, { value, negate }]) => {
              const field = key.startsWith('!') ? key.slice(1) : key;
              const fieldDef = FACET_FIELDS.find(f => f.key === field);
              return (
                <span key={key} className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-medium font-mono ${
                  negate ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 'bg-primary/10 text-primary border border-primary/20'
                }`}>
                  {fieldDef && <fieldDef.icon className="w-3 h-3" />}
                  {negate && <span className="font-bold">NOT</span>}
                  {FIELD_LABELS[field] ?? field}={value}
                  <button onClick={() => removeFieldFilter(field)} title="Remove filter" className="hover:opacity-70 ml-0.5"><X className="w-3 h-3" /></button>
                </span>
              );
            })}
            {timeRange && (
              <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-medium bg-primary/10 text-primary border border-primary/20">
                <Clock className="w-3 h-3" />
                {TIME_RANGES.find(t => t.value === timeRange)?.label}
                <button onClick={() => { setTimeRange(''); setPage(1); }} title="Remove time filter" className="hover:opacity-70 ml-0.5"><X className="w-3 h-3" /></button>
              </span>
            )}
            {debouncedSearch.length >= 2 && (
              <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-medium bg-secondary border border-border text-foreground font-mono">
                <Search className="w-3 h-3" />
                &quot;{debouncedSearch.length > 40 ? debouncedSearch.slice(0, 40) + '…' : debouncedSearch}&quot;
                <button onClick={() => { setSearchTerm(''); setDebouncedSearch(''); setPage(1); }} title="Remove search" className="hover:opacity-70 ml-0.5"><X className="w-3 h-3" /></button>
              </span>
            )}
            <button onClick={clearAllFilters}
              className="flex items-center gap-1 px-2 py-1 text-xs text-muted-foreground hover:text-foreground transition-colors">
              <X className="w-3 h-3" /> Clear all
            </button>
          </div>
        )}

        {/* ── Severity Summary Strip ── */}
        <div className="grid grid-cols-3 md:grid-cols-6 gap-3">
          <div className="bg-card border border-border rounded-xl p-3.5 shadow-sm">
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-[10px] text-muted-foreground font-medium uppercase tracking-wider">Events</span>
              <Database className="w-3.5 h-3.5 text-primary" />
            </div>
            <div className="text-xl font-bold text-foreground">{data?.total?.toLocaleString() ?? '—'}</div>
          </div>
          {SEVERITIES.map(sev => {
            const sc = SEVERITY_COLORS[sev];
            const isActive = activeFieldFilters.get('severity')?.value === sev;
            return (
              <button key={sev} onClick={() => isActive ? removeFieldFilter('severity') : addFieldFilter('severity', sev)}
                className={`bg-card border rounded-xl p-3.5 shadow-sm text-left transition-all ${
                  isActive ? `${sc.bg} border-current/30 ring-2 ring-current/20` : 'border-border hover:border-border/80'
                }`}>
                <div className="flex items-center justify-between mb-1.5">
                  <span className={`text-[10px] font-medium uppercase tracking-wider ${sc.text}`}>{sev}</span>
                  <div className={`w-2 h-2 rounded-full ${sc.dot}`} />
                </div>
                <div className={`text-xl font-bold ${severityCounts[sev] > 0 ? sc.text : 'text-muted-foreground/30'}`}>
                  {severityCounts[sev]}
                </div>
              </button>
            );
          })}
        </div>

        {/* ── Classic Filters Panel ────────────────────────────────────── */}
        {showFilters && (
          <div className="bg-card border border-border rounded-xl p-5 flex flex-col md:flex-row gap-6">
            <div className="flex-1">
              <div className="text-[10px] font-semibold uppercase text-muted-foreground tracking-wider mb-2.5">Source</div>
              <div className="flex flex-wrap gap-1.5">
                {dynamicSources.map((s: string) => {
                  const isActive = activeFieldFilters.get('source')?.value === s;
                  return (
                    <button key={s} onClick={() => isActive ? removeFieldFilter('source') : addFieldFilter('source', s)}
                      className={`px-2.5 py-1.5 rounded-lg text-xs font-medium border transition-colors ${isActive ? 'bg-primary/10 border-primary/30 text-primary' : 'border-border text-muted-foreground hover:text-foreground hover:border-border/80'}`}>
                      {s}
                    </button>
                  );
                })}
                {dynamicSources.length === 0 && <span className="text-xs text-muted-foreground italic">No sources yet</span>}
              </div>
            </div>
            <div className="flex-1">
              <div className="text-[10px] font-semibold uppercase text-muted-foreground tracking-wider mb-2.5">Severity</div>
              <div className="flex flex-wrap gap-1.5">
                {SEVERITIES.map(s => {
                  const sc = SEVERITY_COLORS[s];
                  const isActive = activeFieldFilters.get('severity')?.value === s;
                  return (
                    <button key={s} onClick={() => isActive ? removeFieldFilter('severity') : addFieldFilter('severity', s)}
                      className={`px-2.5 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
                        isActive ? `${sc.bg} border-current/30 ${sc.text}` : 'border-border text-muted-foreground hover:text-foreground hover:border-border/80'
                      }`}>
                      <div className="flex items-center gap-1.5">
                        <div className={`w-1.5 h-1.5 rounded-full ${sc.dot}`} />
                        {s}
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>
            {dynamicCategories.length > 0 && (
              <div className="flex-1">
                <div className="text-[10px] font-semibold uppercase text-muted-foreground tracking-wider mb-2.5">Category</div>
                <div className="flex flex-wrap gap-1.5">
                  {dynamicCategories.slice(0, 20).map((c: string) => {
                    const isActive = activeFieldFilters.get('category')?.value === c;
                    return (
                      <button key={c} onClick={() => isActive ? removeFieldFilter('category') : addFieldFilter('category', c)}
                        className={`px-2.5 py-1.5 rounded-lg text-xs font-medium border transition-colors ${isActive ? 'bg-primary/10 border-primary/30 text-primary' : 'border-border text-muted-foreground hover:text-foreground hover:border-border/80'}`}>
                        {c}
                      </button>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── Event Histogram ──────────────────────────────────────────── */}
        <div className="bg-card border border-border rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
              <BarChart3 className="w-4 h-4 text-primary" /> Event Volume
            </h3>
            <div className="flex items-center gap-1 bg-secondary/50 rounded-lg p-0.5">
              {['5m', '15m', '1h', '6h', '1d'].map(iv => (
                <button key={iv} onClick={() => setHistogramInterval(iv)}
                  className={`px-2.5 py-1 text-xs rounded-md font-medium transition-all ${histogramInterval === iv ? 'bg-card text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'}`}>
                  {iv}
                </button>
              ))}
            </div>
          </div>
          {histogramData?.buckets && histogramData.buckets.length > 0 ? (
            <ResponsiveContainer width="100%" height={130}>
              <BarChart data={histogramData.buckets}>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} />
                <XAxis dataKey="bucket" tick={{ fontSize: 10, fill: 'hsl(var(--muted-foreground))' }} tickFormatter={v => safeFormat(v, histogramInterval === '1d' ? 'MM/dd' : 'HH:mm')} />
                <YAxis tick={{ fontSize: 10, fill: 'hsl(var(--muted-foreground))' }} width={40} />
                <Tooltip
                  contentStyle={{ backgroundColor: 'hsl(var(--card))', border: '1px solid hsl(var(--border))', borderRadius: '12px', fontSize: '12px', boxShadow: '0 10px 25px rgba(0,0,0,0.2)' }}
                  labelFormatter={v => safeFormat(v, 'PPp')} />
                <Bar dataKey="count" fill="hsl(var(--primary))" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-32 flex items-center justify-center text-xs text-muted-foreground">No histogram data</div>
          )}
        </div>

        {/* ── Live Tail ────────────────────────────────────────────────── */}
        <div className="flex items-center gap-3">
          <button onClick={() => { setLiveTail(!liveTail); if (liveTail) clearLive(); }}
            className={`inline-flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-xl border transition-all ${
              liveTail ? 'bg-green-500/10 border-green-500/30 text-green-400 shadow-sm shadow-green-500/5' : 'border-border bg-card text-muted-foreground hover:text-foreground hover:bg-secondary/80'
            }`}>
            <Radio className={`w-4 h-4 ${liveTail && liveConnected ? 'animate-pulse' : ''}`} />
            {liveTail ? 'Stop Live Tail' : 'Live Tail'}
          </button>
          {liveTail && (
            <span className="text-xs text-muted-foreground flex items-center gap-1.5">
              {liveConnected ? (
                <><Activity className="w-3 h-3 text-green-400" /> Connected · {liveEvents.length} events</>
              ) : (
                <><Loader2 className="w-3 h-3 animate-spin" /> Connecting…</>
              )}
            </span>
          )}
        </div>

        {liveTail && liveEvents.length > 0 && (
          <div className="bg-[#050810] border border-green-500/20 rounded-xl overflow-hidden max-h-64 overflow-y-auto shadow-lg shadow-green-500/5">
            <div className="px-4 py-2.5 text-xs font-medium text-green-400 bg-green-500/5 border-b border-green-500/10 flex items-center gap-2 sticky top-0 z-10 backdrop-blur-sm">
              <Radio className="w-3 h-3 animate-pulse" /> Live Stream
              <span className="ml-auto text-green-400/60">{liveEvents.length} events</span>
            </div>
            <div className="p-2.5 space-y-0.5 font-mono text-xs">
              {liveEvents.slice(0, 100).map((ev, i) => (
                <div key={i} className="flex gap-2.5 text-gray-300 hover:text-white hover:bg-white/5 rounded px-1.5 py-0.5 transition-colors">
                  <span className="text-muted-foreground shrink-0">{safeFormat(ev.timestamp ?? Date.now(), 'HH:mm:ss')}</span>
                  <span className={`shrink-0 w-16 ${ev.severity === 'critical' ? 'text-red-400' : ev.severity === 'high' ? 'text-orange-400' : ev.severity === 'medium' ? 'text-yellow-400' : 'text-blue-400'}`}>
                    {ev.severity ?? 'info'}
                  </span>
                  <span className="text-primary shrink-0">[{ev.source ?? 'unknown'}]</span>
                  <span className="truncate">{ev.message ?? JSON.stringify(ev)}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── Main Content: Sidebar + Table ────────────────────────────── */}
        <div className="flex gap-5">
          {/* Field Sidebar */}
          {showFieldSidebar && (
            <div className="w-64 shrink-0 space-y-1 hidden lg:block">
              <div className="bg-card border border-border rounded-xl shadow-sm overflow-hidden">
                <div className="px-4 py-3 border-b border-border bg-secondary/20">
                  <h3 className="text-xs font-semibold text-foreground uppercase tracking-wider flex items-center gap-2">
                    <SlidersHorizontal className="w-3.5 h-3.5 text-primary" /> Fields
                  </h3>
                  <div className="mt-2 relative">
                    <Search className="w-3 h-3 absolute left-2 top-1/2 -translate-y-1/2 text-muted-foreground" />
                    <input
                      type="text"
                      placeholder="Filter fields…"
                      value={fieldSearch}
                      onChange={e => setFieldSearch(e.target.value)}
                      className="w-full bg-input border border-border rounded-md pl-7 pr-2 py-1 text-[11px] text-foreground focus:outline-none focus:border-primary/50 placeholder:text-muted-foreground/50"
                    />
                    {fieldSearch && (
                      <button onClick={() => setFieldSearch('')} title="Clear field search" className="absolute right-1.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
                        <X className="w-3 h-3" />
                      </button>
                    )}
                  </div>
                </div>
                <div className="max-h-[calc(100vh-400px)] overflow-y-auto divide-y divide-border/30">
                  {FACET_FIELDS.filter(f => !fieldSearch || f.label.toLowerCase().includes(fieldSearch.toLowerCase()) || f.key.toLowerCase().includes(fieldSearch.toLowerCase())).map(field => {
                    const values = facets[field.key] ?? [];
                    const isExpanded = expandedFacet === field.key;
                    const activeEntry = activeFieldFilters.get(field.key);
                    const negatedEntry = activeFieldFilters.get(`!${field.key}`);
                    const activeValue = activeEntry?.value;
                    const total = values.reduce((s, v) => s + v.count, 0);

                    return (
                      <div key={field.key}>
                        <button
                          onClick={() => setExpandedFacet(isExpanded ? null : field.key)}
                          className={`w-full flex items-center gap-2.5 px-4 py-2.5 text-left hover:bg-secondary/40 transition-colors ${isExpanded ? 'bg-secondary/20' : ''}`}>
                          <field.icon className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                          <span className="text-xs font-medium text-foreground flex-1 truncate">{field.label}</span>
                          {(activeValue || negatedEntry) && <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${negatedEntry ? 'bg-red-400' : 'bg-primary'}`} />}
                          <span className="text-[10px] text-muted-foreground font-mono">{values.length > 0 ? values.length : '—'}</span>
                          <ChevronR className={`w-3 h-3 text-muted-foreground transition-transform ${isExpanded ? 'rotate-90' : ''}`} />
                        </button>
                        {isExpanded && values.length > 0 && (
                          <div className="px-3 pb-2 space-y-0.5">
                            {values.map(v => {
                              const isSelected = activeValue === v.value;
                              const isNegated = negatedEntry?.value === v.value;
                              const pct = total > 0 ? (v.count / total) * 100 : 0;
                              return (
                                <div
                                  key={v.value}
                                  className={`w-full flex items-center gap-1.5 px-2 py-1.5 rounded-md text-left transition-colors group ${
                                    isSelected ? 'bg-primary/10 ring-1 ring-primary/20' : isNegated ? 'bg-red-500/10 ring-1 ring-red-500/20' : 'hover:bg-secondary/50'
                                  }`}>
                                  <div className="flex-1 min-w-0 cursor-pointer" onClick={() => isSelected ? removeFieldFilter(field.key) : addFieldFilter(field.key, v.value)}>
                                    <div className="flex items-center justify-between gap-2">
                                      <span className={`text-[11px] font-mono truncate ${isSelected ? 'text-primary font-medium' : isNegated ? 'text-red-400 line-through' : 'text-foreground'}`}>
                                        {v.value}
                                      </span>
                                      <span className="text-[10px] text-muted-foreground font-mono shrink-0">{v.count.toLocaleString()}</span>
                                    </div>
                                    <div className="mt-1 h-1 bg-secondary rounded-full overflow-hidden">
                                      <div className={`h-full rounded-full transition-all ${isSelected ? 'bg-primary' : isNegated ? 'bg-red-400/50' : 'bg-muted-foreground/30 group-hover:bg-primary/50'}`}
                                        style={{ width: `${Math.max(2, pct)}%` }} />
                                    </div>
                                    <span className="text-[9px] text-muted-foreground/60 font-mono">{pct.toFixed(1)}%</span>
                                  </div>
                                  {/* Include / Exclude buttons */}
                                  <div className="flex flex-col gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity shrink-0">
                                    <button
                                      onClick={(e) => { e.stopPropagation(); addFieldFilter(field.key, v.value, false); }}
                                      title={`Include ${field.label}=${v.value}`}
                                      className={`w-4 h-4 rounded flex items-center justify-center text-[10px] font-bold transition-colors ${isSelected ? 'bg-primary text-white' : 'bg-secondary hover:bg-primary/20 text-muted-foreground hover:text-primary'}`}>
                                      +
                                    </button>
                                    <button
                                      onClick={(e) => { e.stopPropagation(); addFieldFilter(field.key, v.value, true); }}
                                      title={`Exclude ${field.label}=${v.value}`}
                                      className={`w-4 h-4 rounded flex items-center justify-center text-[10px] font-bold transition-colors ${isNegated ? 'bg-red-500 text-white' : 'bg-secondary hover:bg-red-500/20 text-muted-foreground hover:text-red-400'}`}>
                                      −
                                    </button>
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        )}
                        {isExpanded && values.length === 0 && (
                          <div className="px-4 pb-2 text-[10px] text-muted-foreground italic">No values</div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}

          {/* Event Table */}
          <div className="flex-1 min-w-0">
            <div className="bg-card border border-border rounded-xl shadow-lg shadow-black/10 flex flex-col overflow-hidden">
              <div className="overflow-x-auto">
                {isLoading ? (
                  <div className="flex items-center justify-center py-20 gap-3 text-muted-foreground">
                    <Loader2 className="w-6 h-6 animate-spin text-primary" /> Loading events…
                  </div>
                ) : sortedLogs.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-20 gap-4">
                    <div className="w-16 h-16 rounded-full bg-secondary flex items-center justify-center">
                      <Database className="w-8 h-8 text-muted-foreground/30" />
                    </div>
                    <p className="text-sm font-medium text-muted-foreground">No log events found</p>
                    <p className="text-xs text-muted-foreground/60">
                      {hasActiveFilters
                        ? 'Try adjusting your filters or search query'
                        : 'Ingest logs via POST /api/ingest-log to see events here'}
                    </p>
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
                        {visibleColumns.map(colKey => {
                          const col = ALL_COLUMNS.find(c => c.key === colKey)!;
                          return (
                            <th key={col.key}
                              className={`px-4 py-3 font-medium ${col.sortable ? 'cursor-pointer hover:text-foreground transition-colors' : ''} ${col.key === 'message' ? 'min-w-75' : ''}`}
                              onClick={() => col.sortable && handleSort(col.key as SortKey)}>
                              <div className="flex items-center gap-1">{col.label} {col.sortable && <SortIcon col={col.key as SortKey} />}</div>
                            </th>
                          );
                        })}
                        <th className="px-4 py-3 w-10" />
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border/30">
                      {sortedLogs.map(log => {
                        const sevColor = SEVERITY_COLORS[log.severity] || SEVERITY_COLORS.info;
                        const isExpanded = expandedLogId === log.id;
                        const stBadge = log.sourcetype ? (SOURCETYPE_BADGE[log.sourcetype] ?? { label: log.sourcetype.toUpperCase(), cls: 'bg-secondary text-muted-foreground border-border' }) : null;
                        return (
                          <React.Fragment key={log.id}>
                          <tr
                            className={`hover:bg-secondary/40 transition-all cursor-pointer group ${isExpanded ? 'bg-primary/5 border-b-0' : ''} ${selectedLog?.id === log.id ? 'ring-1 ring-inset ring-primary/20' : ''}`}
                            onClick={() => setExpandedLogId(isExpanded ? null : log.id)}>
                            {visibleColumns.map(colKey => {
                              if (colKey === 'timestamp') return (
                                <td key={colKey} className="px-4 py-3">
                                  <div className="flex flex-col gap-0.5">
                                    <span className="font-mono text-xs text-muted-foreground whitespace-nowrap">{safeFormat(log.timestamp, 'MM-dd HH:mm:ss')}</span>
                                    <span className="text-[10px] text-muted-foreground/50">{timeAgo(log.timestamp)}</span>
                                  </div>
                                </td>
                              );
                              if (colKey === 'source') return (
                                <td key={colKey} className="px-4 py-3">
                                  <button onClick={(e) => { e.stopPropagation(); addFieldFilter('source', log.source); }}
                                    className="font-mono text-xs bg-secondary border border-border px-2 py-0.5 rounded-md text-foreground hover:border-primary/50 hover:text-primary transition-colors"
                                    title={`Filter by source=${log.source}`}>
                                    {log.source}
                                  </button>
                                </td>
                              );
                              if (colKey === 'severity') return (
                                <td key={colKey} className="px-0 py-3">
                                  <div className="flex items-center gap-2">
                                    <div className={`w-1 h-6 rounded-full ${sevColor.bar} shrink-0`} />
                                    <SeverityBadge severity={log.severity} />
                                  </div>
                                </td>
                              );
                              if (colKey === 'category') return <td key={colKey} className="px-4 py-3 font-mono text-xs text-muted-foreground">{log.category ?? '—'}</td>;
                              if (colKey === 'eventType') return <td key={colKey} className="px-4 py-3 font-mono text-xs text-foreground">{log.eventType}</td>;
                              if (colKey === 'sourceIp') return (
                                <td key={colKey} className="px-4 py-3">
                                  {log.sourceIp ? (
                                    <button onClick={(e) => { e.stopPropagation(); addFieldFilter('sourceIp', log.sourceIp); }}
                                      className="font-mono text-xs text-muted-foreground hover:text-primary transition-colors"
                                      title={`Filter by srcIp=${log.sourceIp}`}>
                                      {log.sourceIp}
                                    </button>
                                  ) : <span className="text-xs text-muted-foreground/40">—</span>}
                                </td>
                              );
                              if (colKey === 'destIp') return (
                                <td key={colKey} className="px-4 py-3">
                                  {log.destIp ? (
                                    <button onClick={(e) => { e.stopPropagation(); addFieldFilter('destIp', log.destIp); }}
                                      className="font-mono text-xs text-muted-foreground hover:text-primary transition-colors"
                                      title={`Filter by dstIp=${log.destIp}`}>
                                      {log.destIp}
                                    </button>
                                  ) : <span className="text-xs text-muted-foreground/40">—</span>}
                                </td>
                              );
                              if (colKey === 'riskScore') return (
                                <td key={colKey} className="px-4 py-3">
                                  {log.riskScore != null && log.riskScore > 0 ? (
                                    <span className={`font-mono text-xs font-semibold px-2 py-0.5 rounded-md ${log.riskScore >= 70 ? 'bg-red-500/15 text-red-400' : log.riskScore >= 40 ? 'bg-orange-500/15 text-orange-400' : 'bg-green-500/15 text-green-400'}`}>
                                      {log.riskScore}
                                    </span>
                                  ) : <span className="text-xs text-muted-foreground/40">—</span>}
                                </td>
                              );
                              if (colKey === 'message') return (
                                <td key={colKey} className="px-4 py-3 text-xs text-muted-foreground">
                                  <span className="truncate block max-w-[320px]">{log.message}</span>
                                </td>
                              );
                              return null;
                            })}
                            <td className="px-4 py-3">
                              <div className="flex items-center gap-1">
                                {stBadge && (
                                  <span className={`hidden xl:inline-block text-[9px] font-mono font-bold px-1 py-0.5 rounded border ${stBadge.cls} opacity-0 group-hover:opacity-100 transition-opacity`}>
                                    {stBadge.label}
                                  </span>
                                )}
                                <button aria-label="View log details" onClick={(e) => { e.stopPropagation(); setSelectedLog(log); }}
                                  className="p-1.5 text-muted-foreground hover:text-primary hover:bg-primary/10 rounded-lg transition-colors opacity-0 group-hover:opacity-100">
                                  <Eye className="w-4 h-4" />
                                </button>
                                <ChevronDown className={`w-3.5 h-3.5 text-muted-foreground transition-transform duration-200 opacity-0 group-hover:opacity-100 ${isExpanded ? 'rotate-180 opacity-100' : ''}`} />
                              </div>
                            </td>
                          </tr>
                          {isExpanded && (
                            <tr className="bg-secondary/5 border-b border-primary/10">
                              <td colSpan={(visibleColumns.length + 1)} className="p-0">
                                <div className="px-6 py-4 space-y-3">
                                  {/* Header row */}
                                  <div className="flex items-center gap-3 pb-2 border-b border-border/40">
                                    <span className="font-mono text-xs text-muted-foreground">{safeFormat(log.timestamp, 'yyyy-MM-dd HH:mm:ss.SSS')}</span>
                                    <SeverityBadge severity={log.severity} />
                                    {stBadge && <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border ${stBadge.cls}`}>{stBadge.label}</span>}
                                    {log.source && <span className="font-mono text-xs bg-secondary border border-border px-2 py-0.5 rounded">{log.source}</span>}
                                    {log.indexName && <span className="text-[10px] text-muted-foreground font-mono">index={log.indexName}</span>}
                                    <button onClick={(e) => { e.stopPropagation(); setSelectedLog(log); }}
                                      className="ml-auto text-xs text-primary hover:underline flex items-center gap-1">
                                      <Eye className="w-3 h-3" /> Full detail
                                    </button>
                                  </div>
                                  {/* Message */}
                                  {log.message && (
                                    <div className="flex gap-2">
                                      <span className="text-[11px] font-semibold text-muted-foreground w-24 shrink-0 pt-0.5">message</span>
                                      <p className="text-xs text-foreground font-mono leading-relaxed break-all">{log.message}</p>
                                    </div>
                                  )}
                                  {/* Field grid */}
                                  <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-x-6 gap-y-1.5">
                                    {([
                                      ['hostname', log.hostname],
                                      ['sourceIp', log.sourceIp],
                                      ['destIp', log.destIp],
                                      ['srcPort', log.srcPort],
                                      ['dstPort', log.dstPort],
                                      ['protocol', log.protocol],
                                      ['category', log.category],
                                      ['eventType', log.eventType],
                                      ['action', log.action],
                                      ['outcome', log.outcome],
                                      ['user', log.user],
                                      ['process', log.processName],
                                      ['pid', log.processId],
                                      ['httpMethod', log.httpMethod],
                                      ['httpUrl', log.httpUrl],
                                      ['httpStatus', log.httpStatusCode],
                                      ['dnsQuery', log.dnsQuery],
                                      ['geoCountry', log.geoCountry],
                                      ['riskScore', log.riskScore],
                                    ] as [string, any][]).filter(([, v]) => v != null && v !== '').map(([k, v]) => (
                                      <div key={k} className="flex items-baseline gap-2 min-w-0">
                                        <button onClick={(e) => { e.stopPropagation(); addFieldFilter(k, String(v)); }}
                                          className="text-[11px] font-semibold text-primary/70 hover:text-primary shrink-0 font-mono" title={`Filter ${k}=${v}`}>
                                          {k}
                                        </button>
                                        <span className="text-xs text-muted-foreground font-mono truncate">=</span>
                                        <span className="text-xs text-foreground font-mono truncate">{String(v)}</span>
                                      </div>
                                    ))}
                                  </div>
                                  {/* Raw JSON toggle */}
                                  {log.rawLog && (
                                    <details className="group/raw">
                                      <summary className="text-[11px] text-muted-foreground cursor-pointer select-none hover:text-foreground flex items-center gap-1">
                                        <Code2 className="w-3 h-3" /> Raw event
                                      </summary>
                                      <pre className="mt-2 text-[10px] font-mono text-muted-foreground bg-black/30 rounded-lg p-3 overflow-x-auto max-h-48 whitespace-pre-wrap break-all">{log.rawLog}</pre>
                                    </details>
                                  )}
                                </div>
                              </td>
                            </tr>
                          )}
                          </React.Fragment>
                        );
                      })}
                    </tbody>
                  </table>
                )}
              </div>

              {/* Pagination */}
              {totalPages > 1 && (
                <div className="p-3.5 border-t border-border bg-secondary/20 flex items-center justify-between text-xs text-muted-foreground">
                  <div className="flex items-center gap-2">
                    Page <span className="font-medium text-foreground">{page}</span> of <span className="font-medium text-foreground">{totalPages}</span>
                    <span className="text-muted-foreground/50">·</span>
                    <span className="font-medium text-foreground">{data?.total.toLocaleString()}</span> total events
                  </div>
                  <div className="flex items-center gap-1">
                    <button aria-label="First page" onClick={() => setPage(1)} disabled={page === 1}
                      className="p-2 hover:bg-secondary rounded-lg disabled:opacity-30 transition-colors"><ChevronsLeft className="w-3.5 h-3.5" /></button>
                    <button aria-label="Previous page" onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                      className="p-2 hover:bg-secondary rounded-lg disabled:opacity-30 transition-colors"><ChevronLeft className="w-3.5 h-3.5" /></button>
                    <span className="px-3 py-1.5 font-mono text-foreground font-medium bg-secondary rounded-lg">{page}</span>
                    <button aria-label="Next page" onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}
                      className="p-2 hover:bg-secondary rounded-lg disabled:opacity-30 transition-colors"><ChevronRight className="w-3.5 h-3.5" /></button>
                    <button aria-label="Last page" onClick={() => setPage(totalPages)} disabled={page === totalPages}
                      className="p-2 hover:bg-secondary rounded-lg disabled:opacity-30 transition-colors"><ChevronsRight className="w-3.5 h-3.5" /></button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* ── Log Detail Side Panel ────────────────────────────────────── */}
      {selectedLog && (
        <>
          <div className="fixed inset-0 z-40 bg-black/40 backdrop-blur-sm" onClick={() => setSelectedLog(null)} />
          <div className="fixed right-0 top-0 z-50 h-full w-full max-w-2xl bg-card border-l border-primary/30 shadow-2xl overflow-y-auto animate-in slide-in-from-right duration-200">
            {/* Panel Header */}
            <div className="sticky top-0 bg-card/95 backdrop-blur-md border-b border-border px-5 py-4 flex items-center justify-between z-10">
              <h3 className="font-semibold text-foreground flex items-center gap-2.5">
                <Eye className="w-4 h-4 text-primary" /> Event Detail
                <SeverityBadge severity={selectedLog.severity} />
                {selectedLog.riskScore != null && selectedLog.riskScore > 0 && (
                  <span className={`ml-1 font-mono text-xs font-bold px-2 py-0.5 rounded-md ${selectedLog.riskScore >= 70 ? 'bg-red-500/15 text-red-400' : selectedLog.riskScore >= 40 ? 'bg-orange-500/15 text-orange-400' : 'bg-green-500/15 text-green-400'}`}>
                    Risk: {selectedLog.riskScore}
                  </span>
                )}
              </h3>
              <button aria-label="Close detail" onClick={() => setSelectedLog(null)}
                className="p-2 rounded-xl hover:bg-secondary text-muted-foreground hover:text-foreground transition-colors">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-5 space-y-5">
              {/* Tags */}
              {selectedLog.tags && selectedLog.tags.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {selectedLog.tags.map((t: string) => (
                    <span key={t} className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-medium border border-primary/30 bg-primary/5 text-primary">
                      <Tag className="w-3 h-3" />{t}
                    </span>
                  ))}
                </div>
              )}

              {/* Message */}
              <div>
                <div className="text-[10px] font-semibold uppercase text-muted-foreground tracking-wider mb-1.5">Message</div>
                <div className="text-sm text-foreground bg-secondary/50 rounded-xl p-4 border border-border leading-relaxed">{selectedLog.message}</div>
              </div>

              {/* Grouped Fields */}
              {(() => {
                const groups: { title: string; icon: React.ReactNode; fields: [string, unknown][] }[] = [
                  {
                    title: 'Core', icon: <Database className="w-3.5 h-3.5" />,
                    fields: [
                      ['ID', selectedLog.id], ['Timestamp', safeFormat(selectedLog.timestamp, 'PPpp')],
                      ['Source', selectedLog.source], ['Severity', selectedLog.severity],
                      ['Category', selectedLog.category], ['Event Type', selectedLog.eventType],
                      ['Action', selectedLog.action], ['Outcome', selectedLog.outcome],
                    ],
                  },
                  {
                    title: 'Network', icon: <Globe className="w-3.5 h-3.5" />,
                    fields: [
                      ['Source IP', selectedLog.sourceIp], ['Source Port', selectedLog.srcPort],
                      ['Dest IP', selectedLog.destIp], ['Dest Port', selectedLog.dstPort],
                      ['Protocol', selectedLog.protocol], ['Direction', selectedLog.direction],
                      ['Bytes In', selectedLog.bytesIn], ['Bytes Out', selectedLog.bytesOut],
                    ],
                  },
                  {
                    title: 'User & Auth', icon: <Shield className="w-3.5 h-3.5" />,
                    fields: [
                      ['Username', selectedLog.user], ['Target User', selectedLog.targetUsername],
                      ['Logon Type', selectedLog.logonType], ['Hostname', selectedLog.hostname],
                    ],
                  },
                  {
                    title: 'Process', icon: <Zap className="w-3.5 h-3.5" />,
                    fields: [
                      ['Process Name', selectedLog.processName], ['Process ID', selectedLog.processId],
                      ['Parent PID', selectedLog.parentProcessId], ['Command Line', selectedLog.processCommandLine],
                    ],
                  },
                  {
                    title: 'HTTP', icon: <Globe className="w-3.5 h-3.5" />,
                    fields: [
                      ['Method', selectedLog.httpMethod], ['URL', selectedLog.httpUrl],
                      ['Status Code', selectedLog.httpStatusCode], ['User Agent', selectedLog.httpUserAgent],
                    ],
                  },
                  {
                    title: 'DNS', icon: <Search className="w-3.5 h-3.5" />,
                    fields: [['Query', selectedLog.dnsQuery], ['Response Code', selectedLog.dnsResponseCode]],
                  },
                  {
                    title: 'File', icon: <Database className="w-3.5 h-3.5" />,
                    fields: [
                      ['File Name', selectedLog.fileName], ['File Path', selectedLog.filePath],
                      ['File Hash', selectedLog.fileHash],
                    ],
                  },
                  {
                    title: 'Registry', icon: <Database className="w-3.5 h-3.5" />,
                    fields: [['Registry Key', selectedLog.registryKey], ['Registry Value', selectedLog.registryValue]],
                  },
                  {
                    title: 'Vendor', icon: <Shield className="w-3.5 h-3.5" />,
                    fields: [
                      ['Vendor Name', selectedLog.vendorName], ['Vendor Product', selectedLog.vendorProduct],
                      ['Device Action', selectedLog.deviceAction],
                    ],
                  },
                  {
                    title: 'Geo & Enrichment', icon: <Globe className="w-3.5 h-3.5" />,
                    fields: [
                      ['Src Country', selectedLog.geoCountry], ['Src City', selectedLog.geoCity],
                      ['Dst Country', selectedLog.geoCountryDst], ['Dst City', selectedLog.geoCityDst],
                      ['Risk Score', selectedLog.riskScore], ['Asset Criticality', selectedLog.assetCriticality],
                    ],
                  },
                ];

                return groups.map(g => {
                  const populated = g.fields.filter(([, v]) => v != null && v !== '' && v !== '—' && v !== 'unknown' && v !== '0.0.0.0');
                  if (populated.length === 0) return null;
                  return (
                    <div key={g.title}>
                      <div className="flex items-center gap-1.5 text-[10px] font-semibold uppercase text-muted-foreground tracking-wider mb-2">
                        {g.icon} {g.title}
                      </div>
                      <div className="grid grid-cols-2 gap-x-4 gap-y-2 bg-secondary/30 rounded-xl p-4 border border-border/50">
                        {populated.map(([k, v]) => {
                          const filterKey = DETAIL_FIELD_TO_FILTER[k];
                          return (
                            <div key={k} className="flex flex-col group/field">
                              <span className="text-[10px] text-muted-foreground">{k}</span>
                              <div className="flex items-center gap-1.5">
                                <span className="font-mono text-xs text-foreground break-all">{String(v)}</span>
                                <div className="opacity-0 group-hover/field:opacity-100 flex items-center gap-0.5 shrink-0 transition-all">
                                  {filterKey && (
                                    <>
                                      <button
                                        onClick={(e) => { e.stopPropagation(); addFieldFilter(filterKey, String(v)); setSelectedLog(null); }}
                                        className="p-0.5 text-muted-foreground hover:text-primary transition-colors"
                                        title={`Include ${k}=${String(v)}`}>
                                        <Search className="w-3 h-3" />
                                      </button>
                                      <button
                                        onClick={(e) => { e.stopPropagation(); addFieldFilter(filterKey, String(v), true); setSelectedLog(null); }}
                                        className="p-0.5 text-muted-foreground hover:text-red-400 transition-colors"
                                        title={`Exclude ${k}=${String(v)}`}>
                                        <X className="w-3 h-3" />
                                      </button>
                                    </>
                                  )}
                                  <button
                                    onClick={(e) => { e.stopPropagation(); copyToClipboard(String(v), `${g.title}-${k}`); }}
                                    className="p-0.5 text-muted-foreground hover:text-primary transition-colors"
                                    title="Copy value">
                                    {copiedField === `${g.title}-${k}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                                  </button>
                                </div>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  );
                });
              })()}

              {/* Raw Log */}
              {selectedLog.rawLog && (
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <div className="text-[10px] font-semibold uppercase text-muted-foreground tracking-wider">Raw Log</div>
                    <button onClick={() => copyToClipboard(selectedLog.rawLog!, 'rawLog')}
                      className="text-xs text-muted-foreground hover:text-primary flex items-center gap-1 transition-colors">
                      {copiedField === 'rawLog' ? <><Check className="w-3 h-3 text-emerald-400" /> Copied</> : <><Copy className="w-3 h-3" /> Copy</>}
                    </button>
                  </div>
                  <pre className="text-xs font-mono text-green-400 bg-[#050810] border border-border rounded-xl p-4 overflow-x-auto whitespace-pre-wrap break-all max-h-80">{selectedLog.rawLog}</pre>
                </div>
              )}
            </div>
          </div>
        </>
      )}

      {/* ── Save as Alert Modal ─────────────────────────────────────────── */}
      {showSaveAlertDialog && (
        <>
          <div className="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm" onClick={() => setShowSaveAlertDialog(false)} />
          <div className="fixed inset-0 z-50 flex items-center justify-center pointer-events-none">
            <div className="bg-card border border-border rounded-2xl shadow-2xl w-full max-w-lg mx-4 pointer-events-auto overflow-hidden">
              {/* Header */}
              <div className="flex items-center justify-between px-6 py-4 border-b border-border bg-secondary/20">
                <div className="flex items-center gap-2.5">
                  <Bell className="w-5 h-5 text-amber-400" />
                  <h2 className="font-semibold text-foreground">Save as Alert</h2>
                  <span className="text-[10px] font-mono font-bold bg-amber-500/10 text-amber-400 border border-amber-500/20 px-1.5 py-0.5 rounded">SPL SAVED SEARCH</span>
                </div>
                <button onClick={() => setShowSaveAlertDialog(false)} className="text-muted-foreground hover:text-foreground transition-colors">
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="p-6 space-y-4">
                {/* SPL preview */}
                <div className="bg-black/30 border border-border/50 rounded-xl px-4 py-3">
                  <div className="text-[10px] font-semibold uppercase text-muted-foreground tracking-wider mb-1.5 flex items-center gap-1.5">
                    <Terminal className="w-3 h-3" /> Search Query
                  </div>
                  <p className="text-xs font-mono text-primary/90 break-all leading-relaxed line-clamp-3">{searchTerm}</p>
                </div>

                {/* Alert name */}
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Alert Name *</label>
                  <input
                    autoFocus
                    value={saveAlertName}
                    onChange={e => setSaveAlertName(e.target.value)}
                    placeholder="e.g., High severity brute force detection"
                    className="w-full bg-input border border-border rounded-xl px-4 py-2.5 text-sm text-foreground focus:outline-none focus:border-primary transition-colors"
                  />
                </div>

                {/* Description */}
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Description</label>
                  <input
                    value={saveAlertDesc}
                    onChange={e => setSaveAlertDesc(e.target.value)}
                    placeholder="Optional description..."
                    className="w-full bg-input border border-border rounded-xl px-4 py-2.5 text-sm text-foreground focus:outline-none focus:border-primary transition-colors"
                  />
                </div>

                {/* Severity + Schedule + Threshold row */}
                <div className="grid grid-cols-3 gap-3">
                  <div className="space-y-1.5">
                    <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Severity</label>
                    <select value={saveAlertSeverity} onChange={e => setSaveAlertSeverity(e.target.value)}
                      className="w-full bg-input border border-border rounded-xl px-3 py-2.5 text-sm text-foreground focus:outline-none focus:border-primary transition-colors appearance-none cursor-pointer">
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                      <option value="info">Info</option>
                    </select>
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Schedule</label>
                    <select value={saveAlertInterval} onChange={e => setSaveAlertInterval(e.target.value)}
                      className="w-full bg-input border border-border rounded-xl px-3 py-2.5 text-sm text-foreground focus:outline-none focus:border-primary transition-colors appearance-none cursor-pointer">
                      {SCHEDULE_INTERVALS.map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
                    </select>
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Threshold</label>
                    <input
                      type="number"
                      min={1}
                      value={saveAlertThreshold}
                      onChange={e => setSaveAlertThreshold(Math.max(1, Number(e.target.value)))}
                      className="w-full bg-input border border-border rounded-xl px-3 py-2.5 text-sm text-foreground focus:outline-none focus:border-primary transition-colors"
                    />
                  </div>
                </div>

                {saveAlertError && (
                  <div className="flex items-center gap-2 text-destructive text-sm bg-destructive/10 border border-destructive/20 rounded-xl px-4 py-3">
                    <AlertTriangle className="w-4 h-4 shrink-0" />
                    {saveAlertError}
                  </div>
                )}

                {saveAlertSuccess && (
                  <div className="flex items-center gap-2 text-emerald-400 text-sm bg-emerald-500/10 border border-emerald-500/20 rounded-xl px-4 py-3">
                    <Check className="w-4 h-4 shrink-0" />
                    Alert saved successfully! Rule will run on schedule.
                  </div>
                )}
              </div>

              {/* Footer */}
              <div className="px-6 py-4 border-t border-border bg-secondary/10 flex items-center justify-end gap-3">
                <button onClick={() => setShowSaveAlertDialog(false)} className="px-4 py-2 text-sm text-muted-foreground hover:text-foreground transition-colors">Cancel</button>
                <button
                  onClick={saveSplAsAlert}
                  disabled={!saveAlertName.trim() || saveAlertLoading || saveAlertSuccess}
                  className="px-5 py-2 bg-amber-500 hover:bg-amber-400 disabled:opacity-40 text-black font-semibold text-sm rounded-xl transition-colors flex items-center gap-2"
                >
                  {saveAlertLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Bell className="w-4 h-4" />}
                  {saveAlertLoading ? 'Saving…' : 'Create Alert'}
                </button>
              </div>
            </div>
          </div>
        </>
      )}
    </>
  );
}
