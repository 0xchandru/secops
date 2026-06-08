import React, { useState, useRef, useCallback, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { ingestApi, logsApi } from '@/lib/api';
import {
  Database, Upload, CheckCircle2, AlertTriangle, XCircle, FileText,
  Activity, Wifi, Server, Plus, ChevronDown, ChevronRight, Eye, RefreshCw, Loader2,
  Terminal, BarChart3, RotateCcw, Send
} from 'lucide-react';

type IngestionStatus = 'idle' | 'parsing' | 'uploading' | 'success' | 'error';

interface ParsedResult {
  count: number;
  records: Record<string, unknown>[];
  errors: string[];
}

function parseSyslogLine(line: string): Record<string, unknown> {
  const syslogRe = /^(\w{3}\s+\d+\s+[\d:]+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)$/;
  const m = line.match(syslogRe);
  if (m) {
    return { timestamp: m[1], hostname: m[2], process: m[3], pid: m[4], message: line.trim(), source: 'syslog', severity: 'info', rawLine: line };
  }
  return { message: line.trim(), source: 'syslog', severity: 'info', rawLine: line };
}

function detectAndParse(content: string, filename: string): ParsedResult {
  const ext = filename.split('.').pop()?.toLowerCase() ?? '';
  const errors: string[] = [];

  // JSONL: one JSON object per line
  if (ext === 'jsonl' || ext === 'ndjson') {
    const lines = content.split('\n').filter(l => l.trim());
    const records: Record<string, unknown>[] = [];
    lines.forEach((line, i) => {
      try { records.push(JSON.parse(line)); }
      catch { errors.push(`Line ${i + 1}: invalid JSON — skipped`); }
    });
    return { count: records.length, records, errors };
  }

  if (ext === 'json' || (!ext && content.trimStart().startsWith('['))) {
    try {
      const parsed = JSON.parse(content);
      const records = Array.isArray(parsed) ? parsed : [parsed];
      return { count: records.length, records, errors };
    } catch {
      const lines = content.split('\n').filter(l => l.trim());
      const records: Record<string, unknown>[] = [];
      lines.forEach((line, i) => {
        try { records.push(JSON.parse(line)); }
        catch { errors.push(`Line ${i + 1}: invalid JSON — skipped`); }
      });
      return { count: records.length, records, errors };
    }
  }

  if (ext === 'csv') {
    const lines = content.split('\n').filter(l => l.trim());
    if (lines.length < 2) return { count: 0, records: [], errors: ['CSV has no data rows'] };
    const headers = lines[0].split(',').map(h => h.trim().replace(/^"|"$/g, ''));
    const records = lines.slice(1).map(line => {
      const values = line.split(',').map(v => v.trim().replace(/^"|"$/g, ''));
      return Object.fromEntries(headers.map((h, i) => [h, values[i] ?? '']));
    });
    return { count: records.length, records, errors };
  }

  const lines = content.split('\n').filter(l => l.trim());
  const records = lines.map(parseSyslogLine);
  return { count: records.length, records, errors };
}

const SOURCE_CONFIGS: { id: number; name: string; type: string; status: 'active' | 'warning' | 'error'; format: string; host: string }[] = [];

const statusIcon = (s: 'active' | 'warning' | 'error') => ({
  active: <><span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-60" /><span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500" /></>,
  warning: <span className="relative inline-flex rounded-full h-3 w-3 bg-amber-500" />,
  error: <span className="relative inline-flex rounded-full h-3 w-3 bg-destructive" />,
}[s]);

const statusLabel = { active: 'Active', warning: 'Degraded', error: 'Offline' };

const severityColor: Record<string, string> = {
  critical: 'text-red-400', high: 'text-orange-400', medium: 'text-yellow-400',
  low: 'text-green-400', info: 'text-blue-400',
};

export default function LogIngestionPage() {
  const queryClient = useQueryClient();
  const fileRef = useRef<HTMLInputElement>(null);
  const logRef = useRef<HTMLDivElement>(null);
  const [dragging, setDragging] = useState(false);
  const [status, setStatus] = useState<IngestionStatus>('idle');
  const [parseResult, setParseResult] = useState<ParsedResult | null>(null);
  const [uploadResult, setUploadResult] = useState<{ inserted: number } | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [schemaViewId, setSchemaViewId] = useState<number | null>(null);
  const [addOpen, setAddOpen] = useState(false);
  const [newName, setNewName] = useState('');
  const [newType, setNewType] = useState('Network');
  const [sources, setSources] = useState(SOURCE_CONFIGS);
  const [rawText, setRawText] = useState('');
  const [rawSource, setRawSource] = useState('');
  const [rawHostname, setRawHostname] = useState('');
  const [rawResult, setRawResult] = useState<{ inserted: number; source: string } | null>(null);
  const [rawError, setRawError] = useState<string | null>(null);
  const [sourcetype, setSourcetype] = useState('');

  const { data: logsData, dataUpdatedAt } = useQuery({
    queryKey: ['logs', { limit: 20, page: 1 }],
    queryFn: () => logsApi.list({ limit: 20, page: 1 }).then(r => r.data),
    refetchInterval: 5000,
  });

  const { data: totalData } = useQuery({
    queryKey: ['logs', { limit: 1, page: 1 }],
    queryFn: () => logsApi.list({ limit: 1, page: 1 }).then(r => r.data),
    refetchInterval: 10000,
  });

  const { data: pipelineStats } = useQuery({
    queryKey: ['ingest-stats'],
    queryFn: () => ingestApi.stats().then(r => r.data),
    refetchInterval: 15000,
  });

  const rawMutation = useMutation({
    mutationFn: (text: string) =>
      ingestApi.raw(text, {
        source: rawSource || undefined,
        hostname: rawHostname || undefined,
        sourcetype: sourcetype || undefined,
      }),
    onSuccess: (res) => {
      setRawResult(res.data);
      setRawError(null);
      setRawText('');
      queryClient.invalidateQueries({ queryKey: ['logs'] });
      queryClient.invalidateQueries({ queryKey: ['ingest-stats'] });
    },
    onError: (err: any) => {
      setRawError(err?.response?.data?.error ?? 'Raw ingestion failed');
      setRawResult(null);
    },
  });

  const reprocessMutation = useMutation({
    mutationFn: () => ingestApi.reprocess({ limit: 500 }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['logs'] });
      queryClient.invalidateQueries({ queryKey: ['ingest-stats'] });
    },
  });

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [dataUpdatedAt]);

  const uploadMutation = useMutation({
    mutationFn: (data: { records: Record<string, unknown>[]; sourcetype?: string }) =>
      ingestApi.bulk(data.records, data.sourcetype || undefined),
    onSuccess: (res) => {
      setUploadResult({ inserted: res.data.inserted });
      setStatus('success');
      queryClient.invalidateQueries({ queryKey: ['logs'] });
    },
    onError: (err: any) => {
      setUploadError(err?.response?.data?.error ?? 'Upload failed');
      setStatus('error');
    },
  });

  const processFile = useCallback((file: File) => {
    setStatus('parsing');
    setParseResult(null);
    setUploadResult(null);
    setUploadError(null);
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      const result = detectAndParse(content, file.name);
      setParseResult(result);
      if (result.count === 0) {
        setStatus('error');
        setUploadError('No valid records found in file');
        return;
      }
      setStatus('uploading');
      uploadMutation.mutate({ records: result.records, sourcetype: sourcetype || undefined });
    };
    reader.onerror = () => {
      setStatus('error');
      setUploadError('Failed to read file');
    };
    reader.readAsText(file);
  }, [uploadMutation]);

  const handleFiles = useCallback((files: FileList | null) => {
    if (!files || files.length === 0) return;
    processFile(files[0]);
  }, [processFile]);

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    handleFiles(e.dataTransfer.files);
  }, [handleFiles]);

  const totalLogs = totalData?.total ?? 0;
  const liveEntries = logsData?.logs ?? [];

  return (
    <>
      <div className="flex flex-col gap-6">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-foreground flex items-center gap-3">
            <Database className="w-8 h-8 text-primary" /> Log Ingestion
          </h1>
          <p className="text-muted-foreground mt-1">Upload log files, manage pipelines, and monitor data flow in real time.</p>
        </div>

        <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
          {[
            { label: 'Total Indexed', value: (pipelineStats?.total ?? totalLogs).toLocaleString(), color: 'text-primary' },
            { label: 'Last 24 Hours', value: (pipelineStats?.last24h ?? 0).toLocaleString(), color: 'text-cyan-400' },
            { label: 'Processed', value: (pipelineStats?.processed ?? 0).toLocaleString(), color: 'text-emerald-400' },
            { label: 'Unprocessed', value: (pipelineStats?.unprocessed ?? 0).toLocaleString(), color: 'text-amber-400' },
            { label: 'Unparseable', value: (pipelineStats?.unparseable ?? 0).toLocaleString(), color: 'text-destructive' },
          ].map(s => (
            <div key={s.label} className="bg-card border border-border rounded-xl p-4 shadow-lg">
              <div className="text-xs text-muted-foreground mb-1">{s.label}</div>
              <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
            </div>
          ))}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 space-y-4">

            <div className="bg-card border border-border rounded-xl shadow-lg p-5">
              <h3 className="font-semibold text-foreground mb-4 flex items-center gap-2">
                <Upload className="w-4 h-4 text-primary" /> Upload Log File
              </h3>

              {/* Sourcetype picker */}
              <div className="mb-4 flex items-center gap-3">
                <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide shrink-0">Source type</label>
                <select
                  value={sourcetype}
                  onChange={e => setSourcetype(e.target.value)}
                  aria-label="Source type"
                  className="flex-1 bg-input border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-primary transition-colors appearance-none cursor-pointer"
                >
                  <option value="">Auto-detect</option>
                  <option value="syslog">syslog — RFC 3164/5424</option>
                  <option value="windows_eventlog">windows_eventlog — Windows Event Log</option>
                  <option value="cef">cef — Common Event Format</option>
                  <option value="leef">leef — Log Event Extended Format</option>
                  <option value="ecs">ecs — Elastic Common Schema</option>
                  <option value="cloudtrail">cloudtrail — AWS CloudTrail</option>
                  <option value="vpc_flow">vpc_flow — AWS VPC Flow</option>
                  <option value="xml">xml — XML / Windows EVTX</option>
                  <option value="apache">apache — Apache Access Log</option>
                  <option value="nginx">nginx — NGINX Access Log</option>
                  <option value="firewall">firewall — Firewall Log</option>
                  <option value="dns">dns — DNS Log</option>
                  <option value="json">json — Generic JSON</option>
                  <option value="generic">generic — Generic text</option>
                </select>
              </div>

              <div
                onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
                onDragLeave={() => setDragging(false)}
                onDrop={onDrop}
                onClick={() => status !== 'uploading' && fileRef.current?.click()}
                className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all duration-200
                  ${dragging ? 'border-primary bg-primary/5 scale-[1.01]' : 'border-border hover:border-primary/50 hover:bg-primary/3'}
                  ${status === 'uploading' || status === 'parsing' ? 'pointer-events-none opacity-70' : ''}`}
              >
                <input
                  ref={fileRef}
                  type="file"
                  accept=".json,.csv,.log,.txt,.syslog,.xml,.evtx"
                  aria-label="Upload log file"
                  className="hidden"
                  onChange={(e) => handleFiles(e.target.files)}
                />
                {status === 'idle' || status === 'error' || status === 'success' ? (
                  <>
                    <Upload className="w-10 h-10 text-muted-foreground mx-auto mb-3" />
                    <p className="text-sm font-medium text-foreground mb-1">Drop a log file here or click to browse</p>
                    <p className="text-xs text-muted-foreground">Supports JSON, CSV, Syslog (.log, .txt) — up to 10,000 records</p>
                  </>
                ) : (
                  <>
                    <Loader2 className="w-10 h-10 text-primary mx-auto mb-3 animate-spin" />
                    <p className="text-sm font-medium text-foreground">{status === 'parsing' ? 'Parsing file…' : 'Uploading to database…'}</p>
                    {parseResult && <p className="text-xs text-muted-foreground mt-1">{parseResult.count.toLocaleString()} records found</p>}
                  </>
                )}
              </div>

              {status === 'success' && uploadResult && (
                <div className="mt-4 bg-emerald-500/10 border border-emerald-500/30 rounded-xl p-4">
                  <div className="flex items-center gap-2 text-emerald-400 font-semibold mb-2">
                    <CheckCircle2 className="w-5 h-5" />
                    {uploadResult.inserted.toLocaleString()} log{uploadResult.inserted !== 1 ? 's' : ''} ingested successfully
                  </div>
                  {parseResult && parseResult.errors.length > 0 && (
                    <p className="text-xs text-amber-400">{parseResult.errors.length} line(s) skipped due to parse errors</p>
                  )}
                  <button
                    onClick={() => { setStatus('idle'); setParseResult(null); setUploadResult(null); if (fileRef.current) fileRef.current.value = ''; }}
                    className="mt-2 text-xs text-primary hover:underline"
                  >
                    Upload another file
                  </button>
                </div>
              )}

              {status === 'error' && (
                <div className="mt-4 bg-destructive/10 border border-destructive/30 rounded-xl p-4">
                  <div className="flex items-center gap-2 text-destructive font-semibold mb-1">
                    <XCircle className="w-4 h-4" /> Upload failed
                  </div>
                  <p className="text-xs text-muted-foreground">{uploadError}</p>
                  <button
                    onClick={() => { setStatus('idle'); setParseResult(null); if (fileRef.current) fileRef.current.value = ''; }}
                    className="mt-2 text-xs text-primary hover:underline"
                  >
                    Try again
                  </button>
                </div>
              )}

              <div className="mt-4 pt-4 border-t border-border">
                <p className="text-xs text-muted-foreground font-medium mb-2">Supported formats</p>
                <div className="grid grid-cols-3 sm:grid-cols-6 gap-2">
                  {[
                    { fmt: 'JSON', desc: 'Array / NDJSON', icon: '{ }' },
                    { fmt: 'CSV', desc: 'With header row', icon: ',' },
                    { fmt: 'Syslog', desc: 'RFC 3164 / 5424', icon: '>' },
                    { fmt: 'CEF / LEEF', desc: 'ArcSight / QRadar', icon: '|' },
                    { fmt: 'VPC Flow', desc: 'AWS flow logs', icon: '↔' },
                    { fmt: 'Apache', desc: 'CLF / Combined', icon: '→' },
                    { fmt: 'XML', desc: 'Windows EVTX', icon: '<>' },
                  ].map(f => (
                    <div key={f.fmt} className="bg-secondary/40 border border-border rounded-lg p-3 text-center">
                      <div className="font-mono text-lg text-primary mb-1">{f.icon}</div>
                      <div className="text-xs font-semibold text-foreground">{f.fmt}</div>
                      <div className="text-[10px] text-muted-foreground">{f.desc}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="bg-card border border-border rounded-xl shadow-lg p-5">
              <div className="flex justify-between items-center mb-4">
                <h3 className="font-semibold text-foreground flex items-center gap-2">
                  <Server className="w-4 h-4 text-primary" /> Configured Connectors
                </h3>
                <button onClick={() => setAddOpen(!addOpen)} className="flex items-center gap-1.5 px-3 py-1.5 bg-primary text-white text-sm font-medium rounded-lg hover:bg-primary/90 transition-colors">
                  <Plus className="w-4 h-4" /> Add
                </button>
              </div>

              {addOpen && (
                <div className="mb-4 p-4 bg-secondary/30 border border-border rounded-xl space-y-3">
                  <h4 className="font-medium text-foreground text-sm">New Log Source</h4>
                  <div className="grid grid-cols-2 gap-3">
                    <input value={newName} onChange={e => setNewName(e.target.value)} placeholder="Source Name" className="w-full bg-input border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-primary" />
                    <select value={newType} onChange={e => setNewType(e.target.value)} aria-label="Source type" className="w-full bg-input border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-primary appearance-none">
                      {['Network', 'Cloud', 'Endpoint', 'Identity', 'Application'].map(t => <option key={t}>{t}</option>)}
                    </select>
                  </div>
                  <div className="flex gap-2 justify-end">
                    <button onClick={() => setAddOpen(false)} className="px-3 py-1.5 text-sm text-muted-foreground hover:text-foreground">Cancel</button>
                    <button onClick={() => {
                      if (!newName.trim()) return;
                      setSources(prev => [...prev, { id: Date.now(), name: newName, type: newType, status: 'warning', format: 'JSON', host: 'pending-config.local' }]);
                      setNewName(''); setAddOpen(false);
                    }} disabled={!newName.trim()} className="px-4 py-1.5 bg-primary text-white text-sm font-medium rounded-lg hover:bg-primary/90 disabled:opacity-50 transition-colors">Add</button>
                  </div>
                </div>
              )}

              <div className="space-y-2">
                {sources.length === 0 && (
                  <div className="text-center py-8 text-muted-foreground text-sm">
                    <Server className="w-8 h-8 mx-auto mb-2 opacity-40" />
                    <p>No connectors configured yet.</p>
                    <p className="text-xs mt-1">Click "Add" to create your first log source connector.</p>
                  </div>
                )}
                {sources.map(source => (
                  <div key={source.id} className="border border-border rounded-xl overflow-hidden">
                    <div className="flex items-center gap-4 p-4 hover:bg-secondary/30 transition-colors cursor-pointer" onClick={() => setExpandedId(expandedId === source.id ? null : source.id)}>
                      <div className="p-2 bg-background rounded-lg border border-border shrink-0">
                        <Server className="w-5 h-5 text-primary" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="font-semibold text-foreground">{source.name}</div>
                        <div className="text-xs text-muted-foreground">{source.type} · {source.format}</div>
                      </div>
                      <div className="flex items-center gap-4 shrink-0">
                        <div className="flex items-center gap-2">
                          <span className="relative flex h-3 w-3 shrink-0">{statusIcon(source.status)}</span>
                          <span className="text-sm font-medium text-muted-foreground w-16 hidden sm:block">{statusLabel[source.status]}</span>
                        </div>
                        {expandedId === source.id ? <ChevronDown className="w-4 h-4 text-muted-foreground" /> : <ChevronRight className="w-4 h-4 text-muted-foreground" />}
                      </div>
                    </div>

                    {expandedId === source.id && (
                      <div className="border-t border-border bg-secondary/10 p-4 space-y-3">
                        <div className="grid grid-cols-2 gap-3 text-sm">
                          <div><span className="text-muted-foreground text-xs">Host</span><div className="font-mono text-xs text-foreground mt-0.5">{source.host}</div></div>
                          <div><span className="text-muted-foreground text-xs">Format</span><div className="text-xs text-foreground mt-0.5">{source.format}</div></div>
                        </div>
                        {source.status === 'error' && (
                          <div className="bg-destructive/10 border border-destructive/20 rounded-lg p-3 text-xs text-destructive flex items-center gap-2">
                            <XCircle className="w-4 h-4 shrink-0" />
                            Connection failed: ECONNREFUSED. Check network path and firewall rules.
                          </div>
                        )}
                        {source.status === 'warning' && (
                          <div className="bg-amber-500/10 border border-amber-500/20 rounded-lg p-3 text-xs text-amber-400 flex items-center gap-2">
                            <AlertTriangle className="w-4 h-4 shrink-0" />
                            High latency or degraded connection. Parser may be overloaded.
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="space-y-5">
            <div className="bg-card border border-border rounded-xl shadow-lg p-5">
              <div className="flex items-center gap-2 mb-4">
                <BarChart3 className="w-4 h-4 text-primary" />
                <h3 className="font-semibold text-foreground">Pipeline Health</h3>
              </div>
              <div className="space-y-3 text-sm">
                <div className="flex justify-between items-center py-2 border-b border-border/50">
                  <span className="text-muted-foreground">Total Indexed</span>
                  <span className="font-mono font-semibold text-primary">{(pipelineStats?.total ?? totalLogs).toLocaleString()}</span>
                </div>
                <div className="flex justify-between items-center py-2 border-b border-border/50">
                  <span className="text-muted-foreground">Last 24h</span>
                  <span className="font-mono font-semibold text-cyan-400">{(pipelineStats?.last24h ?? 0).toLocaleString()}</span>
                </div>
                <div className="flex justify-between items-center py-2 border-b border-border/50">
                  <span className="text-muted-foreground">Processed</span>
                  <span className="font-mono font-semibold text-emerald-400">{(pipelineStats?.processed ?? 0).toLocaleString()}</span>
                </div>
                <div className="flex justify-between items-center py-2 border-b border-border/50">
                  <span className="text-muted-foreground">Unprocessed</span>
                  <span className="font-mono font-semibold text-amber-400">{(pipelineStats?.unprocessed ?? 0).toLocaleString()}</span>
                </div>
                <div className="flex justify-between items-center py-2">
                  <span className="text-muted-foreground">Unparseable</span>
                  <span className="font-mono font-semibold text-destructive">{(pipelineStats?.unparseable ?? 0).toLocaleString()}</span>
                </div>
              </div>
              {((pipelineStats?.unprocessed ?? 0) > 0 || (pipelineStats?.unparseable ?? 0) > 0) && (
                <button
                  onClick={() => reprocessMutation.mutate()}
                  disabled={reprocessMutation.isPending}
                  className="mt-4 w-full flex items-center justify-center gap-2 px-3 py-2 bg-amber-500/10 border border-amber-500/30 text-amber-400 text-sm font-medium rounded-lg hover:bg-amber-500/20 disabled:opacity-50 transition-colors"
                >
                  {reprocessMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <RotateCcw className="w-4 h-4" />}
                  {reprocessMutation.isPending ? 'Reprocessing…' : 'Reprocess Failed Logs'}
                </button>
              )}
              {reprocessMutation.isSuccess && (
                <p className="mt-2 text-xs text-emerald-400 text-center">Reprocessed {reprocessMutation.data?.data.reprocessed ?? 0} logs</p>
              )}
            </div>

            {pipelineStats?.bySource && pipelineStats.bySource.length > 0 && (
              <div className="bg-card border border-border rounded-xl shadow-lg p-5">
                <div className="flex items-center gap-2 mb-3">
                  <Activity className="w-4 h-4 text-primary" />
                  <h3 className="font-semibold text-foreground text-sm">By Source</h3>
                </div>
                <div className="space-y-2">
                  {pipelineStats.bySource.slice(0, 8).map(s => {
                    const pct = pipelineStats.total > 0 ? Math.round((s.count / pipelineStats.total) * 100) : 0;
                    return (
                      <div key={s.source} className="space-y-1">
                        <div className="flex justify-between text-xs">
                          <span className="text-muted-foreground truncate">{s.source || 'unknown'}</span>
                          <span className="font-mono text-foreground">{s.count.toLocaleString()}</span>
                        </div>
                        <div className="h-1.5 bg-secondary rounded-full overflow-hidden">
                          <div className="h-full bg-primary rounded-full transition-all duration-500" style={{ width: `${pct}%` }} />
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            <div className="bg-card border border-border rounded-xl shadow-lg p-5">
              <div className="flex items-center gap-2 mb-4">
                <Terminal className="w-4 h-4 text-primary" />
                <h3 className="font-semibold text-foreground text-sm">Raw Log Paste</h3>
              </div>
              <textarea
                value={rawText}
                onChange={e => setRawText(e.target.value)}
                placeholder={"Paste raw log lines here…\n(one event per line — syslog, CEF, JSON, etc.)"}
                rows={6}
                className="w-full bg-[#050810] border border-border rounded-lg p-3 text-xs font-mono text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:border-primary resize-y"
              />
              <div className="grid grid-cols-2 gap-2 mt-2">
                <input
                  value={rawSource}
                  onChange={e => setRawSource(e.target.value)}
                  placeholder="Source (auto-detect)"
                  className="bg-input border border-border rounded-lg px-2 py-1.5 text-xs text-foreground focus:outline-none focus:border-primary"
                />
                <input
                  value={rawHostname}
                  onChange={e => setRawHostname(e.target.value)}
                  placeholder="Hostname (optional)"
                  className="bg-input border border-border rounded-lg px-2 py-1.5 text-xs text-foreground focus:outline-none focus:border-primary"
                />
              </div>
              <button
                onClick={() => rawText.trim() && rawMutation.mutate(rawText)}
                disabled={!rawText.trim() || rawMutation.isPending}
                className="mt-3 w-full flex items-center justify-center gap-2 px-3 py-2 bg-primary text-white text-sm font-medium rounded-lg hover:bg-primary/90 disabled:opacity-50 transition-colors"
              >
                {rawMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
                {rawMutation.isPending ? 'Ingesting…' : 'Ingest Logs'}
              </button>
              {rawResult && (
                <p className="mt-2 text-xs text-emerald-400 flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3" /> {rawResult.inserted} log(s) ingested as <span className="font-mono">{rawResult.source}</span>
                </p>
              )}
              {rawError && (
                <p className="mt-2 text-xs text-destructive flex items-center gap-1">
                  <XCircle className="w-3 h-3" /> {rawError}
                </p>
              )}
            </div>

            <div className="bg-primary/5 border border-primary/20 rounded-xl shadow-lg p-5">
              <div className="flex items-center gap-2 mb-3">
                <Wifi className="w-4 h-4 text-primary" />
                <h3 className="font-semibold text-primary text-sm">Live Event Stream</h3>
                <span className="ml-auto flex items-center gap-1 text-xs text-emerald-400">
                  <span className="relative flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-400" />
                  </span>
                  LIVE
                </span>
              </div>
              <div ref={logRef} className="bg-[#050810] p-3 rounded-lg border border-border h-72 overflow-y-auto">
                {liveEntries.length === 0 ? (
                  <div className="h-full flex flex-col items-center justify-center gap-2">
                    <FileText className="w-8 h-8 text-muted-foreground/40" />
                    <p className="text-xs text-muted-foreground text-center">No logs yet. Upload a file or ingest logs to see them here.</p>
                  </div>
                ) : (
                  <div className="space-y-1 font-mono text-[11px]">
                    {liveEntries.map((entry: any, i: number) => {
                      const ts = entry.createdAt ? new Date(entry.createdAt).toISOString().replace('T', ' ').slice(0, 19) : '';
                      const sev = entry.severity ?? 'info';
                      return (
                        <div key={entry.id ?? i} className={`leading-relaxed ${i === liveEntries.length - 1 ? 'text-green-400' : 'text-muted-foreground'}`}>
                          <span className="text-muted-foreground/50">{ts} </span>
                          <span className={`font-semibold ${severityColor[sev] ?? 'text-blue-400'}`}>[{sev.toUpperCase()}] </span>
                          <span className="text-primary/80">[{entry.source}] </span>
                          {entry.message}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
              <div className="mt-2 flex items-center justify-between">
                <p className="text-[10px] text-muted-foreground">Auto-refreshes every 5s</p>
                <button
                  onClick={() => queryClient.invalidateQueries({ queryKey: ['logs'] })}
                  className="text-[10px] text-primary hover:text-primary/80 flex items-center gap-1 transition-colors"
                >
                  <RefreshCw className="w-3 h-3" /> Refresh now
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
