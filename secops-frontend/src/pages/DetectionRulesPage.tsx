import React, { useState, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { rulesApi, normalizeRule } from '@/lib/api';
import { useAuthStore } from '@/store/authStore';
import { safeFormat } from '@/lib/date-utils';
import { SeverityBadge } from '@/components/ui/Badge';
import { Shield, Plus, Search, Power, PowerOff, Code, Trash2, X, Copy, CheckCheck, Lock, Loader2, BarChart3, ChevronDown, Pencil } from 'lucide-react';
import { useLocation } from 'wouter';
import type { DetectionRule } from '@/lib/types';

function YamlModal({ rule, onClose }: { rule: DetectionRule; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    navigator.clipboard.writeText(rule.yaml).then(() => { setCopied(true); setTimeout(() => setCopied(false), 2000); });
  };
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <div className="bg-card border border-border rounded-xl shadow-2xl w-full max-w-2xl max-h-[80vh] flex flex-col" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between p-4 border-b border-border">
          <div>
            <h2 className="font-semibold text-foreground flex items-center gap-2"><Code className="w-4 h-4 text-primary" /> Sigma YAML</h2>
            <p className="text-xs text-muted-foreground mt-0.5">{rule.name}</p>
          </div>
          <div className="flex gap-2">
            <button onClick={handleCopy} className="flex items-center gap-1.5 px-3 py-1.5 bg-secondary border border-border rounded-lg text-sm text-muted-foreground hover:text-foreground transition-colors">
              {copied ? <CheckCheck className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              {copied ? 'Copied!' : 'Copy'}
            </button>
            <button onClick={onClose} aria-label="Close" className="p-1.5 text-muted-foreground hover:text-foreground hover:bg-secondary rounded-lg transition-colors"><X className="w-5 h-5" /></button>
          </div>
        </div>
        <div className="flex-1 overflow-auto bg-[#050810] p-4">
          <pre className="text-sm font-mono text-green-400 whitespace-pre-wrap">{rule.yaml || '# No YAML content available for this rule.'}</pre>
        </div>
        <div className="p-3 border-t border-border bg-secondary/20 flex justify-between items-center text-xs text-muted-foreground">
          <span>Author: {rule.author} · Modified: {safeFormat(rule.updatedAt, 'MMM dd, yyyy')}</span>
          <span className="font-mono">{(rule.yaml || '').split('\n').length} lines</span>
        </div>
      </div>
    </div>
  );
}

function RuleStatsRow({ ruleId }: { ruleId: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ['rule-stats', ruleId],
    queryFn: () => rulesApi.stats(ruleId).then(r => r.data),
  });

  if (isLoading) {
    return (
      <tr><td colSpan={7} className="px-5 py-4 bg-secondary/20">
        <div className="flex items-center gap-2 text-xs text-muted-foreground"><Loader2 className="w-3 h-3 animate-spin" /> Loading stats…</div>
      </td></tr>
    );
  }

  if (!data) return null;

  return (
    <tr><td colSpan={7} className="px-5 py-4 bg-secondary/10 border-b border-border">
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4 text-xs">
        <div>
          <div className="text-muted-foreground mb-0.5">Total Alerts</div>
          <div className="text-lg font-bold text-foreground">{data.totalAlerts ?? 0}</div>
        </div>
        <div>
          <div className="text-muted-foreground mb-0.5">Last 24h</div>
          <div className="text-lg font-bold text-foreground">{data.alertsLast24h ?? 0}</div>
        </div>
        <div>
          <div className="text-muted-foreground mb-0.5">Last 7d</div>
          <div className="text-lg font-bold text-foreground">{data.alertsLast7d ?? 0}</div>
        </div>
        <div>
          <div className="text-muted-foreground mb-0.5">Trigger Count</div>
          <div className="text-lg font-bold text-foreground">{data.triggerCount ?? 0}</div>
        </div>
        <div>
          <div className="text-muted-foreground mb-0.5">False Positive Rate</div>
          <div className="text-lg font-bold text-foreground">{data.falsePositiveRate != null ? `${(data.falsePositiveRate * 100).toFixed(1)}%` : 'N/A'}</div>
        </div>
      </div>
      {data.alertsBySeverity && Object.keys(data.alertsBySeverity).length > 0 && (
        <div className="flex gap-2 mt-3">
          {Object.entries(data.alertsBySeverity).map(([sev, count]) => (
            <span key={sev} className="text-xs px-2 py-0.5 rounded-full bg-secondary border border-border">
              <span className="capitalize">{sev}</span>: <span className="font-mono font-bold">{count as number}</span>
            </span>
          ))}
        </div>
      )}
    </td></tr>
  );
}

export default function DetectionRulesPage() {
  const qc = useQueryClient();
  const { can } = useAuthStore();
  const [, setLocation] = useLocation();
  const [searchTerm, setSearchTerm] = useState('');
  const [viewYamlFor, setViewYamlFor] = useState<DetectionRule | null>(null);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<'all' | 'enabled' | 'disabled'>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [expandedRuleId, setExpandedRuleId] = useState<string | null>(null);

  const canWrite  = can('rules:write');
  const canDelete = can('rules:delete');
  const canToggle = can('rules:toggle');

  const { data, isLoading } = useQuery({
    queryKey: ['rules'],
    queryFn: () => rulesApi.list().then(r => r.data.rules.map(normalizeRule)),
  });

  const rules = data ?? [];

  const filteredRules = useMemo(() => rules.filter(r => {
    const matchSearch = r.name.toLowerCase().includes(searchTerm.toLowerCase()) || r.mitreIds.some(id => id.includes(searchTerm));
    const matchStatus = statusFilter === 'all' || (statusFilter === 'enabled' ? r.enabled : !r.enabled);
    const matchSeverity = severityFilter === 'all' || r.severity === severityFilter;
    return matchSearch && matchStatus && matchSeverity;
  }), [rules, searchTerm, statusFilter, severityFilter]);

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => rulesApi.toggle(id, !enabled),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rules'] }),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => rulesApi.delete(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['rules'] });
      setConfirmDeleteId(null);
    },
  });

  const ruleToDelete = rules.find(r => r.id === confirmDeleteId);

  return (
    <>
      {viewYamlFor && <YamlModal rule={viewYamlFor} onClose={() => setViewYamlFor(null)} />}

      {confirmDeleteId && canDelete && ruleToDelete && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={() => setConfirmDeleteId(null)}>
          <div className="bg-card border border-destructive/30 rounded-xl shadow-2xl w-full max-w-sm p-6" onClick={e => e.stopPropagation()}>
            <h3 className="font-semibold text-foreground text-lg mb-2">Delete Rule?</h3>
            <p className="text-muted-foreground text-sm mb-1">Are you sure you want to delete:</p>
            <p className="font-medium text-foreground mb-5">"{ruleToDelete.name}"</p>
            <div className="flex gap-3">
              <button onClick={() => setConfirmDeleteId(null)} className="flex-1 py-2 bg-secondary border border-border rounded-lg text-muted-foreground hover:text-foreground transition-colors text-sm">Cancel</button>
              <button
                onClick={() => deleteMutation.mutate(confirmDeleteId)}
                disabled={deleteMutation.isPending}
                className="flex-1 py-2 bg-destructive text-white rounded-lg hover:bg-destructive/80 transition-colors text-sm font-semibold flex items-center justify-center gap-2"
              >
                {deleteMutation.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
                Delete Rule
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="flex flex-col gap-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold tracking-tight text-foreground flex items-center gap-3">
              <Shield className="w-8 h-8 text-primary" /> Detection Engine
            </h1>
            <p className="text-muted-foreground mt-1">Manage SIEM correlation rules and behavioral analytics.</p>
          </div>
          {canWrite ? (
            <button
              onClick={() => setLocation('/rules/new')}
              className="flex items-center gap-2 px-5 py-2.5 bg-primary text-primary-foreground font-semibold rounded-xl hover:bg-primary/90 hover:-translate-y-0.5 hover:shadow-lg hover:shadow-primary/25 transition-all"
            >
              <Plus className="w-4 h-4" /> Create Rule
            </button>
          ) : (
            <div className="flex items-center gap-2 px-4 py-2.5 bg-secondary border border-border rounded-xl text-muted-foreground text-sm cursor-default">
              <Lock className="w-4 h-4 opacity-50" /> View Only
            </div>
          )}
        </div>

        {/* Stats */}
        <div className="grid grid-cols-3 gap-4">
          {[
            { label: 'Total Rules', value: rules.length },
            { label: 'Enabled', value: rules.filter(r => r.enabled).length, color: 'text-emerald-400' },
            { label: 'Total Triggers', value: rules.reduce((s, r) => s + r.triggerCount, 0).toLocaleString() },
          ].map(s => (
            <div key={s.label} className="bg-card border border-border rounded-xl p-4 shadow-lg">
              <div className="text-xs text-muted-foreground mb-1">{s.label}</div>
              <div className={`text-2xl font-bold ${s.color || 'text-foreground'}`}>
                {isLoading ? <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" /> : s.value}
              </div>
            </div>
          ))}
        </div>

        <div className="bg-card border border-border rounded-xl shadow-lg shadow-black/20 flex flex-col overflow-hidden">
          <div className="p-4 border-b border-border flex gap-3 bg-secondary/20 items-center flex-wrap">
            <div className="relative w-full max-w-sm">
              <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
              <input
                type="text"
                placeholder="Search by name or MITRE ID..."
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
                className="w-full bg-input border border-border rounded-lg pl-9 pr-4 py-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>
            <div className="flex items-center gap-1 bg-secondary p-1 rounded-lg border border-border">
              {(['all', 'enabled', 'disabled'] as const).map(f => (
                <button
                  key={f}
                  onClick={() => setStatusFilter(f)}
                  className={`px-3 py-1 rounded-md text-xs font-medium capitalize transition-colors ${statusFilter === f ? 'bg-card text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'}`}
                >
                  {f}
                </button>
              ))}
            </div>
            <select
              value={severityFilter}
              onChange={e => setSeverityFilter(e.target.value)}
              aria-label="Severity filter"
              className="px-3 py-1.5 bg-secondary border border-border rounded-lg text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary appearance-none"
            >
              <option value="all">All Severity</option>
              {['critical', 'high', 'medium', 'low', 'info'].map(s => (
                <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
              ))}
            </select>
            <span className="text-xs text-muted-foreground ml-auto">{filteredRules.length} rules</span>
          </div>

          <div className="overflow-x-auto">
            {isLoading ? (
              <div className="flex items-center justify-center py-16 gap-3 text-muted-foreground">
                <Loader2 className="w-6 h-6 animate-spin text-primary" /> Loading rules…
              </div>
            ) : (
              <table className="w-full text-sm text-left">
                <thead className="text-xs text-muted-foreground bg-secondary/50 border-b border-border uppercase tracking-wider">
                  <tr>
                    <th className="px-5 py-4 font-medium w-16">Status</th>
                    <th className="px-5 py-4 font-medium">Rule Name</th>
                    <th className="px-5 py-4 font-medium">Severity</th>
                    <th className="px-5 py-4 font-medium">MITRE ATT&CK</th>
                    <th className="px-5 py-4 font-medium">Triggers</th>
                    <th className="px-5 py-4 font-medium">Last Modified</th>
                    <th className="px-5 py-4 font-medium text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/40">
                  {filteredRules.map(rule => (
                    <React.Fragment key={rule.id}>
                    <tr className={`transition-colors group cursor-pointer ${rule.enabled ? 'hover:bg-secondary/50' : 'opacity-55 bg-secondary/10 hover:bg-secondary/30'}`} onClick={() => setExpandedRuleId(prev => prev === rule.id ? null : rule.id)}>
                      <td className="px-5 py-4">
                        {canToggle ? (
                          <button
                            onClick={(e) => { e.stopPropagation(); toggleMutation.mutate({ id: rule.id, enabled: rule.enabled }); }}
                            disabled={toggleMutation.isPending}
                            className={`p-1.5 rounded-full transition-all ${rule.enabled ? 'text-emerald-400 bg-emerald-400/10 hover:bg-emerald-400/20 hover:scale-110' : 'text-muted-foreground bg-secondary hover:bg-secondary/80'}`}
                            title={rule.enabled ? 'Disable Rule' : 'Enable Rule'}
                          >
                            {rule.enabled ? <Power className="w-4 h-4" /> : <PowerOff className="w-4 h-4" />}
                          </button>
                        ) : (
                          <span className={`inline-flex p-1.5 rounded-full ${rule.enabled ? 'text-emerald-400 bg-emerald-400/10' : 'text-muted-foreground bg-secondary'}`}>
                            {rule.enabled ? <Power className="w-4 h-4" /> : <PowerOff className="w-4 h-4" />}
                          </span>
                        )}
                      </td>
                      <td className="px-5 py-4">
                        <div className="font-medium text-foreground mb-0.5">{rule.name}</div>
                        <div className="text-xs text-muted-foreground truncate max-w-xs">{rule.description}</div>
                      </td>
                      <td className="px-5 py-4"><SeverityBadge severity={rule.severity} /></td>
                      <td className="px-5 py-4">
                        <div className="flex gap-1 flex-wrap">
                          {rule.mitreIds.slice(0, 2).map(id => (
                            <span key={id} className="text-xs font-mono bg-secondary border border-border/50 px-1.5 py-0.5 rounded text-foreground">{id}</span>
                          ))}
                          {rule.mitreIds.length > 2 && <span className="text-xs text-muted-foreground">+{rule.mitreIds.length - 2}</span>}
                        </div>
                      </td>
                      <td className="px-5 py-4 font-mono text-foreground">{rule.triggerCount.toLocaleString()}</td>
                      <td className="px-5 py-4 text-muted-foreground text-xs">{safeFormat(rule.updatedAt, 'MMM dd, yyyy')}</td>
                      <td className="px-5 py-4 text-right">
                        <div className="flex items-center justify-end gap-1.5 opacity-0 group-hover:opacity-100 transition-opacity">
                          <button onClick={(e) => { e.stopPropagation(); setExpandedRuleId(prev => prev === rule.id ? null : rule.id); }} className={`p-2 rounded-lg transition-colors ${expandedRuleId === rule.id ? 'text-primary bg-primary/10' : 'text-muted-foreground hover:text-primary hover:bg-primary/10'}`} title="View Stats">
                            <BarChart3 className="w-4 h-4" />
                          </button>
                          {canWrite && (
                            <button onClick={(e) => { e.stopPropagation(); setLocation(`/rules/${rule.id}/edit`); }} className="p-2 text-muted-foreground hover:text-primary hover:bg-primary/10 rounded-lg transition-colors" title="Edit Rule">
                              <Pencil className="w-4 h-4" />
                            </button>
                          )}
                          <button onClick={(e) => { e.stopPropagation(); setViewYamlFor(rule); }} className="p-2 text-muted-foreground hover:text-primary hover:bg-primary/10 rounded-lg transition-colors" title="View YAML">
                            <Code className="w-4 h-4" />
                          </button>
                          {canDelete && (
                            <button onClick={(e) => { e.stopPropagation(); setConfirmDeleteId(rule.id); }} className="p-2 text-muted-foreground hover:text-destructive hover:bg-destructive/10 rounded-lg transition-colors" title="Delete Rule">
                              <Trash2 className="w-4 h-4" />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                    {expandedRuleId === rule.id && <RuleStatsRow ruleId={rule.id} />}
                    </React.Fragment>
                  ))}
                </tbody>
              </table>
            )}
            {!isLoading && filteredRules.length === 0 && (
              <div className="p-12 text-center text-muted-foreground">
                <Shield className="w-10 h-10 mx-auto mb-3 opacity-20" />
                <p className="text-sm">{rules.length === 0 ? 'No detection rules yet. Create your first rule.' : 'No rules match your current filter.'}</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </>
  );
}
