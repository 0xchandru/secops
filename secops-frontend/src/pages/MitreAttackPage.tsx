import React, { useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { alertsApi, rulesApi, dashboardApi, normalizeRule } from '@/lib/api';
import { Target, ShieldCheck, X, AlertTriangle, Pencil } from 'lucide-react';
import { useLocation } from 'wouter';
import type { MitreTactic, MitreTechnique } from '@/lib/types';
import { MITRE_MATRIX } from '@/lib/mitre-taxonomy';
import { useAuthStore } from '@/store/authStore';

function TechniquePopup({ technique, tacticName, matchedRuleIds, canWrite, onClose }: { technique: MitreTechnique; tacticName: string; matchedRuleIds: { id: string; name: string }[]; canWrite: boolean; onClose: () => void }) {
  const [, setLocation] = useLocation();
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <div className="bg-card border border-border rounded-xl shadow-2xl w-full max-w-md" onClick={e => e.stopPropagation()}>
        <div className="flex items-start justify-between p-5 border-b border-border">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="font-mono text-xs text-primary bg-primary/10 px-2 py-0.5 rounded">{technique.id}</span>
              {technique.covered ? (
                <span className="text-xs text-emerald-400 bg-emerald-400/10 px-2 py-0.5 rounded border border-emerald-400/20">Covered</span>
              ) : (
                <span className="text-xs text-muted-foreground bg-secondary px-2 py-0.5 rounded border border-border">No Coverage</span>
              )}
            </div>
            <h2 className="font-bold text-foreground text-lg">{technique.name}</h2>
            <div className="text-xs text-muted-foreground mt-0.5">Tactic: {tacticName}</div>
          </div>
          <button onClick={onClose} aria-label="Close" className="p-1.5 text-muted-foreground hover:text-foreground hover:bg-secondary rounded-lg transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="p-5 space-y-4">
          {technique.alertCount > 0 ? (
            <div className="bg-primary/5 border border-primary/20 rounded-lg p-4">
              <div className="flex items-center gap-2 text-primary font-semibold text-sm mb-2">
                <AlertTriangle className="w-4 h-4" /> {technique.alertCount} Alert{technique.alertCount > 1 ? 's' : ''} Triggered
              </div>
              <p className="text-sm text-muted-foreground">Active detection rules are monitoring for this technique. Review the Alert Queue for incidents mapped to {technique.id}.</p>
            </div>
          ) : (
            <div className="bg-secondary/50 border border-border rounded-lg p-4 text-sm text-muted-foreground">
              No alerts have been triggered for this technique in the current dataset.
            </div>
          )}
          <div>
            <h4 className="text-xs font-semibold uppercase text-muted-foreground tracking-wider mb-2">About This Technique</h4>
            <p className="text-sm text-muted-foreground leading-relaxed">
              {technique.name} ({technique.id}) is a {tacticName.toLowerCase()} technique documented in the MITRE ATT&CK framework.
              {technique.covered
                ? ' Your current detection rules provide coverage against this technique.'
                : ' No detection rule is currently mapped to this technique — consider creating one in the Detection Engine.'}
            </p>
          </div>
          {matchedRuleIds.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold uppercase text-muted-foreground tracking-wider mb-2">Mapped Rules</h4>
              <div className="space-y-1.5">
                {matchedRuleIds.map(r => (
                  <div key={r.id} className="flex items-center justify-between bg-secondary/40 border border-border rounded-lg px-3 py-2">
                    <span className="text-sm text-foreground truncate">{r.name}</span>
                    {canWrite && (
                      <button
                        onClick={() => { onClose(); setLocation(`/rules/${r.id}/edit`); }}
                        aria-label={`Edit rule ${r.name}`}
                        className="p-1.5 text-muted-foreground hover:text-primary hover:bg-primary/10 rounded-lg transition-colors shrink-0 ml-2"
                      >
                        <Pencil className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
          <div className="flex gap-3 pt-2">
            <a
              href={`https://attack.mitre.org/techniques/${technique.id.replace('.', '/')}/`}
              target="_blank"
              rel="noopener noreferrer"
              className="flex-1 py-2 text-center text-sm text-primary border border-primary/30 rounded-lg hover:bg-primary/10 transition-colors"
            >
              View on MITRE →
            </a>
            {!technique.covered && canWrite && (
              <a href="/rules/new" className="flex-1 py-2 text-center text-sm bg-primary text-white rounded-lg hover:bg-primary/10 transition-colors">
                Create Rule
              </a>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default function MitreAttackPage() {
  const { can } = useAuthStore();
  const canWrite = can('rules:write');
  const [selectedTechnique, setSelectedTechnique] = useState<{ technique: MitreTechnique; tacticName: string } | null>(null);
  const [showCoveredOnly, setShowCoveredOnly] = useState(false);

  // Fetch real data to overlay onto the static MITRE matrix
  const { data: alertsData } = useQuery({
    queryKey: ['alerts', { limit: '500' }],
    queryFn: () => alertsApi.list({ limit: 500 }).then(r => r.data.alerts),
  });

  const { data: rulesData } = useQuery({
    queryKey: ['rules'],
    queryFn: () => rulesApi.list().then(r => r.data.rules.map(normalizeRule)),
  });

  const { data: dashStats } = useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: () => dashboardApi.stats().then(r => r.data),
  });

  // Merge dashboard heatmap counts into alert counts for richer color intensity
  const heatmapCounts = useMemo(() => {
    const m: Record<string, number> = {};
    (dashStats?.mitreHeatmap ?? []).forEach((h: any) => {
      const key = (h.technique ?? '').toUpperCase();
      if (key) m[key] = (m[key] ?? 0) + h.count;
    });
    return m;
  }, [dashStats]);

  // Compute coverage and alert counts entirely from real backend data
  const mitre = useMemo((): MitreTactic[] => {
    const coveredByRules = new Set<string>();
    const alertsByMitre: Record<string, number> = {};

    (rulesData ?? []).forEach(r => {
      r.mitreIds.forEach((id: string) => {
        coveredByRules.add(id.toUpperCase());
        coveredByRules.add(id.split('.')[0].toUpperCase());
      });
    });

    (alertsData ?? []).forEach((a: any) => {
      (a.mitreIds ?? []).forEach((id: string) => {
        const baseId = id.split('.')[0].toUpperCase();
        alertsByMitre[baseId] = (alertsByMitre[baseId] ?? 0) + 1;
        alertsByMitre[id.toUpperCase()] = (alertsByMitre[id.toUpperCase()] ?? 0) + 1;
      });
    });

    return MITRE_MATRIX.map(tactic => ({
      ...tactic,
      techniques: tactic.techniques.map(tech => {
        const techId = tech.id.toUpperCase();
        const baseId = techId.split('.')[0];
        const alertCount = alertsByMitre[techId] ?? alertsByMitre[baseId] ?? 0;
        const heatCount = heatmapCounts[techId] ?? heatmapCounts[baseId] ?? 0;
        const totalCount = Math.max(alertCount, heatCount);
        return {
          ...tech,
          covered: coveredByRules.has(techId) || coveredByRules.has(baseId),
          alertCount: totalCount,
        };
      }),
    }));
  }, [alertsData, rulesData, heatmapCounts]);

  // Build a map from uppercased technique ID -> [{id, name}] of rules covering it (deduplicated)
  const rulesByTechnique = useMemo(() => {
    const m: Record<string, { id: string; name: string }[]> = {};
    const seen: Record<string, Set<string>> = {};
    const addUnique = (techKey: string, entry: { id: string; name: string }) => {
      if (!seen[techKey]) seen[techKey] = new Set();
      if (seen[techKey].has(entry.id)) return;
      seen[techKey].add(entry.id);
      (m[techKey] ??= []).push(entry);
    };
    (rulesData ?? []).forEach(r => {
      r.mitreIds.forEach((mid: string) => {
        const key = mid.toUpperCase();
        const base = key.split('.')[0];
        const entry = { id: r.id, name: r.name };
        addUnique(key, entry);
        if (key !== base) addUnique(base, entry);
      });
    });
    return m;
  }, [rulesData]);

  const totalTechniques = mitre.reduce((acc, tactic) => acc + tactic.techniques.length, 0);
  const coveredTechniques = mitre.reduce((acc, tactic) => acc + tactic.techniques.filter(t => t.covered).length, 0);
  const totalAlerts = mitre.reduce((acc, tactic) => acc + tactic.techniques.reduce((a, t) => a + t.alertCount, 0), 0);
  const coveragePercent = Math.round((coveredTechniques / totalTechniques) * 100) || 0;

  const maxAlertCount = useMemo(() => Math.max(1, ...mitre.flatMap(t => t.techniques.map(tech => tech.alertCount))), [mitre]);
  const heatClass = (count: number) => {
    if (count === 0) return { bg: '', border: '' };
    const ratio = Math.min(count / maxAlertCount, 1);
    if (ratio <= 0.2) return { bg: 'bg-red-500/10', border: 'border-red-500/30' };
    if (ratio <= 0.4) return { bg: 'bg-red-500/20', border: 'border-red-500/40' };
    if (ratio <= 0.6) return { bg: 'bg-red-500/30', border: 'border-red-500/50' };
    if (ratio <= 0.8) return { bg: 'bg-red-500/40', border: 'border-red-500/60' };
    return { bg: 'bg-red-500/60', border: 'border-red-500/70' };
  };

  const filteredMatrix = showCoveredOnly
    ? mitre.map(tactic => ({ ...tactic, techniques: tactic.techniques.filter(t => t.covered) })).filter(t => t.techniques.length > 0)
    : mitre;

  return (
    <>
      {selectedTechnique && (
        <TechniquePopup
          technique={selectedTechnique.technique}
          tacticName={selectedTechnique.tacticName}
          matchedRuleIds={rulesByTechnique[selectedTechnique.technique.id.toUpperCase()] ?? []}
          canWrite={canWrite}
          onClose={() => setSelectedTechnique(null)}
        />
      )}

      <div className="flex flex-col gap-6">
        <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold tracking-tight text-foreground flex items-center gap-3">
              <Target className="w-8 h-8 text-primary" /> MITRE ATT&CK Matrix
            </h1>
            <p className="text-muted-foreground mt-1">Visualize detection coverage across the adversary attack lifecycle.</p>
          </div>

          <div className="flex items-center gap-4 flex-wrap">
            <button
              onClick={() => setShowCoveredOnly(!showCoveredOnly)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium border transition-all ${showCoveredOnly ? 'bg-primary/10 border-primary/30 text-primary' : 'bg-secondary border-border text-muted-foreground hover:text-foreground'}`}
            >
              <ShieldCheck className="w-4 h-4" />
              {showCoveredOnly ? 'Showing Covered Only' : 'Show Covered Only'}
            </button>
            <div className="bg-card border border-border rounded-xl p-3 flex items-center gap-4 shadow-lg">
              <div className="flex items-center gap-3">
                <div className="relative w-12 h-12">
                  <svg className="w-12 h-12 -rotate-90" viewBox="0 0 36 36">
                    <circle cx="18" cy="18" r="15.9" fill="none" stroke="hsl(var(--secondary))" strokeWidth="3" />
                    <circle cx="18" cy="18" r="15.9" fill="none" stroke="hsl(var(--primary))" strokeWidth="3"
                      strokeDasharray={`${coveragePercent} ${100 - coveragePercent}`} strokeLinecap="round" />
                  </svg>
                  <div className="absolute inset-0 flex items-center justify-center text-xs font-bold text-foreground">{coveragePercent}%</div>
                </div>
                <div>
                  <div className="text-xs text-muted-foreground">Coverage</div>
                  <div className="text-sm font-bold text-foreground">{coveredTechniques}/{totalTechniques}</div>
                </div>
              </div>
              <div className="w-px h-8 bg-border" />
              <div className="text-center">
                <div className="text-xs text-muted-foreground">Active Alerts</div>
                <div className="text-sm font-bold text-primary">{totalAlerts}</div>
              </div>
            </div>
          </div>
        </div>

        {/* Legend */}
        <div className="flex items-center gap-6 text-xs text-muted-foreground flex-wrap">
          <div className="flex items-center gap-2">
            <div className="w-4 h-4 bg-primary/15 border border-primary/40 rounded-sm" />
            <span>Covered by rule</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-4 h-4 bg-secondary/50 border border-border/50 rounded-sm" />
            <span>No coverage</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="flex gap-0.5">
              {[15, 30, 45, 60].map(o => (
                <div key={o} className={`w-3 h-4 rounded-sm border border-red-400/30 bg-red-500/${o}`} />
              ))}
            </div>
            <span>Alert heat intensity</span>
          </div>
          <span className="text-muted-foreground/60 ml-2">Click any technique card for details</span>
        </div>

        {/* Matrix */}
        <div className="bg-card border border-border rounded-xl shadow-lg shadow-black/20 overflow-x-auto p-4">
          <div className="inline-flex gap-2 min-w-full pb-2">
            {filteredMatrix.map(tactic => (
              <div key={tactic.id} className="flex-1 min-w-45 max-w-55 flex flex-col gap-1.5">
                <div className="bg-secondary/60 border border-border p-2.5 rounded-lg text-center">
                  <div className="font-bold text-foreground text-xs mb-0.5 leading-tight">{tactic.name}</div>
                  <div className="font-mono text-[10px] text-muted-foreground">{tactic.id}</div>
                  <div className="mt-1.5 text-[10px] font-semibold text-primary">
                    {tactic.techniques.filter(t => t.covered).length}/{tactic.techniques.length} covered
                  </div>
                </div>

                {tactic.techniques.map(tech => {
                  const heat = heatClass(tech.alertCount);
                  return (
                  <button
                    key={`${tactic.id}-${tech.id}`}
                    onClick={() => setSelectedTechnique({ technique: tech, tacticName: tactic.name })}
                    className={`p-2.5 rounded-lg border text-left text-xs transition-all hover:-translate-y-0.5 hover:shadow-md active:translate-y-0 ${tech.covered
                      ? 'border-primary/30 text-foreground hover:border-primary shadow-[0_0_8px_rgba(59,130,246,0.08)]'
                      : 'border-border/40 text-muted-foreground hover:border-border hover:bg-secondary/60'
                    } ${tech.alertCount > 0 ? `${heat.bg} ${heat.border}` : tech.covered ? 'bg-primary/10' : 'bg-secondary/30'}`}
                  >
                    <div className="font-medium leading-tight mb-1">{tech.name}</div>
                    <div className="flex justify-between items-center">
                      <span className="font-mono text-[10px] opacity-70">{tech.id}</span>
                      {tech.alertCount > 0 && (
                        <span className="bg-red-500 text-white text-[9px] font-bold px-1.5 py-0.5 rounded-full">
                          {tech.alertCount}
                        </span>
                      )}
                    </div>
                  </button>
                  );
                })}
              </div>
            ))}
          </div>
        </div>
      </div>
    </>
  );
}
