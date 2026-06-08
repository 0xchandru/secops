import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '@/lib/api';
import { getRiskColor, getRecommendedAction } from '@/lib/ioc-helpers';
import { ThreatScoreBar } from './ThreatScoreBar';
import { SourceResultCard } from './SourceResultCard';
import { MitreTechniqueList } from './MitreTechniqueList';
import { IocSelectorChip } from './IocSelectorChip';
import { RefreshCw, ExternalLink, WifiOff, Loader2 } from 'lucide-react';

interface AlertEnrichmentResult {
  iocValue: string;
  iocType: string;
  extractedFrom: string | null;
  confidence: string | null;
  threatScore: number | null;
  riskLevel: string | null;
  iocConfidence: string | null;
  breakdown: Record<string, number> | null;
  mitreMappings: Array<{ technique_id: string; technique: string; tactic: string; confidence: string }> | null;
  sourceResults: Record<string, any> | null;
  recommendedAction: string | null;
  tags: string[] | null;
  queriedAt: string | null;
  queryTimeMs: number | null;
  fromCache: boolean;
}

async function getAlertEnrichments(alertId: string): Promise<AlertEnrichmentResult[]> {
  const { data } = await apiClient.get<{ enrichments: AlertEnrichmentResult[]; count: number }>(
    `/enrichment/alert/${alertId}`
  );
  return data.enrichments ?? [];
}

async function triggerAlertEnrichment(alertId: string) {
  const { data } = await apiClient.post(`/enrichment/alert/${alertId}`);
  return data;
}

function formatRelativeTime(ts: string | null): string {
  if (!ts) return 'never';
  const diff = Date.now() - new Date(ts).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

interface Props {
  alertId: string;
}

export function ThreatLensReportTab({ alertId }: Props) {
  const qc = useQueryClient();
  const [selectedIoc, setSelectedIoc] = useState<string | null>(null);
  const [enrichmentTriggered, setEnrichmentTriggered] = useState(false);

  const { data: enrichments, isLoading, isError, isFetching } = useQuery({
    queryKey: ['enrichment', alertId],
    queryFn: () => getAlertEnrichments(alertId),
    staleTime: 5 * 60 * 1000,
    retry: 1,
  });

  const enrichMutation = useMutation({
    mutationFn: () => triggerAlertEnrichment(alertId),
    onSuccess: () => {
      setEnrichmentTriggered(true);
      // Poll for results after triggering
      setTimeout(() => {
        qc.invalidateQueries({ queryKey: ['enrichment', alertId] });
      }, 3000);
    },
  });

  // Auto-trigger enrichment if no results
  useEffect(() => {
    if (!isLoading && !enrichmentTriggered && (!enrichments || enrichments.length === 0)) {
      setEnrichmentTriggered(true);
      enrichMutation.mutate();
    }
  }, [isLoading, enrichments]);

  // Auto-select first IOC
  useEffect(() => {
    if (enrichments?.length && !selectedIoc) {
      setSelectedIoc(enrichments[0].iocValue);
    }
  }, [enrichments]);

  const threatlensUrl = (import.meta.env.VITE_THREATLENS_URL as string) ?? '';

  if (isLoading || (enrichMutation.isPending && (!enrichments || enrichments.length === 0))) {
    return (
      <div className="flex flex-col items-center justify-center py-20 gap-4">
        <Loader2 className="w-8 h-8 text-blue-400 animate-spin" />
        <p className="text-muted-foreground text-sm font-medium">Querying threat intelligence sources…</p>
        <p className="text-muted-foreground/60 text-xs">VirusTotal · AbuseIPDB · AlienVault · URLhaus · GreyNoise · MalwareBazaar · ThreatFox</p>
      </div>
    );
  }

  if (isError || !enrichments?.length) {
    return (
      <div className="flex flex-col items-center justify-center py-20 gap-5">
        <div className="w-14 h-14 rounded-full bg-secondary flex items-center justify-center">
          <WifiOff className="w-7 h-7 text-muted-foreground/50" />
        </div>
        <div className="text-center">
          <p className="text-foreground font-medium mb-1">No enrichment data available</p>
          <p className="text-muted-foreground text-sm">ThreatLens may be offline or no actionable IOCs were found</p>
        </div>
        <button
          onClick={() => {
            setEnrichmentTriggered(false);
            enrichMutation.mutate();
          }}
          disabled={enrichMutation.isPending}
          className="flex items-center gap-2 px-5 py-2.5 bg-primary/10 text-primary border border-primary/30 text-sm rounded-xl hover:bg-primary/20 transition-all disabled:opacity-50"
        >
          {enrichMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
          Retry Enrichment
        </button>
      </div>
    );
  }

  const selected = enrichments.find(e => e.iocValue === selectedIoc) ?? enrichments[0];
  const { text, bg, border } = getRiskColor(selected.riskLevel);
  const action = selected.recommendedAction ?? getRecommendedAction(selected.threatScore);

  return (
    <div className="space-y-4">
      {/* Multi-IOC selector */}
      {enrichments.length > 1 && (
        <div className="flex gap-2 flex-wrap">
          {enrichments.map(e => (
            <IocSelectorChip
              key={e.iocValue}
              ioc={e.iocValue}
              score={e.threatScore}
              riskLevel={e.riskLevel}
              iocType={e.iocType}
              isSelected={e.iocValue === selectedIoc}
              onClick={() => setSelectedIoc(e.iocValue)}
            />
          ))}
        </div>
      )}

      {/* Verdict card */}
      <div
        className="rounded-xl p-6 text-center relative overflow-hidden"
        style={{ background: bg, border: `1px solid ${border}` }}
      >
        {isFetching && (
          <div className="absolute top-3 right-3">
            <Loader2 className="w-3.5 h-3.5 animate-spin opacity-40" style={{ color: text }} />
          </div>
        )}
        <div className="font-mono text-5xl font-bold mb-1" style={{ color: text }}>
          {selected.threatScore != null ? selected.threatScore.toFixed(1) : 'N/A'}
        </div>
        <div className="text-lg font-semibold tracking-widest uppercase mt-1 mb-2" style={{ color: text }}>
          {selected.riskLevel ?? 'unknown'}
        </div>
        <p className="text-xs opacity-70 mb-3" style={{ color: text }}>
          Confidence: {selected.iocConfidence ?? selected.confidence ?? '—'} ·
          Queried {formatRelativeTime(selected.queriedAt)} ·
          {selected.fromCache && ' (cached)'}
          {selected.queryTimeMs && ` ${selected.queryTimeMs}ms`}
        </p>
        <div className="text-sm font-medium px-4 py-2.5 rounded-lg bg-black/20" style={{ color: text }}>
          {action}
        </div>
      </div>

      {/* IOC details */}
      <div className="flex items-center gap-3 px-4 py-3 rounded-xl bg-secondary/40 border border-border">
        <span className="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold">IOC</span>
        <code className="font-mono text-sm text-foreground flex-1 break-all">{selected.iocValue}</code>
        <span className="text-[10px] bg-secondary px-2 py-1 rounded text-muted-foreground uppercase">
          {selected.iocType}
        </span>
        {selected.extractedFrom && (
          <span className="text-[10px] text-muted-foreground/60">from {selected.extractedFrom}</span>
        )}
      </div>

      {/* Tags */}
      {selected.tags && selected.tags.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {selected.tags.map(tag => (
            <span key={tag} className="text-[10px] px-2 py-1 rounded-lg bg-secondary text-muted-foreground border border-border">
              {tag}
            </span>
          ))}
        </div>
      )}

      {/* Score breakdown bars */}
      <ThreatScoreBar breakdown={selected.breakdown} />

      {/* Source result cards */}
      {selected.sourceResults && Object.keys(selected.sourceResults).length > 0 && (
        <div className="space-y-2">
          {Object.entries(selected.sourceResults).map(([source, result]) => (
            <SourceResultCard key={source} source={source} data={result} />
          ))}
        </div>
      )}

      {/* MITRE techniques from ThreatLens */}
      {selected.mitreMappings && selected.mitreMappings.length > 0 && (
        <MitreTechniqueList techniques={selected.mitreMappings} />
      )}

      {/* Action buttons */}
      <div className="flex gap-3 pt-1">
        <button
          onClick={() => {
            setEnrichmentTriggered(false);
            enrichMutation.mutate();
          }}
          disabled={enrichMutation.isPending}
          className="flex-1 flex items-center justify-center gap-2 py-2.5 border border-border text-muted-foreground text-sm rounded-xl hover:border-foreground/30 hover:text-foreground transition-all disabled:opacity-50"
        >
          {enrichMutation.isPending
            ? <Loader2 className="w-4 h-4 animate-spin" />
            : <RefreshCw className="w-4 h-4" />}
          Re-enrich
        </button>
        {threatlensUrl && (
          <a
            href={`${threatlensUrl}/lookup?q=${encodeURIComponent(selected.iocValue)}`}
            target="_blank"
            rel="noreferrer"
            className="flex-1 flex items-center justify-center gap-2 py-2.5 bg-blue-900/30 text-blue-300 text-sm rounded-xl border border-blue-700/50 hover:bg-blue-900/50 transition-all"
          >
            <ExternalLink className="w-4 h-4" />
            Open in ThreatLens
          </a>
        )}
      </div>
    </div>
  );
}
