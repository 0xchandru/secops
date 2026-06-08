import { getSourceLabel, getSourceMax, scoreToPercent } from '@/lib/ioc-helpers';

interface Props {
  breakdown: Record<string, number> | null | undefined;
}

const BAR_COLORS: Record<string, string> = {
  virustotal:    '#ef4444',
  abuseipdb:     '#f97316',
  alienvault:    '#eab308',
  urlhaus:       '#8b5cf6',
  greynoise:     '#6366f1',
  malwarebazaar: '#ec4899',
  threatfox:     '#14b8a6',
};

function getBarColor(key: string): string {
  return BAR_COLORS[key.toLowerCase()] ?? '#64748b';
}

export function ThreatScoreBar({ breakdown }: Props) {
  if (!breakdown || Object.keys(breakdown).length === 0) return null;

  return (
    <div className="rounded-xl border border-border bg-card/50 p-4 space-y-3">
      <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Score Breakdown</h4>
      {Object.entries(breakdown).map(([source, score]) => {
        const max = getSourceMax(source);
        const pct = scoreToPercent(score, max);
        const color = getBarColor(source);
        return (
          <div key={source} className="space-y-1">
            <div className="flex items-center justify-between text-xs">
              <span className="text-foreground font-medium">{getSourceLabel(source)}</span>
              <span className="text-muted-foreground font-mono">{score.toFixed(1)}/{max}</span>
            </div>
            <div className="h-2 w-full rounded-full bg-secondary overflow-hidden">
              <div
                className="h-full rounded-full transition-all duration-500"
                style={{ width: `${pct}%`, backgroundColor: color }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}
