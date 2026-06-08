import { getRiskColor } from '@/lib/ioc-helpers';

interface Props {
  score: number | null | undefined;
  riskLevel: string | null | undefined;
  confidence?: string | null;
  size?: 'sm' | 'md';
}

export function ThreatBadge({ score, riskLevel, confidence, size = 'sm' }: Props) {
  if (!score && !riskLevel) {
    return <span className="text-muted-foreground/40 text-xs font-mono">—</span>;
  }

  const level = riskLevel ?? 'unknown';
  const { text, bg, border } = getRiskColor(level);

  return (
    <span
      title={`ThreatLens: ${score != null ? score.toFixed(0) + '/100' : 'N/A'} · ${level} · ${confidence ?? ''}`}
      style={{ background: bg, color: text, border: `1px solid ${border}` }}
      className={`inline-flex items-center gap-1 rounded font-mono whitespace-nowrap ${size === 'sm' ? 'px-1.5 py-0.5 text-[10px]' : 'px-2.5 py-1 text-xs'}`}
    >
      {score != null ? `${score.toFixed(0)}/100` : 'N/A'}
      <span className="opacity-60">·</span>
      {level.toUpperCase()}
    </span>
  );
}
