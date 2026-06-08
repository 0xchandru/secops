import { getRiskColor } from '@/lib/ioc-helpers';

interface Props {
  ioc: string;
  score: number | null | undefined;
  riskLevel: string | null | undefined;
  iocType?: string;
  isSelected: boolean;
  onClick: () => void;
}

const TYPE_LABELS: Record<string, string> = {
  ip: 'IP',
  domain: 'DOM',
  url: 'URL',
  md5: 'MD5',
  sha256: 'SHA256',
  sha1: 'SHA1',
};

export function IocSelectorChip({ ioc, score, riskLevel, iocType, isSelected, onClick }: Props) {
  const level = riskLevel ?? 'unknown';
  const { text, bg, border } = getRiskColor(level);
  const typeLabel = iocType ? (TYPE_LABELS[iocType.toLowerCase()] ?? iocType.toUpperCase()) : 'IOC';

  const display = ioc.length > 22 ? ioc.slice(0, 10) + '…' + ioc.slice(-8) : ioc;

  return (
    <button
      onClick={onClick}
      title={ioc}
      style={isSelected ? { background: bg, borderColor: border, color: text } : undefined}
      className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-mono border transition-all ${
        isSelected
          ? 'ring-2 ring-offset-1 ring-offset-background'
          : 'border-border bg-secondary text-muted-foreground hover:bg-secondary/80'
      }`}
    >
      <span className={`text-[9px] px-1 py-0.5 rounded font-bold ${isSelected ? 'bg-white/10' : 'bg-muted text-muted-foreground'}`}>
        {typeLabel}
      </span>
      {display}
      {score != null && (
        <span
          style={isSelected ? { color: text } : undefined}
          className={`font-bold ${isSelected ? '' : 'text-muted-foreground'}`}
        >
          {score.toFixed(0)}
        </span>
      )}
    </button>
  );
}
