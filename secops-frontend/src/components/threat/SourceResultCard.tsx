import { useState } from 'react';
import { ChevronDown, ChevronUp } from 'lucide-react';
import { getSourceLabel } from '@/lib/ioc-helpers';

interface Props {
  source: string;
  data: Record<string, any> | null;
}

const SOURCE_ICONS: Record<string, string> = {
  virustotal:    'VT',
  abuseipdb:     'AB',
  alienvault:    'AV',
  urlhaus:       'UH',
  greynoise:     'GN',
  malwarebazaar: 'MB',
  threatfox:     'TF',
};

// Pull out the most important fields per source for the summary line
function getSummaryLine(source: string, data: Record<string, any>): string {
  const s = source.toLowerCase();
  if (s === 'virustotal') {
    const mal = data.malicious ?? data.malicious_count ?? 0;
    const sus = data.suspicious ?? data.suspicious_count ?? 0;
    const total = data.total ?? data.total_votes ?? 0;
    return `Malicious: ${mal} · Suspicious: ${sus} · Total engines: ${total}`;
  }
  if (s === 'abuseipdb') {
    const conf = data.abuseConfidenceScore ?? data.confidence ?? 0;
    const reports = data.totalReports ?? data.reports ?? 0;
    return `Confidence: ${conf}% · Reports: ${reports}`;
  }
  if (s === 'alienvault') {
    const pulses = data.pulse_count ?? data.pulses ?? 0;
    return `Pulses: ${pulses}`;
  }
  if (s === 'urlhaus') {
    const threat = data.threat ?? data.tags ?? '';
    return `Threat: ${Array.isArray(threat) ? threat.join(', ') : threat || 'N/A'}`;
  }
  if (s === 'greynoise') {
    const cls = data.classification ?? data.status ?? 'unknown';
    const noise = data.noise ?? false;
    return `Classification: ${cls} · Noise: ${noise ? 'Yes' : 'No'}`;
  }
  if (s === 'malwarebazaar') {
    const tags = data.tags ?? [];
    return tags.length ? `Tags: ${(Array.isArray(tags) ? tags : [tags]).join(', ')}` : 'No tags';
  }
  if (s === 'threatfox') {
    const malware = data.malware_printable ?? data.malware ?? '';
    return malware ? `Malware: ${malware}` : 'No data';
  }
  return '';
}

function renderValue(val: any): string {
  if (val === null || val === undefined) return '—';
  if (Array.isArray(val)) return val.join(', ') || '—';
  if (typeof val === 'boolean') return val ? 'Yes' : 'No';
  if (typeof val === 'object') return JSON.stringify(val);
  return String(val);
}

export function SourceResultCard({ source, data }: Props) {
  const [open, setOpen] = useState(false);

  if (!data) return null;

  const label = getSourceLabel(source);
  const icon = SOURCE_ICONS[source.toLowerCase()] ?? source.slice(0, 2).toUpperCase();
  const summary = getSummaryLine(source, data);

  return (
    <div className="rounded-xl border border-border bg-card/50 overflow-hidden">
      <button
        onClick={() => setOpen(v => !v)}
        className="w-full flex items-center justify-between px-4 py-3 hover:bg-secondary/30 transition-colors text-left"
      >
        <div className="flex items-center gap-3">
          <span className="w-7 h-7 rounded-md bg-secondary flex items-center justify-center text-[10px] font-bold text-muted-foreground shrink-0">
            {icon}
          </span>
          <div>
            <span className="text-sm font-semibold text-foreground">{label}</span>
            {summary && (
              <p className="text-[11px] text-muted-foreground mt-0.5">{summary}</p>
            )}
          </div>
        </div>
        {open ? <ChevronUp className="w-4 h-4 text-muted-foreground shrink-0" /> : <ChevronDown className="w-4 h-4 text-muted-foreground shrink-0" />}
      </button>

      {open && (
        <div className="border-t border-border/50 px-4 py-3 bg-background/50">
          <div className="grid grid-cols-2 gap-x-4 gap-y-1.5">
            {Object.entries(data)
              .filter(([k]) => !['error', '__raw'].includes(k))
              .map(([key, val]) => (
                <div key={key} className="col-span-1">
                  <span className="text-[10px] uppercase tracking-wider text-muted-foreground/60">{key.replace(/_/g, ' ')}</span>
                  <p className="text-xs text-foreground font-mono break-all">{renderValue(val)}</p>
                </div>
              ))}
          </div>
        </div>
      )}
    </div>
  );
}
