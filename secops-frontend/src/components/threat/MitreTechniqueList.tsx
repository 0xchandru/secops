interface Technique {
  technique_id: string;
  technique: string;
  tactic: string;
  confidence: string;
}

interface Props {
  techniques: Technique[];
  label?: string;
}

const CONFIDENCE_COLORS: Record<string, string> = {
  high:   'text-red-400 bg-red-500/10 border-red-500/20',
  medium: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
  low:    'text-slate-400 bg-slate-500/10 border-slate-500/20',
};

export function MitreTechniqueList({ techniques, label = 'MITRE ATT&CK (from ThreatLens)' }: Props) {
  if (!techniques || techniques.length === 0) return null;

  return (
    <div className="rounded-xl border border-border bg-card/50 p-4 space-y-3">
      <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
        <span className="w-2 h-2 rounded-full bg-purple-400 shrink-0" />
        {label}
      </h4>
      <div className="space-y-2">
        {techniques.map((t) => {
          const confColor = CONFIDENCE_COLORS[t.confidence?.toLowerCase()] ?? CONFIDENCE_COLORS.low;
          return (
            <div key={t.technique_id} className="flex items-start gap-3 p-2 rounded-lg bg-secondary/30">
              <span className="font-mono text-xs text-purple-400 bg-purple-500/10 border border-purple-500/20 px-2 py-0.5 rounded shrink-0 mt-0.5">
                {t.technique_id}
              </span>
              <div className="flex-1 min-w-0">
                <p className="text-sm text-foreground font-medium truncate">{t.technique}</p>
                <p className="text-[11px] text-muted-foreground capitalize">{t.tactic}</p>
              </div>
              <span className={`text-[10px] px-1.5 py-0.5 rounded border font-medium capitalize shrink-0 ${confColor}`}>
                {t.confidence}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
