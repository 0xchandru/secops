import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { rulesApi } from '@/lib/api';
import { useAuthStore } from '@/store/authStore';
import { Shield, AlertTriangle, Activity, Loader2, XCircle, ExternalLink } from 'lucide-react';
import { Link } from 'wouter';
import { SeverityBadge } from '@/components/ui/Badge';

interface RuleWidgetProps {
  ruleId: string;
  ruleName?: string;
  onClose?: () => void;
}

export default function RuleWidget({ ruleId, ruleName, onClose }: RuleWidgetProps) {
  const { can } = useAuthStore();
  const canEdit = can('rules:write');

  const { data: ruleData, isLoading } = useQuery({
    queryKey: ['rule', ruleId],
    queryFn: () => rulesApi.getById(ruleId).then(r => r.data.rule ?? r.data),
    enabled: !!ruleId,
  });

  if (isLoading) {
    return (
      <div className="bg-card border border-border rounded-xl p-4 shadow-lg animate-pulse">
        <div className="flex items-center gap-2 text-muted-foreground text-sm">
          <Loader2 className="w-4 h-4 animate-spin" /> Loading rule…
        </div>
      </div>
    );
  }

  if (!ruleData) {
    return (
      <div className="bg-card border border-border rounded-xl p-4 shadow-lg">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-purple-400" />
            <span className="text-sm text-foreground font-medium">{ruleName || 'Unknown Rule'}</span>
          </div>
          {onClose && (
            <button aria-label="Close" onClick={onClose} className="text-muted-foreground hover:text-foreground p-0.5">
              <XCircle className="w-4 h-4" />
            </button>
          )}
        </div>
        <p className="text-xs text-muted-foreground mt-2">Rule details could not be loaded. The rule may have been deleted or the reference is outdated.</p>
      </div>
    );
  }

  const rule = ruleData;

  return (
    <div className="bg-card border border-border rounded-xl p-4 shadow-lg">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-purple-400" />
          <span className="font-semibold text-foreground text-sm truncate max-w-48">{rule.name}</span>
          {rule.severity && <SeverityBadge severity={rule.severity} />}
        </div>
        <div className="flex items-center gap-1">
          {canEdit && (
            <Link
              href={`/rules`}
              className="text-xs text-primary hover:underline flex items-center gap-1"
            >
              Edit <ExternalLink className="w-3 h-3" />
            </Link>
          )}
          {onClose && (
            <button aria-label="Close" onClick={onClose} className="text-muted-foreground hover:text-foreground p-0.5 ml-1">
              <XCircle className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>

      {rule.description && (
        <p className="text-xs text-muted-foreground mb-3 line-clamp-2">{rule.description}</p>
      )}

      <div className="grid grid-cols-2 gap-2 text-xs">
        <div>
          <span className="text-muted-foreground">Status</span>
          <div className={`font-medium ${rule.enabled ? 'text-emerald-400' : 'text-muted-foreground'}`}>
            {rule.enabled ? 'Enabled' : 'Disabled'}
          </div>
        </div>
        {rule.mitreTechniqueId && (
          <div>
            <span className="text-muted-foreground">MITRE</span>
            <div className="font-mono text-purple-400">{rule.mitreTechniqueId}</div>
          </div>
        )}
        {rule.source && (
          <div>
            <span className="text-muted-foreground">Source</span>
            <div className="text-foreground">{rule.source}</div>
          </div>
        )}
        {rule.ruleType && (
          <div>
            <span className="text-muted-foreground">Type</span>
            <div className="text-foreground capitalize">{rule.ruleType}</div>
          </div>
        )}
      </div>
    </div>
  );
}
