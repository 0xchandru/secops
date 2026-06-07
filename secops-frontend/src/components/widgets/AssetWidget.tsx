import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { assetsApi } from '@/lib/api';
import { Server, Shield, AlertTriangle, Activity, Loader2, XCircle } from 'lucide-react';

interface AssetWidgetProps {
  hostname?: string;
  ip?: string;
  onClose?: () => void;
}

const CRITICALITY_STYLES: Record<string, string> = {
  critical: 'text-red-400 bg-red-400/10 border-red-400/20',
  high: 'text-orange-400 bg-orange-400/10 border-orange-400/20',
  medium: 'text-yellow-400 bg-yellow-400/10 border-yellow-400/20',
  low: 'text-green-400 bg-green-400/10 border-green-400/20',
};

export default function AssetWidget({ hostname, ip, onClose }: AssetWidgetProps) {
  const { data, isLoading } = useQuery({
    queryKey: ['asset-lookup', hostname, ip],
    queryFn: () => assetsApi.byIdentifier({ hostname, ip }).then(r => r.data),
    enabled: !!(hostname || ip),
  });

  if (isLoading) {
    return (
      <div className="bg-card border border-border rounded-xl p-4 shadow-lg animate-pulse">
        <div className="flex items-center gap-2 text-muted-foreground text-sm">
          <Loader2 className="w-4 h-4 animate-spin" /> Looking up asset…
        </div>
      </div>
    );
  }

  if (!data?.found) {
    return (
      <div className="bg-card border border-border rounded-xl p-4 shadow-lg">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2 text-muted-foreground text-sm font-medium">
            <Server className="w-4 h-4" /> Unknown Asset
          </div>
          {onClose && (
            <button aria-label="Close" onClick={onClose} className="text-muted-foreground hover:text-foreground p-0.5">
              <XCircle className="w-4 h-4" />
            </button>
          )}
        </div>
        <p className="text-xs text-muted-foreground">
          <span className="font-mono text-foreground">{hostname || ip}</span> is not registered in the asset inventory.
        </p>
      </div>
    );
  }

  const asset = data.asset;
  const critClass = CRITICALITY_STYLES[asset.criticality] ?? 'text-muted-foreground bg-secondary border-border';

  return (
    <div className="bg-card border border-border rounded-xl p-4 shadow-lg">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Server className="w-4 h-4 text-primary" />
          <span className="font-semibold text-foreground text-sm">{asset.hostname}</span>
          {asset.criticality && (
            <span className={`text-xs px-1.5 py-0.5 rounded-full border font-medium ${critClass}`}>
              {asset.criticality.toUpperCase()}
            </span>
          )}
        </div>
        {onClose && (
          <button aria-label="Close" onClick={onClose} className="text-muted-foreground hover:text-foreground p-0.5">
            <XCircle className="w-4 h-4" />
          </button>
        )}
      </div>

      <div className="grid grid-cols-2 gap-2 text-xs">
        {asset.ip && (
          <div>
            <span className="text-muted-foreground">IP</span>
            <div className="font-mono text-foreground">{asset.ip}</div>
          </div>
        )}
        {asset.os && (
          <div>
            <span className="text-muted-foreground">OS</span>
            <div className="text-foreground">{asset.os}</div>
          </div>
        )}
        {asset.owner && (
          <div>
            <span className="text-muted-foreground">Owner</span>
            <div className="text-foreground">{asset.owner}</div>
          </div>
        )}
        {asset.department && (
          <div>
            <span className="text-muted-foreground">Dept</span>
            <div className="text-foreground">{asset.department}</div>
          </div>
        )}
      </div>

      <div className="flex items-center gap-4 mt-3 pt-3 border-t border-border text-xs">
        <div className="flex items-center gap-1.5">
          <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
          <span className="text-foreground font-medium">{data.alertCount ?? 0}</span>
          <span className="text-muted-foreground">alerts</span>
        </div>
        <div className="flex items-center gap-1.5">
          <Activity className="w-3.5 h-3.5 text-primary" />
          <span className="text-foreground font-medium">{data.eventCount ?? 0}</span>
          <span className="text-muted-foreground">events</span>
        </div>
      </div>
    </div>
  );
}
