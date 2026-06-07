import React, { useState, useMemo, useEffect } from 'react';
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter,
} from '@/components/ui/dialog';
import { ROLE_LABELS, ROLE_COLORS, ROLE_HIERARCHY, ALL_ROLES_ORDERED, getNextHigherRole, getRolesAbove } from '@/lib/constants';
import {
  TrendingUp, Search, ChevronRight, Loader2, Users, ArrowUp, AlertTriangle, Shield,
} from 'lucide-react';

export interface EscalateDialogUser {
  id: string;
  username: string;
  displayName?: string | null;
  role: string;
}

interface EscalateDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  targets: EscalateDialogUser[];
  currentAssigneeRole?: string;
  alertTitle?: string;
  isPending?: boolean;
  onEscalate: (targetId: string, reason: string) => void;
}

export default function EscalateDialog({
  open, onOpenChange, targets, currentAssigneeRole, alertTitle,
  isPending, onEscalate,
}: EscalateDialogProps) {
  const [selectedTarget, setSelectedTarget] = useState<string | null>(null);
  const [reason, setReason] = useState('');
  const [roleFilter, setRoleFilter] = useState<string>('all');
  const [search, setSearch] = useState('');

  // Auto-select the next higher role filter on open
  const nextRole = useMemo(() =>
    currentAssigneeRole ? getNextHigherRole(currentAssigneeRole) : null,
    [currentAssigneeRole],
  );

  useEffect(() => {
    if (open && nextRole) {
      setRoleFilter(nextRole);
    }
  }, [open, nextRole]);

  // Filter targets to only show users with roles above current assignee (escalation = upward only)
  const validTargets = useMemo(() => {
    const higherRoles = currentAssigneeRole ? getRolesAbove(currentAssigneeRole) : Object.keys(ROLE_HIERARCHY);
    return targets.filter(t => higherRoles.includes(t.role));
  }, [targets, currentAssigneeRole]);

  const availableRoles = useMemo(() => {
    const roles = new Set(validTargets.map(t => t.role));
    return ALL_ROLES_ORDERED.filter(r => roles.has(r.value));
  }, [validTargets]);

  const filteredTargets = useMemo(() => {
    let list = validTargets;
    if (roleFilter !== 'all') list = list.filter(t => t.role === roleFilter);
    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter(t =>
        (t.displayName ?? t.username).toLowerCase().includes(q) ||
        t.username.toLowerCase().includes(q),
      );
    }
    return list.sort((a, b) => (ROLE_HIERARCHY[a.role] ?? 0) - (ROLE_HIERARCHY[b.role] ?? 0));
  }, [validTargets, roleFilter, search]);

  const selectedTargetObj = useMemo(() =>
    targets.find(t => t.id === selectedTarget),
    [targets, selectedTarget],
  );

  const canConfirm = !!selectedTarget && reason.trim().length >= 10;

  const handleOpenChange = (next: boolean) => {
    if (!next) { setSelectedTarget(null); setReason(''); setSearch(''); setRoleFilter('all'); }
    onOpenChange(next);
  };

  const handleConfirm = () => {
    if (selectedTarget && reason.trim().length >= 10) {
      onEscalate(selectedTarget, reason.trim());
    }
  };

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="max-w-lg max-h-[85vh] flex flex-col">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <TrendingUp className="w-5 h-5 text-red-400" />
            Escalate Alert
          </DialogTitle>
          {alertTitle && (
            <DialogDescription className="truncate">{alertTitle}</DialogDescription>
          )}
        </DialogHeader>

        <div className="flex flex-col gap-4 flex-1 overflow-hidden">
          {/* Hierarchy indicator */}
          {currentAssigneeRole && (
            <div className="flex items-center gap-2 p-3 bg-red-500/5 border border-red-500/20 rounded-lg text-sm">
              <ArrowUp className="w-4 h-4 text-red-400 shrink-0" />
              <span className="text-muted-foreground">
                Escalating from <span className={`font-medium px-1.5 py-0.5 rounded border ${ROLE_COLORS[currentAssigneeRole]}`}>
                  {ROLE_LABELS[currentAssigneeRole]}
                </span>
                {nextRole && (
                  <> — suggested: <span className={`font-medium px-1.5 py-0.5 rounded border ${ROLE_COLORS[nextRole]}`}>
                    {ROLE_LABELS[nextRole]}
                  </span></>
                )}
              </span>
            </div>
          )}

          {/* Role filter */}
          <div className="flex items-center gap-1.5 flex-wrap">
            <button
              onClick={() => setRoleFilter('all')}
              className={`px-2.5 py-1.5 rounded-lg text-xs font-medium transition-all ${
                roleFilter === 'all' ? 'bg-red-500/10 border border-red-500/30 text-red-400' : 'bg-secondary border border-border text-muted-foreground hover:text-foreground'
              }`}>
              <Users className="w-3 h-3 inline mr-1" />All ({validTargets.length})
            </button>
            {availableRoles.map(r => {
              const count = validTargets.filter(t => t.role === r.value).length;
              return (
                <button key={r.value} onClick={() => setRoleFilter(r.value)}
                  className={`px-2.5 py-1.5 rounded-lg text-xs font-medium transition-all ${
                    roleFilter === r.value ? 'bg-red-500/10 border border-red-500/30 text-red-400' : 'bg-secondary border border-border text-muted-foreground hover:text-foreground'
                  }`}>
                  {r.label} ({count})
                </button>
              );
            })}
          </div>

          {/* Search */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
            <input
              type="text"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search escalation targets…"
              className="w-full bg-input border border-border rounded-lg pl-9 pr-3 py-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-red-400/50"
            />
          </div>

          {/* Target list */}
          <div className="flex-1 overflow-y-auto space-y-1 min-h-0 max-h-48">
            {filteredTargets.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-6 text-muted-foreground">
                <Users className="w-6 h-6 opacity-30 mb-2" />
                <p className="text-sm">No escalation targets available</p>
              </div>
            ) : (
              filteredTargets.map(target => (
                <button
                  key={target.id}
                  onClick={() => setSelectedTarget(target.id)}
                  className={`w-full flex items-center gap-3 p-2.5 rounded-lg border transition-all text-left ${
                    selectedTarget === target.id
                      ? 'bg-red-500/5 border-red-500/20 shadow-sm'
                      : 'border-transparent hover:bg-secondary/80 hover:border-border'
                  }`}>
                  <div className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold shrink-0 ${
                    selectedTarget === target.id ? 'bg-red-500 text-white' : 'bg-secondary border border-border text-muted-foreground'
                  }`}>
                    {(target.displayName ?? target.username).charAt(0).toUpperCase()}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium text-foreground truncate">{target.displayName ?? target.username}</div>
                    <span className={`text-[10px] px-1.5 py-0.5 rounded border ${ROLE_COLORS[target.role]}`}>
                      {ROLE_LABELS[target.role] ?? target.role}
                    </span>
                  </div>
                  {selectedTarget === target.id && (
                    <div className="w-4 h-4 rounded-full bg-red-500 flex items-center justify-center shrink-0">
                      <div className="w-2 h-2 rounded-full bg-white" />
                    </div>
                  )}
                </button>
              ))
            )}
          </div>

          {/* Mandatory reason */}
          <div>
            <label className="flex items-center gap-1.5 text-sm font-medium text-foreground mb-2">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
              Escalation Reason <span className="text-destructive">*</span>
            </label>
            <textarea
              value={reason}
              onChange={e => setReason(e.target.value)}
              placeholder="Describe why this alert needs to be escalated (min 10 characters)…"
              className="w-full bg-input border border-border rounded-lg p-3 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-red-400/50 h-24 resize-none"
              maxLength={500}
              disabled={isPending}
            />
            <div className="flex justify-between text-xs text-muted-foreground mt-1">
              <span>{reason.trim().length < 10 ? `${10 - reason.trim().length} more characters needed` : '\u00A0'}</span>
              <span>{reason.length}/500</span>
            </div>
          </div>
        </div>

        <DialogFooter className="flex gap-2 sm:gap-2">
          <button onClick={() => handleOpenChange(false)} disabled={isPending}
            className="flex-1 px-4 py-2.5 bg-secondary border border-border rounded-lg text-sm hover:bg-secondary/80 transition-colors">
            Cancel
          </button>
          <button onClick={handleConfirm} disabled={!canConfirm || isPending}
            className="flex-1 px-4 py-2.5 bg-red-600 hover:bg-red-700 text-white rounded-lg text-sm font-medium transition-colors flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed">
            {isPending && <Loader2 className="w-4 h-4 animate-spin" />}
            <TrendingUp className="w-4 h-4" />
            Escalate
          </button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
