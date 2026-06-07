import React, { useState, useMemo } from 'react';
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter,
} from '@/components/ui/dialog';
import { ROLE_LABELS, ROLE_COLORS, ROLE_HIERARCHY, ALL_ROLES_ORDERED } from '@/lib/constants';
import {
  UserPlus, Search, ChevronRight, CheckCircle2, Loader2, Users, Shield, ArrowRight,
} from 'lucide-react';

export interface AssignDialogUser {
  id: string;
  username: string;
  displayName?: string | null;
  role: string;
  status?: string;
}

interface AssignDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  users: AssignDialogUser[];
  currentAssigneeId?: string | null;
  /** Alert title or description shown in the dialog */
  alertTitle?: string;
  isPending?: boolean;
  onAssign: (userId: string) => void;
  onClearAssignment?: () => void;
  isClearPending?: boolean;
}

export default function AssignDialog({
  open, onOpenChange, users, currentAssigneeId, alertTitle,
  isPending, onAssign, onClearAssignment, isClearPending,
}: AssignDialogProps) {
  const [roleFilter, setRoleFilter] = useState<string>('all');
  const [search, setSearch] = useState('');
  const [selectedUser, setSelectedUser] = useState<string | null>(null);
  const [step, setStep] = useState<'select' | 'confirm'>('select');

  const activeUsers = useMemo(() =>
    users.filter(u => u.status === 'active' && u.role !== 'viewer'),
    [users],
  );

  const availableRoles = useMemo(() => {
    const roles = new Set(activeUsers.map(u => u.role));
    return ALL_ROLES_ORDERED.filter(r => roles.has(r.value));
  }, [activeUsers]);

  const filteredUsers = useMemo(() => {
    let list = activeUsers;
    if (roleFilter !== 'all') list = list.filter(u => u.role === roleFilter);
    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter(u =>
        (u.displayName ?? u.username).toLowerCase().includes(q) ||
        u.username.toLowerCase().includes(q),
      );
    }
    return list.sort((a, b) => (ROLE_HIERARCHY[b.role] ?? 0) - (ROLE_HIERARCHY[a.role] ?? 0));
  }, [activeUsers, roleFilter, search]);

  const selectedUserObj = useMemo(() =>
    users.find(u => u.id === selectedUser),
    [users, selectedUser],
  );

  const currentAssignee = useMemo(() =>
    users.find(u => u.id === currentAssigneeId),
    [users, currentAssigneeId],
  );

  const handleOpenChange = (next: boolean) => {
    if (!next) { setStep('select'); setSelectedUser(null); setSearch(''); setRoleFilter('all'); }
    onOpenChange(next);
  };

  const handleSelectUser = (userId: string) => {
    setSelectedUser(userId);
    setStep('confirm');
  };

  const handleConfirm = () => {
    if (selectedUser) onAssign(selectedUser);
  };

  const handleBack = () => {
    setStep('select');
    setSelectedUser(null);
  };

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="max-w-md max-h-[85vh] flex flex-col">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <UserPlus className="w-5 h-5 text-primary" />
            {step === 'select' ? 'Assign Alert' : 'Confirm Assignment'}
          </DialogTitle>
          {alertTitle && (
            <DialogDescription className="truncate">{alertTitle}</DialogDescription>
          )}
        </DialogHeader>

        {step === 'select' && (
          <div className="flex flex-col gap-3 flex-1 overflow-hidden">
            {/* Current assignee banner */}
            {currentAssignee && (
              <div className="flex items-center justify-between p-3 bg-primary/5 border border-primary/20 rounded-lg">
                <div className="flex items-center gap-2">
                  <div className="w-7 h-7 rounded-full bg-primary flex items-center justify-center text-xs font-bold text-white">
                    {(currentAssignee.displayName ?? currentAssignee.username).charAt(0).toUpperCase()}
                  </div>
                  <div>
                    <div className="text-sm font-medium text-foreground">{currentAssignee.displayName ?? currentAssignee.username}</div>
                    <div className="text-[10px] text-muted-foreground">Currently assigned</div>
                  </div>
                </div>
                {onClearAssignment && (
                  <button
                    onClick={onClearAssignment}
                    disabled={isClearPending}
                    className="text-xs text-muted-foreground hover:text-destructive transition-colors px-2 py-1 rounded hover:bg-destructive/10">
                    {isClearPending ? <Loader2 className="w-3 h-3 animate-spin" /> : 'Unassign'}
                  </button>
                )}
              </div>
            )}

            {/* Role filter pills */}
            <div className="flex items-center gap-1.5 flex-wrap">
              <button
                onClick={() => setRoleFilter('all')}
                className={`px-2.5 py-1.5 rounded-lg text-xs font-medium transition-all ${
                  roleFilter === 'all' ? 'bg-primary/10 border border-primary/30 text-primary' : 'bg-secondary border border-border text-muted-foreground hover:text-foreground'
                }`}>
                <Users className="w-3 h-3 inline mr-1" />All ({activeUsers.length})
              </button>
              {availableRoles.map(r => {
                const count = activeUsers.filter(u => u.role === r.value).length;
                return (
                  <button key={r.value} onClick={() => setRoleFilter(r.value)}
                    className={`px-2.5 py-1.5 rounded-lg text-xs font-medium transition-all ${
                      roleFilter === r.value ? 'bg-primary/10 border border-primary/30 text-primary' : 'bg-secondary border border-border text-muted-foreground hover:text-foreground'
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
                placeholder="Search analysts…"
                className="w-full bg-input border border-border rounded-lg pl-9 pr-3 py-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>

            {/* User list */}
            <div className="flex-1 overflow-y-auto space-y-1 min-h-0 max-h-64">
              {filteredUsers.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                  <Users className="w-6 h-6 opacity-30 mb-2" />
                  <p className="text-sm">No analysts match your filters</p>
                </div>
              ) : (
                filteredUsers.map(user => (
                  <button
                    key={user.id}
                    onClick={() => handleSelectUser(user.id)}
                    disabled={isPending}
                    className={`w-full flex items-center gap-3 p-2.5 rounded-lg border transition-all text-left ${
                      currentAssigneeId === user.id
                        ? 'bg-primary/5 border-primary/20 opacity-60'
                        : 'border-transparent hover:bg-secondary/80 hover:border-border'
                    }`}>
                    <div className="w-8 h-8 rounded-full bg-secondary border border-border flex items-center justify-center text-xs font-bold text-muted-foreground shrink-0">
                      {(user.displayName ?? user.username).charAt(0).toUpperCase()}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="text-sm font-medium text-foreground truncate">
                        {user.displayName ?? user.username}
                        {currentAssigneeId === user.id && <span className="text-[10px] text-primary ml-1.5">(current)</span>}
                      </div>
                      <span className={`text-[10px] px-1.5 py-0.5 rounded border ${ROLE_COLORS[user.role]}`}>
                        {ROLE_LABELS[user.role] ?? user.role}
                      </span>
                    </div>
                    <ChevronRight className="w-4 h-4 text-muted-foreground shrink-0" />
                  </button>
                ))
              )}
            </div>
          </div>
        )}

        {step === 'confirm' && selectedUserObj && (
          <div className="space-y-4">
            <div className="bg-secondary/30 border border-border rounded-xl p-4">
              <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-3">Assignment Change</div>
              <div className="flex items-center gap-3 justify-center">
                {currentAssignee ? (
                  <div className="flex items-center gap-2">
                    <div className="w-9 h-9 rounded-full bg-secondary border border-border flex items-center justify-center text-xs font-bold text-muted-foreground">
                      {(currentAssignee.displayName ?? currentAssignee.username).charAt(0).toUpperCase()}
                    </div>
                    <div className="text-sm text-muted-foreground line-through">{currentAssignee.displayName ?? currentAssignee.username}</div>
                  </div>
                ) : (
                  <div className="text-sm text-muted-foreground italic">Unassigned</div>
                )}
                <ArrowRight className="w-4 h-4 text-primary shrink-0" />
                <div className="flex items-center gap-2">
                  <div className="w-9 h-9 rounded-full bg-primary flex items-center justify-center text-xs font-bold text-white">
                    {(selectedUserObj.displayName ?? selectedUserObj.username).charAt(0).toUpperCase()}
                  </div>
                  <div>
                    <div className="text-sm font-medium text-foreground">{selectedUserObj.displayName ?? selectedUserObj.username}</div>
                    <span className={`text-[10px] px-1.5 py-0.5 rounded border ${ROLE_COLORS[selectedUserObj.role]}`}>
                      {ROLE_LABELS[selectedUserObj.role] ?? selectedUserObj.role}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            <DialogFooter className="flex gap-2 sm:gap-2">
              <button onClick={handleBack} disabled={isPending}
                className="flex-1 px-4 py-2.5 bg-secondary border border-border rounded-lg text-sm hover:bg-secondary/80 transition-colors">
                Back
              </button>
              <button onClick={handleConfirm} disabled={isPending}
                className="flex-1 px-4 py-2.5 bg-primary text-primary-foreground rounded-lg text-sm font-medium hover:bg-primary/90 transition-colors flex items-center justify-center gap-2">
                {isPending && <Loader2 className="w-4 h-4 animate-spin" />}
                Assign
              </button>
            </DialogFooter>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
