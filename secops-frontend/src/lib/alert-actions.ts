import type { AlertStatus } from './types';

export type AlertAction =
  | 'investigate'
  | 'escalate'
  | 'resolve'
  | 'false_positive'
  | 'reopen'
  | 'assign'
  | 'unassign'
  | 'add_note';

export interface AlertActionContext {
  status: AlertStatus;
  assignedTo?: string | null;
  currentUserId: string;
}

export interface AvailableActions {
  canInvestigate: boolean;
  canResolve: boolean;
  canFalsePositive: boolean;
  canEscalate: boolean;
  canAssign: boolean;
  canReopen: boolean;
  canAddNote: boolean;
  isOwner: boolean;
  isReadOnly: boolean;
}

/**
 * Convert a backend-provided action list into the AvailableActions shape.
 * When the backend returns the list of allowed actions for an alert+user combo,
 * this maps them to the boolean flags used by UI components.
 */
export function actionsFromBackend(actions: AlertAction[], assignedTo: string | null, currentUserId: string): AvailableActions {
  const isOwner = !!assignedTo && assignedTo === currentUserId;
  return {
    canInvestigate: actions.includes('investigate'),
    canResolve: actions.includes('resolve'),
    canFalsePositive: actions.includes('false_positive'),
    canEscalate: actions.includes('escalate'),
    canAssign: actions.includes('assign'),
    canReopen: actions.includes('reopen'),
    canAddNote: actions.includes('add_note'),
    isOwner,
    isReadOnly: actions.length === 0 || (actions.length === 1 && actions[0] === 'add_note'),
  };
}

/**
 * Centralized action availability logic for alerts.
 * @deprecated Use actionsFromBackend() with data from GET /alerts/:id/actions instead.
 * Kept as local fallback when the backend action endpoint is unreachable.
 *
 * Rules:
 * - NEW: "Start Investigation" (auto-assigns). Can also assign/escalate.
 * - INVESTIGATING + owner: Resolve, False Positive, Escalate, Add Note.
 * - INVESTIGATING + not owner: Read-only (view only).
 * - ESCALATED: Re-investigate (claims it), or assign to someone.
 * - RESOLVED / FALSE_POSITIVE: Re-open (higher roles), read-only otherwise.
 */
export function getAvailableActions(ctx: AlertActionContext): AvailableActions {
  const { status, assignedTo, currentUserId } = ctx;
  const isOwner = !!assignedTo && assignedTo === currentUserId;

  const base: AvailableActions = {
    canInvestigate: false,
    canResolve: false,
    canFalsePositive: false,
    canEscalate: false,
    canAssign: false,
    canReopen: false,
    canAddNote: false,
    isOwner,
    isReadOnly: true,
  };

  switch (status) {
    case 'new':
      return {
        ...base,
        canInvestigate: true,
        canResolve: true,
        canFalsePositive: true,
        canAssign: true,
        canEscalate: true,
        canAddNote: true,
        isReadOnly: false,
      };
    case 'investigating':
      return {
        ...base,
        canResolve: true,
        canFalsePositive: true,
        canEscalate: true,
        canAssign: true,
        canAddNote: true,
        isOwner,
        isReadOnly: false,
      };
    case 'escalated':
      return {
        ...base,
        canInvestigate: true,
        canAssign: true,
        canAddNote: true,
        isReadOnly: false,
      };
    case 'resolved':
    case 'false_positive':
      return {
        ...base,
        canReopen: true,
        canAddNote: true,
      };
    default:
      return base;
  }
}
