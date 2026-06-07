import type { UserContext } from "./permission-engine.js";

/** Valid alert statuses matching the alertStatusEnum. */
export type AlertStatus = "new" | "investigating" | "escalated" | "resolved" | "false_positive";

/** Actions that trigger state transitions. */
export type AlertAction =
  | "investigate"
  | "escalate"
  | "resolve"
  | "false_positive"
  | "reopen"
  | "assign"
  | "unassign"
  | "add_note";

interface TransitionRule {
  from: AlertStatus[];
  to: AlertStatus;
  requiredPermission: string;
  /** If true, actor must own the alert OR have override priority. */
  ownershipRequired?: boolean;
}

interface ActionDef {
  action: AlertAction;
  transition?: TransitionRule;
  /** Permission needed when the action doesn't change status (e.g. add_note). */
  requiredPermission?: string;
}

const ACTION_DEFINITIONS: ActionDef[] = [
  {
    action: "investigate",
    transition: {
      from: ["new", "escalated", "resolved", "false_positive"],
      to: "investigating",
      requiredPermission: "alerts:triage",
    },
  },
  {
    action: "escalate",
    transition: {
      from: ["new", "investigating"],
      to: "escalated",
      requiredPermission: "alerts:close",
    },
  },
  {
    action: "resolve",
    transition: {
      from: ["investigating"],
      to: "resolved",
      requiredPermission: "alerts:close",
      ownershipRequired: true,
    },
  },
  {
    action: "false_positive",
    transition: {
      from: ["investigating"],
      to: "false_positive",
      requiredPermission: "alerts:close",
      ownershipRequired: true,
    },
  },
  {
    action: "reopen",
    transition: {
      from: ["resolved", "false_positive"],
      to: "new",
      requiredPermission: "alerts:triage",
    },
  },
  {
    action: "assign",
    requiredPermission: "alerts:assign",
  },
  {
    action: "unassign",
    requiredPermission: "alerts:assign",
  },
  {
    action: "add_note",
    requiredPermission: "alerts:note",
  },
];

export interface AlertContext {
  status: AlertStatus;
  assignedTo: string | null;
}

export interface TransitionResult {
  allowed: boolean;
  toStatus?: AlertStatus;
  isOverride: boolean;
  reason?: string;
}

/**
 * AlertStateMachine — validates alert lifecycle transitions.
 *
 * Centralises the rules for which actions are available from which states,
 * enforces ownership-or-override semantics, and returns available actions
 * for a given alert + user context so the frontend can render buttons.
 */
export class AlertStateMachine {
  /**
   * Get all actions available to `user` on the given alert.
   */
  getAvailableActions(
    alert: AlertContext,
    user: UserContext,
  ): AlertAction[] {
    return ACTION_DEFINITIONS
      .filter((def) => this.isActionAllowed(def, alert, user).allowed)
      .map((def) => def.action);
  }

  /**
   * Validate whether `action` is allowed and return the target status (if any).
   */
  validateTransition(
    action: AlertAction,
    alert: AlertContext,
    user: UserContext,
  ): TransitionResult {
    const def = ACTION_DEFINITIONS.find((d) => d.action === action);
    if (!def) {
      return { allowed: false, isOverride: false, reason: `Unknown action: ${action}` };
    }
    return this.isActionAllowed(def, alert, user);
  }

  // ─── Internal ────────────────────────────────────────────────────────

  private isActionAllowed(
    def: ActionDef,
    alert: AlertContext,
    user: UserContext,
  ): TransitionResult {
    // Check permission
    const requiredPerm = def.transition?.requiredPermission ?? def.requiredPermission;
    if (requiredPerm && !user.permissions.includes(requiredPerm)) {
      return { allowed: false, isOverride: false, reason: `Missing permission: ${requiredPerm}` };
    }

    // If there's no state transition (e.g. add_note, assign), it's allowed if permission passes
    if (!def.transition) {
      return { allowed: true, isOverride: false };
    }

    const { from, to, ownershipRequired } = def.transition;

    // Check current status is valid source
    if (!from.includes(alert.status)) {
      return {
        allowed: false,
        isOverride: false,
        reason: `Cannot ${def.action} from status '${alert.status}'`,
      };
    }

    // Ownership check — owner or higher-priority override
    if (ownershipRequired && alert.assignedTo) {
      const isOwner = alert.assignedTo === user.userId;
      if (!isOwner) {
        // Priority-based override: actor must have strictly higher authority
        // We don't know target priority here — caller must verify externally
        // For now, we mark it as override and let the service layer confirm
        return { allowed: true, toStatus: to, isOverride: true };
      }
    }

    return { allowed: true, toStatus: to, isOverride: false };
  }
}

export const alertStateMachine = new AlertStateMachine();
