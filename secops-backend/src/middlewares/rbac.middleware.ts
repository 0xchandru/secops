import type { Request, Response, NextFunction } from "express";
import type { UserRole } from "../db";

export type Permission =
  | "alerts:view"
  | "alerts:triage"        // change own-accessible status (new→investigating)
  | "alerts:assign"        // assign to another analyst
  | "alerts:close"         // resolve / false_positive / escalate
  | "alerts:note"          // add timeline notes
  | "rules:view"
  | "rules:toggle"         // enable / disable rule
  | "rules:write"          // create / update rule
  | "rules:delete"
  | "rules:test"
  | "ingest:write"
  | "ingest:pending"
  | "users:manage"
  | "audit:view"
  | "reports:view";

const ROLE_PERMISSIONS: Record<UserRole, Permission[]> = {
  admin: [
    "alerts:view", "alerts:triage", "alerts:assign", "alerts:close", "alerts:note",
    "rules:view", "rules:toggle", "rules:write", "rules:delete", "rules:test",
    "ingest:write", "ingest:pending",
    "users:manage",
    "audit:view",
    "reports:view",
  ],
  soc_manager: [
    "alerts:view", "alerts:triage", "alerts:assign", "alerts:close", "alerts:note",
    "rules:view",
    "ingest:write", "ingest:pending",
    "audit:view",
    "reports:view",
  ],
  detection_engineer: [
    "alerts:view", "alerts:note",
    "rules:view", "rules:toggle", "rules:write", "rules:delete", "rules:test",
    "ingest:write", "ingest:pending",
    "reports:view",
  ],
  soc_l2: [
    "alerts:view", "alerts:triage", "alerts:assign", "alerts:close", "alerts:note",
    "rules:view", "rules:toggle", "rules:write", "rules:test",
    "ingest:write", "ingest:pending",
    "reports:view",
  ],
  soc_l1: [
    "alerts:view", "alerts:triage", "alerts:note",
    "rules:view",
    "reports:view",
  ],
  viewer: [
    "alerts:view",
    "rules:view",
    "reports:view",
  ],
};

export function can(permission: Permission) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const user = req.user;
    if (!user) {
      res.status(401).json({ error: "Authentication required" });
      return;
    }
    const perms = ROLE_PERMISSIONS[user.role] ?? [];
    if (!perms.includes(permission)) {
      res.status(403).json({
        error: "Insufficient permissions",
        required: permission,
        role: user.role,
      });
      return;
    }
    next();
  };
}

/**
 * Permission check that accepts either:
 *  - A JWT-authenticated user whose role grants the permission (via ROLE_PERMISSIONS), OR
 *  - An API-key-authenticated caller whose key includes the matching scope string.
 *
 * Use with requireAuthOrApiKey for endpoints that forwarders (API keys) need to reach.
 */
export function canOrApiKeyScope(permission: Permission) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const user = req.user;
    if (!user) {
      res.status(401).json({ error: "Authentication required" });
      return;
    }
    // API key path: check key scopes directly
    if ((req.apiKeyScopes?.length ?? 0) > 0) {
      const scopes: string[] = req.apiKeyScopes ?? [];
      if (scopes.includes(permission)) {
        next();
        return;
      }
      res.status(403).json({
        error: "Insufficient permissions",
        required: permission,
        hint: `API key must include the '${permission}' scope`,
      });
      return;
    }
    // JWT path: check role-based permissions
    const perms = ROLE_PERMISSIONS[user.role] ?? [];
    if (!perms.includes(permission)) {
      res.status(403).json({
        error: "Insufficient permissions",
        required: permission,
        role: user.role,
      });
      return;
    }
    next();
  };
}

export function requireRole(...roles: UserRole[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const user = req.user;
    if (!user) {
      res.status(401).json({ error: "Authentication required" });
      return;
    }
    if (!roles.includes(user.role)) {
      res.status(403).json({ error: "Insufficient permissions", required: roles, current: user.role });
      return;
    }
    next();
  };
}

export function requireMinRole(minRole: UserRole) {
  const HIERARCHY: Record<UserRole, number> = {
    admin: 6, soc_manager: 5, detection_engineer: 4, soc_l2: 3, soc_l1: 2, viewer: 1,
  };
  return (req: Request, res: Response, next: NextFunction): void => {
    const user = req.user;
    if (!user) {
      res.status(401).json({ error: "Authentication required" });
      return;
    }
    if ((HIERARCHY[user.role] ?? 0) < (HIERARCHY[minRole] ?? 0)) {
      res.status(403).json({ error: "Insufficient permissions" });
      return;
    }
    next();
  };
}
