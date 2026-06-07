import type { Request, Response, NextFunction } from "express";

/**
 * Permission-gate middleware — checks req.userContext.permissions
 * against the required permission code.
 *
 * Must be used AFTER requireAuthWithContext so that req.userContext is populated.
 */
export function requirePermission(permission: string) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const ctx = req.userContext;
    if (!ctx) {
      res.status(401).json({ error: "Authentication required" });
      return;
    }
    if (!ctx.permissions.includes(permission)) {
      res.status(403).json({
        error: "Insufficient permissions",
        required: permission,
        roles: ctx.roles,
      });
      return;
    }
    next();
  };
}

/**
 * Requires ALL listed permissions.
 */
export function requireAllPermissions(...permissions: string[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const ctx = req.userContext;
    if (!ctx) {
      res.status(401).json({ error: "Authentication required" });
      return;
    }
    const missing = permissions.filter((p) => !ctx.permissions.includes(p));
    if (missing.length > 0) {
      res.status(403).json({
        error: "Insufficient permissions",
        required: permissions,
        missing,
        roles: ctx.roles,
      });
      return;
    }
    next();
  };
}

/**
 * Requires at least one of the listed permissions.
 */
export function requireAnyPermission(...permissions: string[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const ctx = req.userContext;
    if (!ctx) {
      res.status(401).json({ error: "Authentication required" });
      return;
    }
    if (!permissions.some((p) => ctx.permissions.includes(p))) {
      res.status(403).json({
        error: "Insufficient permissions",
        requiredAny: permissions,
        roles: ctx.roles,
      });
      return;
    }
    next();
  };
}

/**
 * Requires the user to have at most the given priority value.
 * Lower number = higher authority (admin=0, viewer=100).
 */
export function requireMinPriority(maxPriorityValue: number) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const ctx = req.userContext;
    if (!ctx) {
      res.status(401).json({ error: "Authentication required" });
      return;
    }
    if (ctx.effectivePriority > maxPriorityValue) {
      res.status(403).json({
        error: "Insufficient priority level",
        required: maxPriorityValue,
        current: ctx.effectivePriority,
      });
      return;
    }
    next();
  };
}
