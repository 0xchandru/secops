import { db, auditLogsTable } from "../db";
import type { Request } from "express";
import type { JwtPayload } from "./jwt";
import type { AuditAction } from "../db/schema/audit-logs";
import type { UserContext } from "./permission-engine";
import { logger } from "./logger";

// ─── Legacy helper (backward-compatible) ─────────────────────────────────────

export async function logAuditEvent(
  req: Request,
  action: string,
  opts: {
    resource?: string;
    resourceId?: string;
    metadata?: Record<string, unknown>;
    success?: boolean;
    userId?: string | null;
    username?: string;
  } = {}
): Promise<void> {
  const user = (req as any).user as JwtPayload | undefined;
  try {
    await db.insert(auditLogsTable).values({
      userId: opts.userId !== undefined ? opts.userId : (user?.userId ?? null),
      username: opts.username ?? user?.username ?? "anonymous",
      action: action as AuditAction,
      resource: opts.resource ?? null,
      resourceId: opts.resourceId ?? null,
      metadata: opts.metadata ?? null,
      ipAddress: req.ip ?? null,
      userAgent: req.get("user-agent") ?? null,
      success: String(opts.success ?? true),
    });
  } catch {
  }
}

// ─── Enhanced AuditService ───────────────────────────────────────────────────

interface AuditEventOpts {
  action: AuditAction;
  entityType: string;
  entityId: string;
  previousState?: Record<string, unknown> | null;
  newState?: Record<string, unknown> | null;
  metadata?: Record<string, unknown>;
  success?: boolean;
}

/**
 * AuditService — enhanced audit logging with state diff tracking.
 *
 * Captures previous/new state, auto-computes a shallow diff,
 * records performer priority and override flag.
 */
export class AuditService {
  /**
   * Log an audit event with full state tracking.
   */
  async log(
    req: Request,
    userCtx: UserContext | null,
    opts: AuditEventOpts,
  ): Promise<void> {
    const diff = opts.previousState && opts.newState
      ? this.computeDiff(opts.previousState, opts.newState)
      : null;

    try {
      await db.insert(auditLogsTable).values({
        userId: userCtx?.userId ?? null,
        username: userCtx?.username ?? "system",
        action: opts.action,
        entityType: opts.entityType,
        entityId: opts.entityId,
        previousState: opts.previousState ?? null,
        newState: opts.newState ?? null,
        diff,
        performerPriority: userCtx?.effectivePriority ?? null,
        isOverride: false,
        metadata: opts.metadata ?? null,
        ipAddress: req.ip ?? null,
        userAgent: req.get("user-agent") ?? null,
        success: String(opts.success ?? true),
      });
    } catch (err) {
      logger.error({ err, action: opts.action }, "AuditService: failed to write audit log");
    }
  }

  /**
   * Log an audit event for a priority-based override.
   */
  async logOverride(
    req: Request,
    userCtx: UserContext,
    opts: AuditEventOpts & { targetPriority: number },
  ): Promise<void> {
    const diff = opts.previousState && opts.newState
      ? this.computeDiff(opts.previousState, opts.newState)
      : null;

    try {
      await db.insert(auditLogsTable).values({
        userId: userCtx.userId,
        username: userCtx.username,
        action: opts.action,
        entityType: opts.entityType,
        entityId: opts.entityId,
        previousState: opts.previousState ?? null,
        newState: opts.newState ?? null,
        diff,
        performerPriority: userCtx.effectivePriority,
        isOverride: true,
        metadata: {
          ...opts.metadata,
          targetPriority: opts.targetPriority,
        },
        ipAddress: req.ip ?? null,
        userAgent: req.get("user-agent") ?? null,
        success: String(opts.success ?? true),
      });
    } catch (err) {
      logger.error({ err, action: opts.action }, "AuditService: failed to write override audit log");
    }
  }

  /**
   * Compute a shallow diff between two state objects.
   * Returns only fields that changed, with { from, to } values.
   */
  private computeDiff(
    prev: Record<string, unknown>,
    next: Record<string, unknown>,
  ): Record<string, { from: unknown; to: unknown }> {
    const diff: Record<string, { from: unknown; to: unknown }> = {};
    const allKeys = new Set([...Object.keys(prev), ...Object.keys(next)]);

    for (const key of allKeys) {
      const a = prev[key];
      const b = next[key];
      if (JSON.stringify(a) !== JSON.stringify(b)) {
        diff[key] = { from: a, to: b };
      }
    }

    return diff;
  }
}

export const auditService = new AuditService();
