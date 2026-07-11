import { db, alertsTable, alertTimelineTable, usersTable, rawLogsTable } from "../../db";
import { alertStateTransitionsTable, escalationHistoryTable } from "../../db/schema/alert-state-transitions";
import { eq, desc, and, or, ilike, sql, inArray, gte, lte } from "drizzle-orm";
import { notifyUser } from "../../lib/notifications";
import { alertStateMachine, type AlertStatus, type AlertAction } from "../../lib/alert-state-machine";
import { permissionEngine, type UserContext } from "../../lib/permission-engine";
import { auditService } from "../../lib/audit";
import { notifyAlertStatusChanged, notifyAlertAssigned } from "../../lib/notification-service";
import type { Request } from "express";

let alertCounter = 1000;

function generateAlertCode(): string {
  return `ALT-${Date.now()}-${++alertCounter}`;
}

const RANGE_MS: Record<string, number> = {
  "1h":  3_600_000,
  "6h":  21_600_000,
  "24h": 86_400_000,
  "7d":  604_800_000,
  "30d": 2_592_000_000,
};

export async function getAlerts(filters: {
  status?: string;
  severity?: string;
  search?: string;
  page?: number;
  limit?: number;
  from?: string;
} = {}) {
  const { page = 1, limit = 50 } = filters;
  const offset = (page - 1) * limit;

  const conditions: any[] = [];
  if (filters.status) conditions.push(eq(alertsTable.status, filters.status as any));
  if (filters.severity) conditions.push(eq(alertsTable.severity, filters.severity as any));
  if (filters.search) {
    conditions.push(
      sql`(${alertsTable.title} ilike ${"%" + filters.search + "%"} OR ${alertsTable.description} ilike ${"%" + filters.search + "%"} OR ${alertsTable.hostname} ilike ${"%" + filters.search + "%"})`
    );
  }
  if (filters.from && RANGE_MS[filters.from]) {
    const rangeStart = new Date(Date.now() - RANGE_MS[filters.from]);
    conditions.push(gte(alertsTable.createdAt, rangeStart));
  }

  const where = conditions.length > 0 ? and(...conditions) : undefined;

  const [alerts, [{ count }]] = await Promise.all([
    db.select({
      id: alertsTable.id,
      alertCode: alertsTable.alertCode,
      title: alertsTable.title,
      description: alertsTable.description,
      severity: alertsTable.severity,
      severityScore: alertsTable.severityScore,
      status: alertsTable.status,
      source: alertsTable.source,
      ruleId: alertsTable.ruleId,
      ruleName: alertsTable.ruleName,
      mitreIds: alertsTable.mitreIds,
      mitreTactic: alertsTable.mitreTactic,
      mitreTechniqueId: alertsTable.mitreTechniqueId,
      mitreTechniqueName: alertsTable.mitreTechniqueName,
      mitreSubtechniqueId: alertsTable.mitreSubtechniqueId,
      sourceIp: alertsTable.sourceIp,
      destIp: alertsTable.destIp,
      hostname: alertsTable.hostname,
      sourceHost: alertsTable.sourceHost,
      triggerTimestamp: alertsTable.triggerTimestamp,
      context: alertsTable.context,
      tags: alertsTable.tags,
      assignedTo: alertsTable.assignedTo,
      resolvedAt: alertsTable.resolvedAt,
      resolutionNotes: alertsTable.resolutionNotes,
      createdAt: alertsTable.createdAt,
      updatedAt: alertsTable.updatedAt,
    })
    .from(alertsTable)
    .where(where)
    .orderBy(desc(alertsTable.severityScore), desc(alertsTable.createdAt))
    .limit(limit)
    .offset(offset),
    db.select({ count: sql<number>`count(*)` }).from(alertsTable).where(where),
  ]);

  return { alerts, total: Number(count), page, limit };
}

export async function getAlertById(id: string) {
  const [alert] = await db.select().from(alertsTable).where(eq(alertsTable.id, id)).limit(1);
  if (!alert) return null;

  const timeline = await db
    .select()
    .from(alertTimelineTable)
    .where(eq(alertTimelineTable.alertId, id))
    .orderBy(alertTimelineTable.createdAt);

  return { ...alert, timeline };
}

/**
 * Get available actions for a specific alert and user context.
 * Used by the frontend to render action buttons.
 */
export function getAvailableActions(alert: { status: string; assignedTo: string | null }, userCtx: UserContext): AlertAction[] {
  return alertStateMachine.getAvailableActions(
    { status: alert.status as AlertStatus, assignedTo: alert.assignedTo },
    userCtx,
  );
}

export async function createAlert(data: {
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  source?: string;
  description?: string;
  ruleId?: string;
  ruleName?: string;
  mitreIds?: string[];
  mitreTactic?: string;
  sourceIp?: string;
  destIp?: string;
  hostname?: string;
  rawLog?: unknown;
  createdBy?: string;
}) {
  const [alert] = await db.insert(alertsTable).values({
    alertCode: generateAlertCode(),
    ...data,
    rawLog: data.rawLog as any,
    status: "new",
  }).returning();
  return alert;
}

// ─── Unified Alert Action Handler ────────────────────────────────────────────

export interface ActionResult {
  success: boolean;
  alert?: any;
  error?: string;
  isOverride?: boolean;
}

/**
 * Unified action handler — validates via AlertStateMachine, applies the
 * action, records the state transition, and writes an audit log.
 */
export async function executeAlertAction(
  req: Request,
  alertId: string,
  action: AlertAction,
  userCtx: UserContext,
  params: {
    reason?: string;
    escalateTo?: string;
    assignTo?: string;
    resolutionNotes?: string;
    noteContent?: string;
  } = {},
): Promise<ActionResult> {
  // 1. Load current alert
  const [existing] = await db.select().from(alertsTable).where(eq(alertsTable.id, alertId)).limit(1);
  if (!existing) return { success: false, error: "Alert not found" };

  const alertCtx = { status: existing.status as AlertStatus, assignedTo: existing.assignedTo };

  // 2. Validate transition via state machine
  const result = alertStateMachine.validateTransition(action, alertCtx, userCtx);
  if (!result.allowed) {
    return { success: false, error: result.reason };
  }

  // 3. If override, verify actor has higher priority than current assignee
  let isOverride = result.isOverride;
  if (isOverride && existing.assignedTo) {
    const targetCtx = await permissionEngine.resolveUserContext(existing.assignedTo);
    if (targetCtx && !permissionEngine.canOverride(userCtx.effectivePriority, targetCtx.effectivePriority)) {
      return { success: false, error: "Insufficient priority to override the current assignee" };
    }
  }

  const now = new Date();
  const previousState = { status: existing.status, assignedTo: existing.assignedTo };

  // 4. Execute the action
  let updatedAlert: any;
  switch (action) {
    case "investigate":
      updatedAlert = await doInvestigate(alertId, userCtx, now);
      break;
    case "escalate":
      if (!params.escalateTo || !params.reason) {
        return { success: false, error: "escalateTo and reason are required for escalation" };
      }
      updatedAlert = await doEscalate(alertId, userCtx, params.escalateTo, params.reason, now);
      break;
    case "resolve":
      updatedAlert = await doClose(alertId, "resolved", userCtx, params.resolutionNotes, now);
      break;
    case "false_positive":
      updatedAlert = await doClose(alertId, "false_positive", userCtx, params.resolutionNotes, now);
      break;
    case "reopen":
      updatedAlert = await doReopen(alertId, userCtx, now);
      break;
    case "assign":
      if (!params.assignTo) return { success: false, error: "assignTo is required" };
      updatedAlert = await doAssign(alertId, params.assignTo, userCtx, now);
      break;
    case "unassign":
      updatedAlert = await doClearAssignment(alertId, userCtx, now);
      break;
    case "add_note":
      if (!params.noteContent) return { success: false, error: "noteContent is required" };
      await addTimelineNote(alertId, userCtx.userId, userCtx.displayName ?? userCtx.username, params.noteContent);
      return { success: true, alert: existing };
  }

  if (!updatedAlert) {
    return { success: false, error: "Failed to execute action" };
  }

  // Fire-and-forget external notifications (email / Slack) — must not block the response
  setImmediate(async () => {
    try {
      if (action === "escalate" || action === "resolve") {
        await notifyAlertStatusChanged({
          id: updatedAlert.id,
          alertCode: updatedAlert.alertCode ?? null,
          title: updatedAlert.title,
          severity: updatedAlert.severity,
          status: updatedAlert.status,
          previousStatus: existing.status,
          actor: userCtx.displayName ?? userCtx.username,
        });
      }
      if (action === "assign" && params.assignTo) {
        const [assignee] = await db
          .select({ email: usersTable.email, displayName: usersTable.displayName, username: usersTable.username })
          .from(usersTable)
          .where(eq(usersTable.id, params.assignTo))
          .limit(1);
        if (assignee?.email) {
          await notifyAlertAssigned({
            alertId: updatedAlert.id,
            alertCode: updatedAlert.alertCode ?? null,
            title: updatedAlert.title,
            severity: updatedAlert.severity,
            assigneeEmail: assignee.email,
            assigneeName: assignee.displayName || assignee.username || params.assignTo,
          });
        }
      }
    } catch { /* non-fatal */ }
  });

  // 5. Record state transition (for status-changing actions)
  if (result.toStatus) {
    await db.insert(alertStateTransitionsTable).values({
      alertId,
      fromStatus: existing.status as AlertStatus,
      toStatus: result.toStatus,
      performedBy: userCtx.userId,
      performerPriority: userCtx.effectivePriority,
      isOverride,
      reason: params.reason ?? null,
      metadata: { action } as any,
    });
  }

  const AUDIT_ACTION_MAP = {
    investigate: "alert_investigated",
    assign: "alert_assigned",
    unassign: "alert_unassigned",
    escalate: "alert_escalated",
    resolve: "alert_resolved",
    reopen: "alert_reopened",
    false_positive: "alert_false_positive",
    add_note: "alert_note_added",
  } as const;

  // 6. Audit log
  const newState = { status: updatedAlert.status, assignedTo: updatedAlert.assignedTo };
  if (isOverride) {
    const targetCtx = existing.assignedTo
      ? await permissionEngine.resolveUserContext(existing.assignedTo)
      : null;
    await auditService.logOverride(req, userCtx, {
      action: AUDIT_ACTION_MAP[action] as any,
      entityType: "alert",
      entityId: alertId,
      previousState,
      newState,
      targetPriority: targetCtx?.effectivePriority ?? 100,
      metadata: { alertCode: existing.alertCode, ...params },
    });
  } else {
    await auditService.log(req, userCtx, {
      action: AUDIT_ACTION_MAP[action] as any,
      entityType: "alert",
      entityId: alertId,
      previousState,
      newState,
      metadata: { alertCode: existing.alertCode, ...params },
    });
  }

  return { success: true, alert: updatedAlert, isOverride };
}

// ─── Internal action implementations ─────────────────────────────────────────

async function doInvestigate(alertId: string, userCtx: UserContext, now: Date) {
  const claimableStatuses = ["new", "escalated", "resolved", "false_positive"];
  const result = await db.update(alertsTable)
    .set({
      status: "investigating" as any,
      assignedTo: userCtx.userId,
      investigationStartedAt: now,
      updatedBy: userCtx.userId,
      updatedAt: now,
    })
    .where(and(eq(alertsTable.id, alertId), inArray(alertsTable.status, claimableStatuses as any)))
    .returning();

  const alert = result[0];
  if (alert) {
    const userName = userCtx.displayName ?? userCtx.username;
    await db.insert(alertTimelineTable).values({
      alertId,
      authorId: userCtx.userId,
      authorName: userName,
      type: "status_change",
      content: `Investigation started by ${userName}`,
      metadata: { status: "investigating", investigator: userName, investigationStartedAt: now.toISOString() } as any,
    });
  }
  return alert ?? null;
}

async function doEscalate(alertId: string, userCtx: UserContext, escalateTo: string, reason: string, now: Date) {
  const [alert] = await db.update(alertsTable)
    .set({
      status: "escalated" as any,
      escalatedTo: escalateTo,
      escalationReason: reason,
      escalatedAt: now,
      assignedTo: escalateTo,
      updatedBy: userCtx.userId,
      updatedAt: now,
    })
    .where(eq(alertsTable.id, alertId))
    .returning();

  if (alert) {
    const [target] = await db.select({ displayName: usersTable.displayName, username: usersTable.username })
      .from(usersTable).where(eq(usersTable.id, escalateTo)).limit(1);
    const targetName = target?.displayName || target?.username || escalateTo;

    await db.insert(alertTimelineTable).values({
      alertId,
      authorId: userCtx.userId,
      type: "escalation",
      content: `Escalated to ${targetName}: ${reason}`,
      metadata: { escalateTo, targetName, reason } as any,
    });

    // Record escalation history
    const targetCtx = await permissionEngine.resolveUserContext(escalateTo);
    await db.insert(escalationHistoryTable).values({
      alertId,
      fromUserId: userCtx.userId,
      toUserId: escalateTo,
      fromPriority: userCtx.effectivePriority,
      toPriority: targetCtx?.effectivePriority ?? null,
      reason,
    });

    notifyUser(escalateTo, "alert_escalated", `Alert escalated to you: ${alert.title}`, {
      message: `Reason: ${reason}`,
      link: `/alerts/${alertId}`,
      metadata: { alertId, alertCode: alert.alertCode },
    });
  }

  return alert ?? null;
}

async function doClose(alertId: string, status: "resolved" | "false_positive", userCtx: UserContext, resolutionNotes?: string, now = new Date()) {
  const [alert] = await db.update(alertsTable)
    .set({
      status: status as any,
      updatedBy: userCtx.userId,
      updatedAt: now,
      resolvedAt: now,
      resolutionNotes: resolutionNotes ?? null,
    })
    .where(eq(alertsTable.id, alertId))
    .returning();

  if (alert) {
    await db.insert(alertTimelineTable).values({
      alertId,
      authorId: userCtx.userId,
      type: "status_change",
      content: `Status changed to ${status}${resolutionNotes ? `: ${resolutionNotes}` : ""}`,
      metadata: { status, resolutionNotes } as any,
    });
  }

  return alert ?? null;
}

async function doReopen(alertId: string, userCtx: UserContext, now: Date) {
  const [alert] = await db.update(alertsTable)
    .set({
      status: "new" as any,
      assignedTo: null,
      updatedBy: userCtx.userId,
      updatedAt: now,
      resolvedAt: null,
      resolutionNotes: null,
    })
    .where(eq(alertsTable.id, alertId))
    .returning();

  if (alert) {
    await db.insert(alertTimelineTable).values({
      alertId,
      authorId: userCtx.userId,
      type: "status_change",
      content: "Alert reopened",
      metadata: { status: "new" } as any,
    });
  }

  return alert ?? null;
}

async function doAssign(alertId: string, assignedTo: string, userCtx: UserContext, now: Date) {
  const [alert] = await db.update(alertsTable)
    .set({ assignedTo, updatedBy: userCtx.userId, updatedAt: now })
    .where(eq(alertsTable.id, alertId))
    .returning();

  if (alert) {
    const [assignee] = await db.select({ displayName: usersTable.displayName, username: usersTable.username })
      .from(usersTable).where(eq(usersTable.id, assignedTo)).limit(1);
    const assigneeName = assignee?.displayName || assignee?.username || assignedTo;
    await db.insert(alertTimelineTable).values({
      alertId,
      authorId: userCtx.userId,
      type: "assignment",
      content: `Alert assigned to ${assigneeName}`,
      metadata: { assignedTo, assigneeName } as any,
    });

    notifyUser(assignedTo, "alert_assigned", `Alert assigned to you: ${alert.title}`, {
      message: `You have been assigned alert ${alert.alertCode}`,
      link: `/alerts/${alertId}`,
      metadata: { alertId, alertCode: alert.alertCode },
    });
  }

  return alert ?? null;
}

async function doClearAssignment(alertId: string, userCtx: UserContext, now: Date) {
  const [alert] = await db.update(alertsTable)
    .set({ assignedTo: null, updatedBy: userCtx.userId, updatedAt: now })
    .where(eq(alertsTable.id, alertId))
    .returning();

  if (alert) {
    await db.insert(alertTimelineTable).values({
      alertId,
      authorId: userCtx.userId,
      type: "assignment",
      content: "Assignment cleared",
      metadata: { assignedTo: null } as any,
    });
  }

  return alert ?? null;
}

// ─── Legacy wrappers (backward-compatible with existing routes) ──────────────

export async function updateAlertStatus(id: string, status: string, userId: string, resolutionNotes?: string) {
  const isTerminal = status === "resolved" || status === "false_positive";
  const [alert] = await db.update(alertsTable)
    .set({
      status: status as any,
      updatedBy: userId,
      updatedAt: new Date(),
      resolvedAt: isTerminal ? new Date() : null,
      resolutionNotes: resolutionNotes ?? null,
    })
    .where(eq(alertsTable.id, id))
    .returning();

  if (alert) {
    await db.insert(alertTimelineTable).values({
      alertId: id,
      authorId: userId,
      type: "status_change",
      content: `Status changed to ${status}${resolutionNotes ? `: ${resolutionNotes}` : ""}`,
      metadata: { status, resolutionNotes } as any,
    });
  }

  return alert ?? null;
}

export async function bulkUpdateAlertStatus(
  ids: string[],
  status: string,
  userId: string,
  resolutionNotes?: string,
) {
  const updated = await db
    .update(alertsTable)
    .set({
      status: status as any,
      updatedBy: userId,
      updatedAt: new Date(),
      resolvedAt: status === "resolved" ? new Date() : null,
      resolutionNotes: resolutionNotes ?? null,
    })
    .where(inArray(alertsTable.id, ids))
    .returning({ id: alertsTable.id });

  return updated.length;
}

export async function assignAlertTo(id: string, assignedTo: string, userId: string) {
  const [alert] = await db.update(alertsTable)
    .set({ assignedTo, updatedBy: userId, updatedAt: new Date() })
    .where(eq(alertsTable.id, id))
    .returning();

  if (alert) {
    const [assignee] = await db.select({ displayName: usersTable.displayName, username: usersTable.username })
      .from(usersTable).where(eq(usersTable.id, assignedTo)).limit(1);
    const assigneeName = assignee?.displayName || assignee?.username || assignedTo;
    await db.insert(alertTimelineTable).values({
      alertId: id,
      authorId: userId,
      type: "assignment",
      content: `Alert assigned to ${assigneeName}`,
      metadata: { assignedTo, assigneeName } as any,
    });

    notifyUser(assignedTo, "alert_assigned", `Alert assigned to you: ${alert.title}`, {
      message: `You have been assigned alert ${alert.alertCode}`,
      link: `/alerts/${id}`,
      metadata: { alertId: id, alertCode: alert.alertCode },
    });
  }

  return alert ?? null;
}

export async function clearAssignment(id: string, userId: string) {
  const [alert] = await db.update(alertsTable)
    .set({ assignedTo: null, updatedBy: userId, updatedAt: new Date() })
    .where(eq(alertsTable.id, id))
    .returning();

  if (alert) {
    await db.insert(alertTimelineTable).values({
      alertId: id,
      authorId: userId,
      type: "assignment",
      content: "Assignment cleared",
      metadata: { assignedTo: null } as any,
    });
  }

  return alert ?? null;
}

export async function investigateAlert(id: string, userId: string) {
  const claimableStatuses = ["new", "escalated", "resolved", "false_positive"];
  const now = new Date();

  const result = await db.update(alertsTable)
    .set({
      status: "investigating" as any,
      assignedTo: userId,
      investigationStartedAt: now,
      updatedBy: userId,
      updatedAt: now,
    })
    .where(
      and(
        eq(alertsTable.id, id),
        inArray(alertsTable.status, claimableStatuses as any),
      )
    )
    .returning();

  const alert = result[0];
  if (!alert) {
    const [existing] = await db.select({ status: alertsTable.status, assignedTo: alertsTable.assignedTo })
      .from(alertsTable).where(eq(alertsTable.id, id)).limit(1);
    if (!existing) return { error: "not_found" as const };
    if (existing.status === "investigating") {
      return { error: "already_investigating" as const, assignedTo: existing.assignedTo };
    }
    return { error: "invalid_transition" as const, currentStatus: existing.status };
  }

  const [user] = await db.select({ displayName: usersTable.displayName, username: usersTable.username })
    .from(usersTable).where(eq(usersTable.id, userId)).limit(1);
  const userName = user?.displayName || user?.username || userId;

  await db.insert(alertTimelineTable).values({
    alertId: id,
    authorId: userId,
    authorName: userName,
    type: "status_change",
    content: `Investigation started by ${userName}`,
    metadata: { status: "investigating", previousStatus: alert.status, investigator: userName, investigationStartedAt: now.toISOString() } as any,
  });

  return { alert };
}

export async function escalateAlert(id: string, userId: string, escalateTo: string, reason: string) {
  const [alert] = await db.update(alertsTable)
    .set({
      status: "escalated" as any,
      escalatedTo: escalateTo,
      escalationReason: reason,
      escalatedAt: new Date(),
      assignedTo: escalateTo,
      updatedBy: userId,
      updatedAt: new Date(),
    })
    .where(eq(alertsTable.id, id))
    .returning();

  if (alert) {
    const [target] = await db.select({ displayName: usersTable.displayName, username: usersTable.username })
      .from(usersTable).where(eq(usersTable.id, escalateTo)).limit(1);
    const targetName = target?.displayName || target?.username || escalateTo;
    await db.insert(alertTimelineTable).values({
      alertId: id,
      authorId: userId,
      type: "escalation",
      content: `Escalated to ${targetName}: ${reason}`,
      metadata: { escalateTo, targetName, reason } as any,
    });

    notifyUser(escalateTo, "alert_escalated", `Alert escalated to you: ${alert.title}`, {
      message: `Reason: ${reason}`,
      link: `/alerts/${id}`,
      metadata: { alertId: id, alertCode: alert.alertCode },
    });
  }

  return alert ?? null;
}

export async function addTimelineNote(alertId: string, authorId: string, authorName: string, content: string, type = "note") {
  const [entry] = await db.insert(alertTimelineTable).values({
    alertId,
    authorId,
    authorName,
    type,
    content,
  }).returning();
  return entry;
}

export async function getRelatedEvents(alertId: string, minutesBefore = 10, minutesAfter = 5) {
  const [alert] = await db.select().from(alertsTable).where(eq(alertsTable.id, alertId)).limit(1);
  if (!alert) return [];

  const triggerTime = alert.triggerTimestamp ?? alert.createdAt;
  const from = new Date(triggerTime.getTime() - minutesBefore * 60_000);
  const to = new Date(triggerTime.getTime() + minutesAfter * 60_000);

  const correlationParts: ReturnType<typeof sql>[] = [];

  if (alert.triggerEventId) {
    correlationParts.push(sql`${rawLogsTable.id} = ${alert.triggerEventId}`);
  }

  const host = alert.sourceHost ?? alert.hostname;
  if (host) {
    correlationParts.push(sql`${rawLogsTable.sourceHost} = ${host}`);
    correlationParts.push(sql`${rawLogsTable.hostname} = ${host}`);
  }

  if (alert.sourceIp) {
    correlationParts.push(sql`${rawLogsTable.sourceIp} = ${alert.sourceIp}`);
  }

  if (alert.destIp) {
    correlationParts.push(sql`${rawLogsTable.destIp} = ${alert.destIp}`);
  }

  if (correlationParts.length === 0) return [];

  const correlationFilter = correlationParts.length === 1
    ? correlationParts[0]
    : sql.join(correlationParts, sql` OR `);

  const events = await db.select().from(rawLogsTable).where(
    and(
      gte(rawLogsTable.createdAt, from),
      lte(rawLogsTable.createdAt, to),
      sql`(${correlationFilter})`,
    )
  ).orderBy(rawLogsTable.createdAt).limit(100);

  return events;
}
