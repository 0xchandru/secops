import type { Request, Response } from "express";
import * as alertsService from "./alerts.service";
import { logAuditEvent } from "../../lib/audit";
import type { AlertAction } from "../../lib/alert-state-machine";

// Status transition validation: which statuses can move to which
const VALID_TRANSITIONS: Record<string, string[]> = {
  new:            ["investigating", "escalated", "false_positive"],
  investigating:  ["resolved", "escalated", "false_positive", "new"],
  escalated:      ["investigating", "resolved", "false_positive"],
  resolved:       ["investigating", "new"],
  false_positive: ["investigating", "new"],
};

export async function investigate(req: Request, res: Response): Promise<void> {
  const id = req.params.id as string;
  const userId = req.user!.userId;
  const result = await alertsService.investigateAlert(id, userId);

  if ("error" in result) {
    if (result.error === "not_found") {
      res.status(404).json({ error: "Alert not found" });
      return;
    }
    if (result.error === "already_investigating") {
      res.status(409).json({ error: "Alert is already under investigation", assignedTo: result.assignedTo });
      return;
    }
    res.status(400).json({ error: "Cannot investigate this alert", currentStatus: result.currentStatus });
    return;
  }

  await logAuditEvent(req, "alerts.investigate", {
    resource: "alerts", resourceId: id,
    metadata: { status: "investigating", assignedTo: userId },
  });
  res.json({ alert: result.alert });
}

export async function listAlerts(req: Request, res: Response): Promise<void> {
  const { status, severity, search, page, limit, from } = req.query;
  const result = await alertsService.getAlerts({
    status: status as string,
    severity: severity as string,
    search: search as string,
    page: page ? Number(page) : 1,
    limit: limit ? Number(limit) : 50,
    from: from ? String(from) : undefined,
  });
  res.json(result);
}

export async function getAlert(req: Request, res: Response): Promise<void> {
  const id = req.params.id as string;
  const alert = await alertsService.getAlertById(id);
  if (!alert) { res.status(404).json({ error: "Alert not found" }); return; }
  res.json({ alert });
}

export async function updateStatus(req: Request, res: Response): Promise<void> {
  const { status, resolutionNotes } = req.body;
  const validStatuses = ["new", "investigating", "escalated", "resolved", "false_positive"];
  if (!status || !validStatuses.includes(status)) {
    res.status(400).json({ error: "Invalid status" });
    return;
  }

  const id = req.params.id as string;
  // Validate transition
  const existing = await alertsService.getAlertById(id);
  if (!existing) { res.status(404).json({ error: "Alert not found" }); return; }
  const currentStatus = existing.status;
  const allowed = VALID_TRANSITIONS[currentStatus] ?? [];
  if (!allowed.includes(status)) {
    res.status(400).json({
      error: `Invalid status transition from "${currentStatus}" to "${status}"`,
      allowedTransitions: allowed,
    });
    return;
  }

  // For "investigating" transitions, redirect to the dedicated investigate endpoint logic
  if (status === "investigating") {
    const result = await alertsService.investigateAlert(id, req.user!.userId);
    if ("error" in result) {
      if (result.error === "not_found") { res.status(404).json({ error: "Alert not found" }); return; }
      if (result.error === "already_investigating") { res.status(409).json({ error: "Alert is already under investigation", assignedTo: result.assignedTo }); return; }
      res.status(400).json({ error: "Cannot investigate this alert", currentStatus: result.currentStatus }); return;
    }
    await logAuditEvent(req, "alerts.investigate", { resource: "alerts", resourceId: id, metadata: { status: "investigating", assignedTo: req.user!.userId } });
    res.json({ alert: result.alert }); return;
  }

  let alert;
  try {
    alert = await alertsService.updateAlertStatus(id, status, req.user!.userId, resolutionNotes);
  } catch (err: any) {
    res.status(403).json({ error: err.message });
    return;
  }
  if (!alert) { res.status(404).json({ error: "Alert not found" }); return; }
  await logAuditEvent(req, "alerts.status_update", { resource: "alerts", resourceId: id, metadata: { status, previousStatus: currentStatus } });
  res.json({ alert });
}

export async function assignAlert(req: Request, res: Response): Promise<void> {
  const id = req.params.id as string;
  const { assignedTo } = req.body;
  if (!assignedTo) { res.status(400).json({ error: "assignedTo is required" }); return; }
  const alert = await alertsService.assignAlertTo(id, assignedTo, req.user!.userId);
  if (!alert) { res.status(404).json({ error: "Alert not found" }); return; }
  await logAuditEvent(req, "alerts.assign", { resource: "alerts", resourceId: id, metadata: { assignedTo } });
  res.json({ alert });
}

export async function clearAssignment(req: Request, res: Response): Promise<void> {
  const id = req.params.id as string;
  const alert = await alertsService.clearAssignment(id, req.user!.userId);
  if (!alert) { res.status(404).json({ error: "Alert not found" }); return; }
  await logAuditEvent(req, "alerts.clear_assign", { resource: "alerts", resourceId: id });
  res.json({ alert });
}

export async function escalateAlert(req: Request, res: Response): Promise<void> {
  const { escalateTo, reason } = req.body;
  if (!escalateTo || !reason) {
    res.status(400).json({ error: "escalateTo and reason are required" });
    return;
  }
  if (reason.length < 10) {
    res.status(400).json({ error: "Escalation reason must be at least 10 characters" });
    return;
  }
  const id = req.params.id as string;
  const alert = await alertsService.escalateAlert(id, req.user!.userId, escalateTo, reason);
  if (!alert) { res.status(404).json({ error: "Alert not found" }); return; }
  await logAuditEvent(req, "alerts.escalate", { resource: "alerts", resourceId: id, metadata: { escalateTo, reason } });
  res.json({ alert });
}

export async function addNote(req: Request, res: Response): Promise<void> {
  const { content, type } = req.body;
  if (!content) { res.status(400).json({ error: "content is required" }); return; }
  const id = req.params.id as string;
  const entry = await alertsService.addTimelineNote(
    id,
    req.user!.userId,
    req.user!.displayName ?? req.user!.username,
    content,
    type ?? "note"
  );
  await logAuditEvent(req, "alerts.add_note", { resource: "alerts", resourceId: id });
  res.status(201).json({ entry });
}

export async function bulkUpdate(req: Request, res: Response): Promise<void> {
  const { ids, status, resolutionNotes } = req.body;
  if (!Array.isArray(ids) || ids.length === 0) {
    res.status(400).json({ error: "ids must be a non-empty array" });
    return;
  }
  const validStatuses = ["new", "investigating", "escalated", "resolved", "false_positive"];
  if (!status || !validStatuses.includes(status)) {
    res.status(400).json({ error: "Invalid status" });
    return;
  }
  const count = await alertsService.bulkUpdateAlertStatus(ids, status, req.user!.userId, resolutionNotes);
  await logAuditEvent(req, "alerts.bulk_update", { resource: "alerts", metadata: { ids, status, count } });
  res.json({ updated: count });
}

export async function getRelatedEvents(req: Request, res: Response): Promise<void> {
  const minutesBefore = Number(req.query.minutesBefore ?? 10);
  const minutesAfter = Number(req.query.minutesAfter ?? 5);
  const events = await alertsService.getRelatedEvents(req.params.id as string, minutesBefore, minutesAfter);
  res.json({ events, total: events.length });
}

// ─── Unified Action Endpoint ─────────────────────────────────────────────────

const VALID_ACTIONS: AlertAction[] = [
  "investigate", "escalate", "resolve", "false_positive",
  "reopen", "assign", "unassign", "add_note",
];

export async function getActions(req: Request, res: Response): Promise<void> {
  const id = req.params.id as string;
  const alert = await alertsService.getAlertById(id);
  if (!alert) { res.status(404).json({ error: "Alert not found" }); return; }

  const userCtx = req.userContext!;
  const actions = alertsService.getAvailableActions(
    { status: alert.status, assignedTo: alert.assignedTo },
    userCtx,
  );
  res.json({ actions, alertId: id, status: alert.status });
}

export async function executeAction(req: Request, res: Response): Promise<void> {
  const { id, action } = req.params as { id: string; action: string };

  if (!VALID_ACTIONS.includes(action as AlertAction)) {
    res.status(400).json({ error: `Invalid action: ${action}`, validActions: VALID_ACTIONS });
    return;
  }

  const userCtx = req.userContext!;
  const payload = req.body ?? {};

  try {
    const result = await alertsService.executeAlertAction(
      req,
      id,
      action as AlertAction,
      userCtx,
      payload,
    );
    res.json(result);
  } catch (err: any) {
    const status = err.message?.includes("not found") ? 404
      : err.message?.includes("not allowed") || err.message?.includes("override") ? 403
      : 400;
    res.status(status).json({ error: err.message });
  }
}
