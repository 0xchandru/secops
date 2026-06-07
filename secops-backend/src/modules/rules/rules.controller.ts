import type { Request, Response } from "express";
import * as rulesService from "./rules.service";
import { logAuditEvent } from "../../lib/audit";
import { invalidateEngine } from "../../lib/detection/pipeline";
import { detectionEngine } from "../../lib/detection/engine";
import { db, alertsTable } from "../../db";
import { eq, sql, gte, and } from "drizzle-orm";

export async function listRules(req: Request, res: Response): Promise<void> {
  const rules = await rulesService.getRules();
  res.json({ rules });
}

export async function getRule(req: Request, res: Response): Promise<void> {
  const id = req.params.id as string;
  const rule = await rulesService.getRuleById(id);
  if (!rule) { res.status(404).json({ error: "Rule not found" }); return; }
  res.json({ rule });
}

export async function createRule(req: Request, res: Response): Promise<void> {
  const { name, description, severity, yamlContent, logSource, mitreIds, mitreTactic, tags } = req.body;
  if (!name || !severity) {
    res.status(400).json({ error: "name and severity are required" });
    return;
  }
  const rule = await rulesService.createRule({
    name, description, severity, yamlContent, logSource, mitreIds, mitreTactic, tags,
    createdBy: req.user!.userId,
  });
  invalidateEngine();
  await logAuditEvent(req, "rules.create", { resource: "rules", resourceId: rule.id, metadata: { name } });
  res.status(201).json({ rule });
}

export async function updateRule(req: Request, res: Response): Promise<void> {
  const { name, description, severity, yamlContent, mitreIds } = req.body;
  const id = req.params.id as string;
  const rule = await rulesService.updateRule(id, {
    name, description, severity, yamlContent, mitreIds, updatedBy: req.user!.userId,
  });
  if (!rule) { res.status(404).json({ error: "Rule not found" }); return; }
  invalidateEngine();
  await logAuditEvent(req, "rules.update", { resource: "rules", resourceId: id });
  res.json({ rule });
}

export async function deleteRule(req: Request, res: Response): Promise<void> {
  const id = req.params.id as string;
  await rulesService.deleteRule(id);
  invalidateEngine();
  await logAuditEvent(req, "rules.delete", { resource: "rules", resourceId: id });
  res.json({ message: "Rule deleted" });
}

export async function toggleRule(req: Request, res: Response): Promise<void> {
  const { enabled } = req.body;
  if (typeof enabled !== "boolean") {
    res.status(400).json({ error: "enabled (boolean) is required" });
    return;
  }
  const id = req.params.id as string;
  const rule = await rulesService.toggleRule(id, enabled, req.user!.userId);
  if (!rule) { res.status(404).json({ error: "Rule not found" }); return; }
  invalidateEngine();
  await logAuditEvent(req, enabled ? "rules.enable" : "rules.disable", { resource: "rules", resourceId: id });
  res.json({ rule });
}

export async function testRule(req: Request, res: Response): Promise<void> {
  const { yamlContent, events } = req.body;
  if (!yamlContent || !Array.isArray(events)) {
    res.status(400).json({ error: "yamlContent (string) and events (array) are required" });
    return;
  }

  const testEvents = events.map((e: any) => ({
    ...e,
    timestamp: e.timestamp ? new Date(e.timestamp) : new Date(),
  }));

  const results = detectionEngine.testRule(yamlContent, testEvents);
  res.json({ matches: results.length, alerts: results });
}

export async function getRuleStats(req: Request, res: Response): Promise<void> {
  const ruleId = req.params.id as string;
  const rule = await rulesService.getRuleById(ruleId);
  if (!rule) { res.status(404).json({ error: "Rule not found" }); return; }

  const now = new Date();
  const last24h = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  const last7d = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

  const [
    totalAlerts,
    alertsLast24h,
    alertsLast7d,
    alertsBySeverity,
    recentAlerts,
    hourlyTrend,
  ] = await Promise.all([
    db.select({ count: sql<number>`count(*)` }).from(alertsTable)
      .where(eq(alertsTable.ruleId, ruleId)),
    db.select({ count: sql<number>`count(*)` }).from(alertsTable)
      .where(and(eq(alertsTable.ruleId, ruleId), gte(alertsTable.createdAt, last24h))),
    db.select({ count: sql<number>`count(*)` }).from(alertsTable)
      .where(and(eq(alertsTable.ruleId, ruleId), gte(alertsTable.createdAt, last7d))),
    db.select({ severity: alertsTable.severity, count: sql<number>`count(*)` }).from(alertsTable)
      .where(eq(alertsTable.ruleId, ruleId))
      .groupBy(alertsTable.severity),
    db.select({
      id: alertsTable.id,
      alertCode: alertsTable.alertCode,
      title: alertsTable.title,
      severity: alertsTable.severity,
      status: alertsTable.status,
      createdAt: alertsTable.createdAt,
    }).from(alertsTable)
      .where(eq(alertsTable.ruleId, ruleId))
      .orderBy(sql`created_at DESC`)
      .limit(10),
    db.select({
      hour: sql<string>`to_char(date_trunc('hour', created_at), 'HH24:00')`,
      count: sql<number>`count(*)`,
    }).from(alertsTable)
      .where(and(eq(alertsTable.ruleId, ruleId), gte(alertsTable.createdAt, last24h)))
      .groupBy(sql`date_trunc('hour', created_at)`)
      .orderBy(sql`date_trunc('hour', created_at)`),
  ]);

  const sevMap: Record<string, number> = {};
  alertsBySeverity.forEach((r) => { sevMap[r.severity] = Number(r.count); });

  res.json({
    ruleId,
    ruleName: rule.name,
    triggerCount: rule.triggerCount ?? 0,
    falsePositiveRate: rule.falsePositiveRate ?? 0,
    totalAlerts: Number(totalAlerts[0]?.count ?? 0),
    alertsLast24h: Number(alertsLast24h[0]?.count ?? 0),
    alertsLast7d: Number(alertsLast7d[0]?.count ?? 0),
    alertsBySeverity: sevMap,
    recentAlerts,
    hourlyTrend: hourlyTrend.map((r) => ({ hour: r.hour, count: Number(r.count) })),
  });
}
