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
  const {
    name, description, severity, yamlContent, logSource, mitreIds, mitreTactic, tags,
    ruleType, splQuery, splThreshold, scheduleInterval,
  } = req.body;
  if (!name || !severity) {
    res.status(400).json({ error: "name and severity are required" });
    return;
  }

  // Validate SPL saved search
  if (ruleType === "spl_saved_search" && !splQuery) {
    res.status(400).json({ error: "splQuery is required for spl_saved_search rules" });
    return;
  }

  const rule = await rulesService.createRule({
    name, description, severity, yamlContent, logSource, mitreIds, mitreTactic, tags,
    ruleType: ruleType ?? "sigma",
    splQuery: splQuery ?? null,
    splThreshold: splThreshold != null ? Number(splThreshold) : 1,
    scheduleInterval: scheduleInterval ?? "15m",
    createdBy: req.user!.userId,
  });
  invalidateEngine();
  await logAuditEvent(req, "rules.create", { resource: "rules", resourceId: rule.id, metadata: { name, ruleType: rule.ruleType } });
  res.status(201).json({ rule });
}

export async function updateRule(req: Request, res: Response): Promise<void> {
  const { name, description, severity, yamlContent, mitreIds, ruleType, splQuery, splThreshold, scheduleInterval } = req.body;
  const id = req.params.id as string;
  const rule = await rulesService.updateRule(id, {
    name, description, severity, yamlContent, mitreIds,
    ruleType, splQuery, splThreshold: splThreshold != null ? Number(splThreshold) : undefined,
    scheduleInterval,
    updatedBy: req.user!.userId,
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
  await logAuditEvent(req, "rules.toggle", { resource: "rules", resourceId: id, metadata: { enabled } });
  res.json({ rule });
}

export async function testRule(req: Request, res: Response): Promise<void> {
  const id = req.params.id as string;
  const rule = await rulesService.getRuleById(id);
  if (!rule) { res.status(404).json({ error: "Rule not found" }); return; }

  // Get recent events
  const recentLogs = await db.select()
    .from((await import("../../db")).rawLogsTable)
    .where(gte((await import("../../db")).rawLogsTable.createdAt, new Date(Date.now() - 3600_000)))
    .limit(200)
    .orderBy(sql`created_at desc`);

  if (recentLogs.length === 0) {
    res.json({ matchCount: 0, sampleMatches: [], message: "No events in the last hour to test against" });
    return;
  }

  // Build NormalizedEvent objects for the test
  const normalizedEvents = recentLogs.map(log => ({
    id: log.id,
    timestamp: log.createdAt,
    parsedTimestamp: log.parsedTimestamp ?? undefined,
    sourceType: log.sourcetype ?? log.source ?? "generic",
    sourceHost: log.hostname ?? log.source ?? "",
    category: log.category ?? "",
    action: log.action ?? "",
    outcome: log.outcome ?? undefined,
    severity: log.severity,
    eventType: log.eventType ?? undefined,
    message: log.message ?? JSON.stringify(log.rawData ?? {}),
    userName: log.username ?? undefined,
    targetUserName: log.targetUsername ?? undefined,
    srcIp: log.sourceIp ?? undefined,
    dstIp: log.destIp ?? undefined,
    srcPort: log.srcPort ?? undefined,
    dstPort: log.dstPort ?? undefined,
    protocol: log.protocol ?? undefined,
    processName: log.processName ?? undefined,
    processId: log.processId ?? undefined,
    processCommandLine: log.processCommandLine ?? undefined,
    httpMethod: log.httpMethod ?? undefined,
    httpUrl: log.httpUrl ?? undefined,
    httpStatusCode: log.httpStatusCode ?? undefined,
    registryKey: log.registryKey ?? undefined,
    registryValue: log.registryValue ?? undefined,
    fileName: log.fileName ?? undefined,
    filePath: log.filePath ?? undefined,
    fileHash: log.fileHash ?? undefined,
    rawData: log.rawData ?? undefined,
  }));

  const yamlContent = rule.yamlContent ?? "";
  const triggered = yamlContent
    ? detectionEngine.testRule(yamlContent, normalizedEvents as any)
    : [];
  const matches = triggered.slice(0, 5).map(t => ({
    logId: t.triggerEventId,
    message: t.description,
    source: t.sourceHost,
    severity: t.severity,
  }));

  res.json({ matchCount: triggered.length, sampleMatches: matches });
}

export async function getRuleStats(req: Request, res: Response): Promise<void> {
  const id = req.params.id as string;
  const rule = await rulesService.getRuleById(id);
  if (!rule) { res.status(404).json({ error: "Rule not found" }); return; }

  const [alertCount, recentAlerts] = await Promise.all([
    db.select({ count: sql<number>`count(*)` }).from(alertsTable).where(eq(alertsTable.ruleId, id)),
    db.select({ createdAt: alertsTable.createdAt, severity: alertsTable.severity, status: alertsTable.status })
      .from(alertsTable)
      .where(and(eq(alertsTable.ruleId, id), gte(alertsTable.createdAt, new Date(Date.now() - 7 * 86_400_000))))
      .orderBy(sql`created_at desc`)
      .limit(10),
  ]);

  res.json({ rule, alertCount: Number(alertCount[0]?.count ?? 0), recentAlerts });
}
