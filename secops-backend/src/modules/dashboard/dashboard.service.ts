import { db, alertsTable, rawLogsTable, rulesTable } from "../../db";
import { sql, desc, gte, and, isNotNull } from "drizzle-orm";
import { getEps, cacheGet, cacheSet } from "../../lib/redis";

export async function getDashboardStats(range = "24h") {
  // Check Redis cache first
  const cacheKey = `secops:dashboard:stats:${range}`;
  const cached = await cacheGet<any>(cacheKey);
  if (cached) return cached;

  const RANGE_MS: Record<string, number> = {
    "1h": 1 * 3600_000,
    "6h": 6 * 3600_000,
    "24h": 24 * 3600_000,
    "7d": 7 * 24 * 3600_000,
    "30d": 30 * 24 * 3600_000,
  };

  const rangeMs = RANGE_MS[range] ?? RANGE_MS["24h"];
  const rangeStart = new Date(Date.now() - rangeMs);
  const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

  const [
    alertsTotal,
    alertsByStatus,
    alertsBySeverity,
    alertsLast24h,
    logsTotal,
    activeRules,
    recentAlerts,
    logsBySource,
    alertTrend,
    mttrResult,
    mitreHeatmap,
    topTargetedHosts,
  ] = await Promise.all([
    db.select({ count: sql<number>`count(*)` }).from(alertsTable),
    db
      .select({ status: alertsTable.status, count: sql<number>`count(*)` })
      .from(alertsTable)
      .groupBy(alertsTable.status),
    db
      .select({ severity: alertsTable.severity, count: sql<number>`count(*)` })
      .from(alertsTable)
      .groupBy(alertsTable.severity),
    db
      .select({ count: sql<number>`count(*)` })
      .from(alertsTable)
      .where(gte(alertsTable.createdAt, rangeStart)),
    db.select({ count: sql<number>`count(*)` }).from(rawLogsTable),
    db.select({ count: sql<number>`count(*)` }).from(rulesTable).where(sql`enabled = true`),
    db
      .select({
        id: alertsTable.id,
        alertCode: alertsTable.alertCode,
        title: alertsTable.title,
        severity: alertsTable.severity,
        status: alertsTable.status,
        createdAt: alertsTable.createdAt,
      })
      .from(alertsTable)
      .orderBy(desc(alertsTable.createdAt))
      .limit(5),
    db
      .select({ source: rawLogsTable.source, count: sql<number>`count(*)` })
      .from(rawLogsTable)
      .groupBy(rawLogsTable.source),
    db
      .select({
        hour: sql<string>`to_char(date_trunc('hour', created_at), 'HH24:00')`,
        count: sql<number>`count(*)`,
      })
      .from(alertsTable)
      .where(gte(alertsTable.createdAt, rangeStart))
      .groupBy(sql`date_trunc('hour', created_at)`)
      .orderBy(sql`date_trunc('hour', created_at)`),
    // MTTR: Mean Time To Resolution for resolved alerts in the last 7 days
    db.select({
      avgMinutes: sql<number>`COALESCE(AVG(EXTRACT(EPOCH FROM (resolved_at - created_at)) / 60), 0)`,
    }).from(alertsTable)
      .where(and(
        isNotNull(alertsTable.resolvedAt),
        gte(alertsTable.createdAt, sevenDaysAgo),
      )),
    // MITRE heatmap: tactic → technique count
    db.select({
      tactic: alertsTable.mitreTactic,
      techniqueId: alertsTable.mitreTechniqueId,
      techniqueName: alertsTable.mitreTechniqueName,
      count: sql<number>`count(*)`,
    }).from(alertsTable)
      .where(isNotNull(alertsTable.mitreTactic))
      .groupBy(alertsTable.mitreTactic, alertsTable.mitreTechniqueId, alertsTable.mitreTechniqueName),
    // Top targeted hosts
    db.select({
      hostname: alertsTable.hostname,
      count: sql<number>`count(*)`,
    }).from(alertsTable)
      .where(isNotNull(alertsTable.hostname))
      .groupBy(alertsTable.hostname)
      .orderBy(sql`count(*) DESC`)
      .limit(10),
  ]);

  const severityMap: Record<string, number> = {};
  alertsBySeverity.forEach(row => { severityMap[row.severity] = Number(row.count); });

  const statusMap: Record<string, number> = {};
  alertsByStatus.forEach(row => { statusMap[row.status] = Number(row.count); });

  const sourceMap: Record<string, number> = {};
  logsBySource.forEach(row => { sourceMap[row.source] = Number(row.count); });

  // Get real-time EPS from Redis
  const eps = await getEps();

  const stats = {
    alerts: {
      total: Number(alertsTotal[0]?.count ?? 0),
      last24h: Number(alertsLast24h[0]?.count ?? 0),
      byStatus: statusMap,
      bySeverity: severityMap,
    },
    logs: {
      total: Number(logsTotal[0]?.count ?? 0),
      bySource: sourceMap,
      eps,
    },
    rules: {
      active: Number(activeRules[0]?.count ?? 0),
    },
    mttr: Math.round(Number(mttrResult[0]?.avgMinutes ?? 0)),
    mitreHeatmap: mitreHeatmap
      .filter((r) => r.tactic)
      .map((r) => ({
        tactic: r.tactic,
        techniqueId: r.techniqueId,
        techniqueName: r.techniqueName,
        count: Number(r.count),
      })),
    topTargetedHosts: topTargetedHosts
      .filter((r) => r.hostname)
      .map((r) => ({ hostname: r.hostname, count: Number(r.count) })),
    recentAlerts,
    alertTrend: alertTrend.map(r => ({ hour: r.hour, count: Number(r.count) })),
  };

  // Cache for 55 seconds
  await cacheSet(cacheKey, stats, 55);

  return stats;
}
