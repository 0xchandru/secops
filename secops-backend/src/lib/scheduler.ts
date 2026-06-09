import cron from "node-cron";
import { logger } from "./logger";
import { detectionEngine } from "./detection/engine";
import { loadAssetCache } from "./enrichment";
import { cacheSet, isRedisAvailable } from "./redis";
import { getDashboardStats } from "../modules/dashboard/dashboard.service";
import { db, rawLogsTable, alertsTable, rulesTable } from "../db";
import { lt, and, eq, isNotNull, lte, gte, sql, desc } from "drizzle-orm";
import { parseSplQuery } from "./search/spl-parser";
import { executeSplPipes } from "./search/spl-executor";
import yaml from "js-yaml";

const tasks: ReturnType<typeof cron.schedule>[] = [];

const INTERVAL_MS: Record<string, number> = {
  "5m": 5 * 60_000,
  "15m": 15 * 60_000,
  "1h": 60 * 60_000,
  "6h": 6 * 60 * 60_000,
  "24h": 24 * 60 * 60_000,
};

async function runSplSavedSearches(): Promise<void> {
  const now = new Date();

  const savedSearchRules = await db.select()
    .from(rulesTable)
    .where(and(
      eq(rulesTable.enabled, true),
      eq(rulesTable.ruleType as any, "spl_saved_search"),
      isNotNull(rulesTable.splQuery),
    ));

  for (const rule of savedSearchRules) {
    try {
      const intervalMs = INTERVAL_MS[rule.scheduleInterval ?? "15m"] ?? INTERVAL_MS["15m"];
      const lastRun = rule.lastRunAt;

      // Check if this rule is due to run
      if (lastRun && (now.getTime() - lastRun.getTime()) < intervalMs) {
        continue;
      }

      // Update lastRunAt immediately to prevent concurrent runs
      await db.update(rulesTable)
        .set({ lastRunAt: now })
        .where(eq(rulesTable.id, rule.id));

      // Parse and execute the SPL query
      const splQuery = rule.splQuery!;
      const parsed = parseSplQuery(splQuery);

      // Apply look-back window based on schedule interval
      const lookbackMs = Math.max(intervalMs * 2, 60 * 60_000); // at least 1h lookback
      const lookbackCondition = gte(rawLogsTable.createdAt, new Date(now.getTime() - lookbackMs));

      const baseConditions = parsed.conditions
        ? and(parsed.conditions, lookbackCondition)
        : lookbackCondition;

      const rows = await db.select()
        .from(rawLogsTable)
        .where(baseConditions)
        .orderBy(sql`created_at desc`)
        .limit(10_000);

      // Apply pipe transformations if present
      let results: Record<string, unknown>[];
      if (parsed.pipe) {
        results = executeSplPipes(rows as Record<string, unknown>[], parsed.pipe);
      } else {
        results = rows as Record<string, unknown>[];
      }

      const threshold = rule.splThreshold ?? 1;
      if (results.length >= threshold) {
        // Create alert
        const alertCode = `SPL-${Date.now()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`;
        await db.insert(alertsTable).values({
          alertCode,
          title: `[SPL Alert] ${rule.name}`,
          description: `SPL saved search "${rule.name}" matched ${results.length} event(s) — threshold: ${threshold}.\n\nQuery: ${splQuery}`,
          severity: rule.severity,
          status: "new",
          source: "spl_saved_search",
          ruleId: rule.id,
          ruleName: rule.name,
          mitreIds: rule.mitreIds ?? [],
          mitreTactic: rule.mitreTactic ?? null,
        } as any);

        // Increment trigger count
        await db.update(rulesTable)
          .set({ triggerCount: sql`${rulesTable.triggerCount} + 1` })
          .where(eq(rulesTable.id, rule.id));

        logger.info(
          { ruleId: rule.id, ruleName: rule.name, matchCount: results.length, threshold },
          "SPL saved search alert triggered",
        );
      }
    } catch (err) {
      logger.error({ err, ruleId: rule.id }, "SPL saved search execution failed");
    }
  }
}

// ── Risk Score Sum Rules ──────────────────────────────────────────────────────
// Accumulate per-entity risk scores over a rolling window and fire when the sum
// exceeds the configured threshold.
async function runRiskScoreSumRules(): Promise<void> {
  const riskRules = await db
    .select()
    .from(rulesTable)
    .where(and(eq(rulesTable.enabled, true), eq(rulesTable.ruleType as any, "sigma")));

  // Filter to only rules with type: risk_score_sum in their YAML
  const eligible = riskRules.filter((r) => {
    if (!r.yamlContent) return false;
    try {
      const parsed = yaml.load(r.yamlContent) as any;
      return parsed?.type === "risk_score_sum" && parsed?.risk_sum;
    } catch { return false; }
  });

  for (const row of eligible) {
    try {
      const parsed = yaml.load(row.yamlContent!) as any;
      const riskSum = parsed.risk_sum;
      if (!riskSum?.field || !riskSum?.sum_threshold) continue;

      const windowMs = parseSchedulerTimeframe(riskSum.timeframe ?? "1h");
      const windowStart = new Date(Date.now() - windowMs);

      // Aggregate riskScore per entity field value over rolling window
      const results = await db
        .select({
          entityKey: sql<string>`${sql.raw(riskSum.field === "srcIp" ? "source_ip" : riskSum.field === "sourceHost" ? "hostname" : "username")}`,
          totalRisk: sql<number>`COALESCE(SUM((context->>'riskScore')::numeric), 0)::int`,
          eventCount: sql<number>`COUNT(*)::int`,
        })
        .from(alertsTable)
        .where(gte(alertsTable.createdAt, windowStart))
        .groupBy(sql.raw(riskSum.field === "srcIp" ? "source_ip" : riskSum.field === "sourceHost" ? "hostname" : "username"))
        .having(sql`COALESCE(SUM((context->>'riskScore')::numeric), 0) >= ${riskSum.sum_threshold}`);

      for (const result of results) {
        if (!result.entityKey) continue;
        const alertCode = `RSK-${Date.now()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`;
        await db.insert(alertsTable).values({
          alertCode,
          title: `High-Risk Entity: ${result.entityKey} (risk score: ${result.totalRisk})`,
          description: `Entity "${result.entityKey}" accumulated a risk score of ${result.totalRisk} (threshold: ${riskSum.sum_threshold}) from ${result.eventCount} events over the past ${riskSum.timeframe ?? "1h"}. Rule: ${row.name}`,
          severity: row.severity,
          status: "new",
          source: "risk_score_sum",
          ruleId: row.id,
          ruleName: row.name,
          mitreIds: row.mitreIds ?? [],
          mitreTactic: row.mitreTactic ?? null,
          context: { entityKey: result.entityKey, totalRisk: result.totalRisk, eventCount: result.eventCount },
          dedupKey: `rsk-${row.id}-${result.entityKey}-${Math.floor(Date.now() / windowMs)}`,
        } as any).onConflictDoNothing();

        await db.update(rulesTable)
          .set({ triggerCount: sql`${rulesTable.triggerCount} + 1` })
          .where(eq(rulesTable.id, row.id));

        logger.info({ ruleId: row.id, entityKey: result.entityKey, totalRisk: result.totalRisk }, "Risk score sum alert triggered");
      }
    } catch (err) {
      logger.error({ err, ruleId: row.id }, "Risk score sum rule evaluation failed");
    }
  }
}

// ── Anomaly Baseline Rules ────────────────────────────────────────────────────
// Compare current-hour event count against a 7-day hourly baseline and fire
// when the current count deviates beyond stddevMultiplier standard deviations.
async function runAnomalyBaselineRules(): Promise<void> {
  const anomalyRules = await db
    .select()
    .from(rulesTable)
    .where(and(eq(rulesTable.enabled, true), eq(rulesTable.ruleType as any, "sigma")));

  const eligible = anomalyRules.filter((r) => {
    if (!r.yamlContent) return false;
    try {
      const parsed = yaml.load(r.yamlContent) as any;
      return parsed?.type === "anomaly" && parsed?.anomaly;
    } catch { return false; }
  });

  for (const row of eligible) {
    try {
      const parsed = yaml.load(row.yamlContent!) as any;
      const anomalyCfg = parsed.anomaly;
      if (!anomalyCfg) continue;

      const stddevMult = anomalyCfg.stddev_multiplier ?? 3;
      const now = new Date();
      const currentHourStart = new Date(now);
      currentHourStart.setMinutes(0, 0, 0);

      // Get current hour count using the rule's match conditions as a filter hint
      const [currentRow] = await db
        .select({ count: sql<number>`COUNT(*)::int` })
        .from(rawLogsTable)
        .where(gte(rawLogsTable.createdAt, currentHourStart));

      const currentCount = currentRow?.count ?? 0;

      // Get hourly counts for last 7 days (168 hours) for baseline
      const baselineRows = await db
        .select({
          hour: sql<string>`DATE_TRUNC('hour', created_at)`,
          count: sql<number>`COUNT(*)::int`,
        })
        .from(rawLogsTable)
        .where(and(
          gte(rawLogsTable.createdAt, new Date(now.getTime() - 7 * 86_400_000)),
          lte(rawLogsTable.createdAt, currentHourStart),
        ))
        .groupBy(sql`DATE_TRUNC('hour', created_at)`)
        .orderBy(desc(sql`DATE_TRUNC('hour', created_at)`));

      if (baselineRows.length < 24) continue; // Need at least 24 data points for a meaningful baseline

      const counts = baselineRows.map((r) => r.count);
      const mean = counts.reduce((s, v) => s + v, 0) / counts.length;
      const variance = counts.reduce((s, v) => s + Math.pow(v - mean, 2), 0) / counts.length;
      const stddev = Math.sqrt(variance);

      if (stddev === 0) continue; // Stable baseline — no anomaly possible

      const zScore = (currentCount - mean) / stddev;
      if (Math.abs(zScore) < stddevMult) continue;

      const direction = currentCount > mean ? "spike" : "drop";
      const alertCode = `ANO-${Date.now()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`;

      await db.insert(alertsTable).values({
        alertCode,
        title: `Anomaly Detected: ${direction === "spike" ? "Unusual spike" : "Unusual drop"} in event volume (${parsed.name ?? row.name})`,
        description: `Current hour count: ${currentCount}. Baseline mean: ${Math.round(mean)} ± ${Math.round(stddev)} (7-day). Z-score: ${zScore.toFixed(1)} (threshold: ±${stddevMult}). Rule: ${row.name}`,
        severity: row.severity,
        status: "new",
        source: "anomaly",
        ruleId: row.id,
        ruleName: row.name,
        mitreIds: row.mitreIds ?? [],
        mitreTactic: row.mitreTactic ?? null,
        context: { currentCount, baselineMean: Math.round(mean), baselineStddev: Math.round(stddev), zScore: parseFloat(zScore.toFixed(2)), direction },
        dedupKey: `ano-${row.id}-${currentHourStart.toISOString()}`,
      } as any).onConflictDoNothing();

      await db.update(rulesTable)
        .set({ triggerCount: sql`${rulesTable.triggerCount} + 1` })
        .where(eq(rulesTable.id, row.id));

      logger.info({ ruleId: row.id, currentCount, mean, zScore, direction }, "Anomaly alert triggered");
    } catch (err) {
      logger.error({ err, ruleId: row.id }, "Anomaly rule evaluation failed");
    }
  }
}

function parseSchedulerTimeframe(tf: string): number {
  const match = tf.match(/^(\d+)([smhd])$/);
  if (!match) return 3_600_000;
  const n = parseInt(match[1]);
  const units: Record<string, number> = { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 };
  return n * (units[match[2]] ?? 3_600_000);
}

export function startScheduler(): void {
  // Reload detection rules every 60 seconds
  tasks.push(
    cron.schedule("* * * * *", async () => {
      try {
        await detectionEngine.loadRulesFromDb();
        logger.debug("Detection rules reloaded (scheduled)");
      } catch (err) {
        logger.error({ err }, "Scheduled rule reload failed");
      }
    }),
  );

  // Refresh asset cache every 5 minutes
  tasks.push(
    cron.schedule("*/5 * * * *", async () => {
      try {
        await loadAssetCache();
        logger.debug("Asset cache refreshed (scheduled)");
      } catch (err) {
        logger.error({ err }, "Scheduled asset cache refresh failed");
      }
    }),
  );

  // Cache dashboard stats every 60 seconds (if Redis available)
  tasks.push(
    cron.schedule("* * * * *", async () => {
      if (!isRedisAvailable()) return;
      try {
        const stats = await getDashboardStats();
        await cacheSet("secops:dashboard:stats", stats, 55);
      } catch (err) {
        logger.error({ err }, "Scheduled dashboard cache failed");
      }
    }),
  );

  // Run SPL saved search alerts every minute
  tasks.push(
    cron.schedule("* * * * *", async () => {
      try {
        await runSplSavedSearches();
      } catch (err) {
        logger.error({ err }, "SPL saved search scheduler failed");
      }
    }),
  );

  // Run risk_score_sum correlation rules every 5 minutes
  tasks.push(
    cron.schedule("*/5 * * * *", async () => {
      try {
        await runRiskScoreSumRules();
      } catch (err) {
        logger.error({ err }, "Risk score sum scheduler failed");
      }
    }),
  );

  // Run anomaly baseline rules every 30 minutes (on the hour and half-hour)
  tasks.push(
    cron.schedule("0,30 * * * *", async () => {
      try {
        await runAnomalyBaselineRules();
      } catch (err) {
        logger.error({ err }, "Anomaly baseline scheduler failed");
      }
    }),
  );

  // Cleanup old Redis stream entries daily at 2 AM
  tasks.push(
    cron.schedule("0 2 * * *", async () => {
      if (!isRedisAvailable()) return;
      try {
        const { getRedis } = await import("./redis");
        const r = getRedis();
        if (!r) return;
        await r.xtrim("secops:log_queue", "MAXLEN", "~", 100000);
        await r.xtrim("secops:dead_letter", "MAXLEN", "~", 10000);
        logger.info("Stream cleanup completed (scheduled)");
      } catch (err) {
        logger.error({ err }, "Scheduled stream cleanup failed");
      }
    }),
  );

  // Data retention: purge old raw_logs (>90 days) and resolved alerts (>180 days) daily at 3 AM
  tasks.push(
    cron.schedule("0 3 * * *", async () => {
      try {
        const now = new Date();
        const logCutoff = new Date(now.getTime() - 90 * 86400_000);
        const alertCutoff = new Date(now.getTime() - 180 * 86400_000);

        const logResult = await db.delete(rawLogsTable)
          .where(lt(rawLogsTable.createdAt, logCutoff));
        const alertResult = await db.delete(alertsTable)
          .where(and(
            eq(alertsTable.status, "resolved"),
            lt(alertsTable.createdAt, alertCutoff),
          ));

        logger.info(
          { logsDeleted: logResult.rowCount, alertsDeleted: alertResult.rowCount },
          "Data retention cleanup completed",
        );
      } catch (err) {
        logger.error({ err }, "Scheduled data retention cleanup failed");
      }
    }),
  );

  logger.info("Scheduler started with periodic tasks");
}

export function stopScheduler(): void {
  for (const task of tasks) {
    task.stop();
  }
  tasks.length = 0;
}
