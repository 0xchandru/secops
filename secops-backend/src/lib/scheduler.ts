import cron from "node-cron";
import { logger } from "./logger";
import { detectionEngine } from "./detection/engine";
import { loadAssetCache } from "./enrichment";
import { cacheSet, isRedisAvailable } from "./redis";
import { getDashboardStats } from "../modules/dashboard/dashboard.service";
import { db, rawLogsTable, alertsTable, rulesTable } from "../db";
import { lt, and, eq, isNotNull, or, lte, gte, sql } from "drizzle-orm";
import { parseSplQuery } from "./search/spl-parser";
import { executeSplPipes } from "./search/spl-executor";

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
