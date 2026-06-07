import cron from "node-cron";
import { logger } from "./logger";
import { detectionEngine } from "./detection/engine";
import { loadAssetCache } from "./enrichment";
import { cacheSet, isRedisAvailable } from "./redis";
import { getDashboardStats } from "../modules/dashboard/dashboard.service";
import { db, rawLogsTable, alertsTable } from "../db";
import { lt, and, eq } from "drizzle-orm";

const tasks: ReturnType<typeof cron.schedule>[] = [];

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

  // Cleanup old Redis stream entries daily at 2 AM
  tasks.push(
    cron.schedule("0 2 * * *", async () => {
      if (!isRedisAvailable()) return;
      try {
        const { getRedis } = await import("./redis");
        const r = getRedis();
        if (!r) return;
        // Trim streams to last 100k entries
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
