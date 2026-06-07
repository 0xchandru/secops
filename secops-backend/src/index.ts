import { config } from "dotenv";
import { dirname, resolve } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
config({ path: resolve(__dirname, "..", ".env") });

import http from "http";
import app from "./app";
import { logger } from "./lib/logger";
import { initWebSocket } from "./lib/websocket";
import { ensureEngineLoaded } from "./lib/detection/pipeline";
import { seedDefaultRules } from "./lib/detection/seed-rules";
import { loadAssetCache } from "./lib/enrichment";
import { getRedis } from "./lib/redis";
import { startScheduler } from "./lib/scheduler";
import { startSyslogReceiver } from "./receivers/syslog-server";
import { startWorker } from "./workers/pipeline-worker";

const rawPort = process.env["PORT"];

if (!rawPort) {
  throw new Error("PORT environment variable is required but was not provided.");
}

const port = Number(rawPort);

if (Number.isNaN(port) || port <= 0) {
  throw new Error(`Invalid PORT value: "${rawPort}"`);
}

const server = http.createServer(app);

initWebSocket(server);

server.listen(port, async () => {
  logger.info({ port }, "Server listening");

  // Initialize Redis (non-blocking)
  try {
    getRedis();
    logger.info("Redis client initialized");
  } catch (err) {
    logger.warn({ err }, "Redis not available, running without cache/queue");
  }

  try {
    await loadAssetCache();
    logger.info("Asset cache loaded");
  } catch (err) {
    logger.warn({ err }, "Failed to load asset cache");
  }

  try {
    await seedDefaultRules();
  } catch (err) {
    logger.warn({ err }, "Failed to seed default rules");
  }

  try {
    await ensureEngineLoaded();
    logger.info("Detection engine loaded");
  } catch (err) {
    logger.warn({ err }, "Failed to load detection engine");
  }

  // Start periodic scheduler
  startScheduler();

  // Start syslog receiver if enabled
  if (process.env["ENABLE_SYSLOG"] === "true") {
    try {
      startSyslogReceiver();
      logger.info("Syslog receiver started");
    } catch (err) {
      logger.warn({ err }, "Failed to start syslog receiver");
    }
  }

  // Start inline pipeline worker if enabled (for single-process mode)
  if (process.env["ENABLE_WORKER"] === "true") {
    try {
      startWorker();
      logger.info("Inline pipeline worker started");
    } catch (err) {
      logger.warn({ err }, "Failed to start inline worker");
    }
  }
});
