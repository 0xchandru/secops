import { createConsumerGroup, readFromStream, ackMessage, sendToDeadLetter, getRedis } from "../lib/redis";
import { processLogRecord, ensureEngineLoaded } from "../lib/detection/pipeline";
import { logger } from "../lib/logger";

const GROUP = "secops-workers";
const CONSUMER = `worker-${process.pid}`;
const BATCH_SIZE = 20;
const MAX_RETRIES = 3;

let running = false;

export async function startWorker(): Promise<void> {
  if (running) return;
  running = true;

  try {
    await createConsumerGroup(GROUP);
  } catch (err) {
    logger.warn({ err }, "Failed to create consumer group, may already exist");
  }

  await ensureEngineLoaded();
  logger.info({ consumer: CONSUMER }, "Pipeline worker started");

  while (running) {
    try {
      const entries = await readFromStream(GROUP, CONSUMER, BATCH_SIZE, 2000);
      if (entries.length === 0) continue;

      for (const [id, fields] of entries) {
        const data = fieldsToObject(fields);
        try {
          await processLogRecord(
            data.logId ?? "unknown",
            data.raw ?? "",
            data.sourceType ?? "generic",
            data.sourceHost ?? "unknown",
            {
              srcIp: data.srcIp,
              userName: data.userName,
            },
          );
          await ackMessage(GROUP, id);
        } catch (err) {
          const retries = parseInt(data._retries ?? "0", 10);
          if (retries >= MAX_RETRIES) {
            await sendToDeadLetter(data, String(err));
            await ackMessage(GROUP, id);
            logger.error({ logId: data.logId, err }, "Log sent to dead letter queue after max retries");
          } else {
            logger.warn({ logId: data.logId, retries: retries + 1, err }, "Log processing failed, will retry");
          }
        }
      }
    } catch (err) {
      logger.error({ err }, "Worker loop error");
      await sleep(1000);
    }
  }
}

export function stopWorker(): void {
  running = false;
}

function fieldsToObject(fields: string[]): Record<string, string> {
  const obj: Record<string, string> = {};
  for (let i = 0; i < fields.length; i += 2) {
    obj[fields[i]] = fields[i + 1];
  }
  return obj;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// If run directly as a standalone worker process
if (process.argv[1]?.includes("pipeline-worker")) {
  startWorker().catch((err) => {
    logger.fatal({ err }, "Worker crashed");
    process.exit(1);
  });

  process.on("SIGINT", () => {
    stopWorker();
    process.exit(0);
  });
  process.on("SIGTERM", () => {
    stopWorker();
    process.exit(0);
  });
}
