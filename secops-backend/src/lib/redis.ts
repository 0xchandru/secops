import Redis from "ioredis";
import { logger } from "./logger";

const REDIS_URL = process.env["REDIS_URL"] ?? "redis://localhost:6379";

let redis: Redis | null = null;
let subscriber: Redis | null = null;
let redisAvailable = false;

export function getRedis(): Redis | null {
  if (redis) return redis;
  try {
    redis = new Redis(REDIS_URL, {
      maxRetriesPerRequest: 3,
      retryStrategy(times) {
        if (times > 5) return null;
        return Math.min(times * 200, 2000);
      },
      lazyConnect: true,
    });
    redis.on("error", (err) => {
      if (redisAvailable) {
        logger.warn({ err: err.message }, "Redis connection error");
        redisAvailable = false;
      }
    });
    redis.on("connect", () => {
      redisAvailable = true;
      logger.info("Redis connected");
    });
    redis.connect().catch(() => {
      logger.warn("Redis not available, running without cache/queue");
    });
    return redis;
  } catch {
    return null;
  }
}

export function getSubscriber(): Redis | null {
  if (subscriber) return subscriber;
  try {
    subscriber = new Redis(REDIS_URL, {
      maxRetriesPerRequest: 3,
      retryStrategy(times) {
        if (times > 5) return null;
        return Math.min(times * 200, 2000);
      },
      lazyConnect: true,
    });
    subscriber.on("error", () => {});
    subscriber.connect().catch(() => {});
    return subscriber;
  } catch {
    return null;
  }
}

export function isRedisAvailable(): boolean {
  return redisAvailable && redis !== null;
}

// --- Cache helpers ---
const DEFAULT_TTL = 60; // seconds

export async function cacheGet<T>(key: string): Promise<T | null> {
  const r = getRedis();
  if (!r || !redisAvailable) return null;
  try {
    const val = await r.get(key);
    return val ? JSON.parse(val) : null;
  } catch {
    return null;
  }
}

export async function cacheSet(key: string, value: unknown, ttlSeconds = DEFAULT_TTL): Promise<void> {
  const r = getRedis();
  if (!r || !redisAvailable) return;
  try {
    await r.setex(key, ttlSeconds, JSON.stringify(value));
  } catch {}
}

export async function cacheDel(key: string): Promise<void> {
  const r = getRedis();
  if (!r || !redisAvailable) return;
  try {
    await r.del(key);
  } catch {}
}

// --- Pub/Sub helpers ---
export async function publish(channel: string, data: unknown): Promise<void> {
  const r = getRedis();
  if (!r || !redisAvailable) return;
  try {
    await r.publish(channel, JSON.stringify(data));
  } catch {}
}

// --- Redis Streams helpers ---
const STREAM_KEY = "secops:log_queue";
const DLQ_STREAM = "secops:dead_letter";

export async function enqueueLog(logData: Record<string, string>): Promise<string | null> {
  const r = getRedis();
  if (!r || !redisAvailable) return null;
  try {
    const id = await r.xadd(STREAM_KEY, "*", ...Object.entries(logData).flat());
    return id;
  } catch {
    return null;
  }
}

export async function createConsumerGroup(group: string): Promise<void> {
  const r = getRedis();
  if (!r) return;
  try {
    await r.xgroup("CREATE", STREAM_KEY, group, "0", "MKSTREAM");
  } catch (err: any) {
    if (!err.message?.includes("BUSYGROUP")) throw err;
  }
}

export async function readFromStream(
  group: string,
  consumer: string,
  count = 10,
  blockMs = 2000,
): Promise<Array<[string, string[]]>> {
  const r = getRedis();
  if (!r) return [];
  try {
    const result = await r.xreadgroup(
      "GROUP", group, consumer,
      "COUNT", count,
      "BLOCK", blockMs,
      "STREAMS", STREAM_KEY, ">",
    );
    if (!result) return [];
    // result: [[streamKey, [[id, fields], ...]]]
    const entries = (result as any)[0]?.[1] ?? [];
    return entries as Array<[string, string[]]>;
  } catch {
    return [];
  }
}

export async function ackMessage(group: string, id: string): Promise<void> {
  const r = getRedis();
  if (!r) return;
  try {
    await r.xack(STREAM_KEY, group, id);
  } catch {}
}

export async function sendToDeadLetter(logData: Record<string, string>, error: string): Promise<void> {
  const r = getRedis();
  if (!r || !redisAvailable) return;
  try {
    await r.xadd(DLQ_STREAM, "*", ...Object.entries({ ...logData, error }).flat());
  } catch {}
}

// --- EPS (events per second) tracking ---
const EPS_KEY = "secops:eps";

export async function incrementEps(): Promise<void> {
  const r = getRedis();
  if (!r || !redisAvailable) return;
  try {
    const now = Math.floor(Date.now() / 1000);
    const key = `${EPS_KEY}:${now}`;
    await r.incr(key);
    await r.expire(key, 120); // keep 2 minutes of buckets
  } catch {}
}

export async function getEps(): Promise<number> {
  const r = getRedis();
  if (!r || !redisAvailable) return 0;
  try {
    const now = Math.floor(Date.now() / 1000);
    // Average over last 10 seconds
    const keys = Array.from({ length: 10 }, (_, i) => `${EPS_KEY}:${now - i}`);
    const values = await r.mget(...keys);
    const total = values.reduce((sum, v) => sum + (parseInt(v ?? "0", 10) || 0), 0);
    return Math.round(total / 10);
  } catch {
    return 0;
  }
}

export { STREAM_KEY, DLQ_STREAM };
