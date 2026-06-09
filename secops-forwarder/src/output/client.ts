import type { OutputsConfig } from "../config/types.js";

export interface ForwarderEvent {
  message: string;
  sourcetype: string;
  index: string;
  host: string;
  source: string;
  hostname?: string;
  parsedTimestamp?: string;
  [key: string]: unknown;
}

export interface BatchResult {
  sent: number;
  failed: number;
  retries: number;
}

export class ForwarderClient {
  private config: OutputsConfig;
  private queue: ForwarderEvent[] = [];
  private flushTimer: ReturnType<typeof setInterval> | null = null;
  private totalSent = 0;
  private totalFailed = 0;
  private eps = 0;
  private epsWindow: number[] = [];
  private lastFlushAt = Date.now();

  constructor(config: OutputsConfig) {
    this.config = config;
  }

  push(event: ForwarderEvent): void {
    this.queue.push(event);
    if (this.queue.length >= this.config.batchSize) {
      this.flush().catch(err => {
        process.stderr.write(`[forwarder] Flush error: ${err.message}\n`);
      });
    }
  }

  start(): void {
    this.flushTimer = setInterval(() => {
      if (this.queue.length > 0) {
        this.flush().catch(err => {
          process.stderr.write(`[forwarder] Flush error: ${err.message}\n`);
        });
      }
    }, this.config.flushIntervalMs);
  }

  stop(): void {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
  }

  async drainAndStop(): Promise<void> {
    this.stop();
    if (this.queue.length > 0) {
      await this.flush();
    }
  }

  async flush(): Promise<BatchResult> {
    if (this.queue.length === 0) return { sent: 0, failed: 0, retries: 0 };

    const batch = this.queue.splice(0, this.config.batchSize);
    const result = await this.sendBatch(batch);

    const now = Date.now();
    const elapsed = (now - this.lastFlushAt) / 1000;
    this.epsWindow.push(result.sent / elapsed);
    if (this.epsWindow.length > 10) this.epsWindow.shift();
    this.eps = this.epsWindow.reduce((a, b) => a + b, 0) / this.epsWindow.length;
    this.lastFlushAt = now;

    return result;
  }

  private async sendBatch(events: ForwarderEvent[], attempt = 0): Promise<BatchResult> {
    const url = `${this.config.server.replace(/\/$/, "")}/api/ingest/bulk`;

    try {
      const response = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${this.config.token}`,
        },
        body: JSON.stringify({ logs: events }),
        signal: AbortSignal.timeout(30_000),
      });

      if (response.ok) {
        this.totalSent += events.length;
        return { sent: events.length, failed: 0, retries: attempt };
      }

      if (response.status === 429 || response.status >= 500) {
        if (attempt < this.config.maxRetries) {
          const delay = this.config.retryBaseMs * Math.pow(2, attempt);
          await sleep(delay);
          return this.sendBatch(events, attempt + 1);
        }
      }

      this.totalFailed += events.length;
      process.stderr.write(`[forwarder] Batch failed: HTTP ${response.status}\n`);
      return { sent: 0, failed: events.length, retries: attempt };
    } catch (err: any) {
      if (attempt < this.config.maxRetries) {
        const delay = this.config.retryBaseMs * Math.pow(2, attempt);
        await sleep(delay);
        return this.sendBatch(events, attempt + 1);
      }

      this.totalFailed += events.length;
      process.stderr.write(`[forwarder] Batch error: ${err.message}\n`);
      return { sent: 0, failed: events.length, retries: attempt };
    }
  }

  async sendHeartbeat(
    monitors: Array<{ path: string; sourcetype?: string; offset: number; eventsSent: number; eps: number }>,
  ): Promise<void> {
    const url = `${this.config.server.replace(/\/$/, "")}/api/forwarders/heartbeat`;
    const payload = {
      name: this.config.forwarderName,
      host: process.env.HOSTNAME ?? "unknown",
      version: "1.0.0",
      totalEventsSent: this.totalSent,
      eps: this.eps,
      monitors,
    };

    try {
      await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${this.config.token}`,
        },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(10_000),
      });
    } catch {
    }
  }

  getStats() {
    return { totalSent: this.totalSent, totalFailed: this.totalFailed, eps: this.eps, queued: this.queue.length };
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}
