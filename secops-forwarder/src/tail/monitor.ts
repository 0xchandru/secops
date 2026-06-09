import { openSync, readSync, statSync, existsSync, closeSync, readdirSync } from "fs";
import { join, dirname, basename } from "path";
import { hostname as osHostname } from "os";
import type { MonitorStanza } from "../config/types.js";
import { CheckpointStore } from "./checkpoint.js";

export interface TailEvent {
  line: string;
  path: string;
  sourcetype: string;
  index: string;
  host: string;
  source: string;
  offset: number;
}

export type LineCallback = (event: TailEvent) => void;

const BUFFER_SIZE = 65_536;
const POLL_INTERVAL_MS = 1_000;

function resolveGlob(pattern: string): string[] {
  if (!pattern.includes("*") && !pattern.includes("?")) {
    return [pattern];
  }
  const dir = dirname(pattern);
  const filePattern = basename(pattern);
  const regexStr = filePattern
    .replace(/\./g, "\\.")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");
  const re = new RegExp(`^${regexStr}$`);

  if (!existsSync(dir)) return [];
  try {
    return readdirSync(dir)
      .filter(f => re.test(f))
      .map(f => join(dir, f));
  } catch {
    return [];
  }
}

export class FileTailMonitor {
  private checkpoints: CheckpointStore;
  private callbacks: LineCallback[] = [];
  private timers = new Map<string, ReturnType<typeof setInterval>>();
  private stats = new Map<string, { eventsSent: number; eps: number; lastEpsReset: number }>();
  private hostname: string;

  constructor(checkpoints: CheckpointStore, hostname?: string) {
    this.checkpoints = checkpoints;
    this.hostname = hostname ?? osHostname();
  }

  onLine(cb: LineCallback): void {
    this.callbacks.push(cb);
  }

  startMonitor(stanza: MonitorStanza): void {
    if (stanza.disabled) return;

    const paths = resolveGlob(stanza.path);
    if (paths.length === 0) {
      console.warn(`[forwarder] No files matched: ${stanza.path}`);
    }

    for (const filePath of paths) {
      this.watchFile(filePath, stanza);
    }

    if (stanza.path.includes("*") || stanza.path.includes("?")) {
      const dir = dirname(stanza.path);
      const interval = setInterval(() => {
        const current = resolveGlob(stanza.path);
        for (const fp of current) {
          if (!this.timers.has(fp)) {
            this.watchFile(fp, stanza);
          }
        }
      }, 30_000);
      this.timers.set(`__glob_${stanza.path}`, interval);
    }
  }

  private watchFile(filePath: string, stanza: MonitorStanza): void {
    if (this.timers.has(filePath)) return;

    this.stats.set(filePath, { eventsSent: 0, eps: 0, lastEpsReset: Date.now() });

    const interval = setInterval(() => {
      this.pollFile(filePath, stanza);
    }, POLL_INTERVAL_MS);

    this.timers.set(filePath, interval);
  }

  private pollFile(filePath: string, stanza: MonitorStanza): void {
    if (!existsSync(filePath)) return;

    let stat: ReturnType<typeof statSync>;
    try {
      stat = statSync(filePath);
    } catch {
      return;
    }

    const checkpoint = this.checkpoints.get(filePath);
    let offset = 0;

    if (checkpoint) {
      const rotated =
        (stat.ino !== checkpoint.inode && checkpoint.inode !== 0) ||
        stat.size < checkpoint.offset;
      if (rotated) {
        offset = 0;
      } else {
        offset = checkpoint.offset;
      }
    } else if (stanza.followTail) {
      offset = stat.size;
    }

    if (offset >= stat.size) {
      this.checkpoints.set({
        path: filePath,
        offset: stat.size,
        inode: Number(stat.ino),
        size: stat.size,
        eventsSent: this.stats.get(filePath)?.eventsSent ?? 0,
        lastReadAt: new Date().toISOString(),
      });
      return;
    }

    let fd: number;
    try {
      fd = openSync(filePath, "r");
    } catch {
      return;
    }

    try {
      const buf = Buffer.alloc(BUFFER_SIZE);
      let remainder = "";
      let currentOffset = offset;
      // lineSplitter: use sourcetype lineBreaker regex if defined, else newline
      const lineSplitter = stanza.lineBreaker ? new RegExp(stanza.lineBreaker) : /\n/;

      while (currentOffset < stat.size) {
        const bytesToRead = Math.min(BUFFER_SIZE, stat.size - currentOffset);
        const bytesRead = readSync(fd, buf, 0, bytesToRead, currentOffset);
        if (bytesRead === 0) break;

        const chunk = buf.slice(0, bytesRead).toString("utf-8");
        const lines = (remainder + chunk).split(lineSplitter);
        remainder = lines.pop() ?? "";

        const st = this.stats.get(filePath)!;

        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed) continue;

          if (stanza.whitelistRegex && !new RegExp(stanza.whitelistRegex).test(trimmed)) continue;
          if (stanza.blacklistRegex && new RegExp(stanza.blacklistRegex).test(trimmed)) continue;

          const event: TailEvent = {
            line: trimmed,
            path: filePath,
            sourcetype: stanza.sourcetype,
            index: stanza.index,
            host: stanza.host ?? this.hostname,
            source: filePath,
            offset: currentOffset,
          };

          for (const cb of this.callbacks) cb(event);

          st.eventsSent++;
          const elapsed = (Date.now() - st.lastEpsReset) / 1000;
          if (elapsed >= 60) {
            st.eps = st.eventsSent / elapsed;
            st.lastEpsReset = Date.now();
            st.eventsSent = 0;
          }
        }

        currentOffset += bytesRead;
      }

      // Commit only up to the last fully-terminated line (not into a partial one).
      // Subtracting the byte length of the pending remainder ensures the next
      // poll re-reads those bytes and completes the line when more data arrives.
      const committedOffset = currentOffset - Buffer.byteLength(remainder, "utf-8");

      this.checkpoints.set({
        path: filePath,
        offset: committedOffset,
        inode: Number(stat.ino),
        size: stat.size,
        eventsSent: this.stats.get(filePath)?.eventsSent ?? 0,
        lastReadAt: new Date().toISOString(),
      });
    } finally {
      closeSync(fd);
    }
  }

  getMonitorStats(): Array<{ path: string; offset: number; eventsSent: number; eps: number }> {
    const results: Array<{ path: string; offset: number; eventsSent: number; eps: number }> = [];
    for (const [path] of this.timers) {
      if (path.startsWith("__glob_")) continue;
      const cp = this.checkpoints.get(path);
      const st = this.stats.get(path);
      results.push({
        path,
        offset: cp?.offset ?? 0,
        eventsSent: st?.eventsSent ?? 0,
        eps: st?.eps ?? 0,
      });
    }
    return results;
  }

  stop(): void {
    for (const [, timer] of this.timers) clearInterval(timer);
    this.timers.clear();
  }
}
