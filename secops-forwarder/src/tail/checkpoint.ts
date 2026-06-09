import { readFileSync, writeFileSync, mkdirSync, existsSync, unlinkSync } from "fs";
import { join, resolve } from "path";

export interface CheckpointEntry {
  path: string;
  offset: number;
  inode: number;
  size: number;
  eventsSent: number;
  lastReadAt: string;
}

export class CheckpointStore {
  private dir: string;
  private cache = new Map<string, CheckpointEntry>();

  constructor(dataDir: string) {
    this.dir = join(dataDir, "checkpoints");
    mkdirSync(this.dir, { recursive: true });
  }

  private filePath(monitorPath: string): string {
    const safe = resolve(monitorPath).replace(/[/\\:*?"<>|]/g, "_");
    return join(this.dir, `${safe}.json`);
  }

  get(monitorPath: string): CheckpointEntry | null {
    if (this.cache.has(monitorPath)) return this.cache.get(monitorPath)!;
    const fp = this.filePath(monitorPath);
    if (!existsSync(fp)) return null;
    try {
      const entry: CheckpointEntry = JSON.parse(readFileSync(fp, "utf-8"));
      this.cache.set(monitorPath, entry);
      return entry;
    } catch {
      return null;
    }
  }

  set(entry: CheckpointEntry): void {
    this.cache.set(entry.path, entry);
    const fp = this.filePath(entry.path);
    writeFileSync(fp, JSON.stringify(entry, null, 2), "utf-8");
  }

  reset(monitorPath: string): void {
    this.cache.delete(monitorPath);
    const fp = this.filePath(monitorPath);
    if (existsSync(fp)) {
      try {
        unlinkSync(fp);
      } catch {}
    }
  }

  all(): CheckpointEntry[] {
    return Array.from(this.cache.values());
  }
}
