import { existsSync, readdirSync, readFileSync } from "fs";
import { join } from "path";
import type { CheckpointEntry } from "../tail/checkpoint.js";
import { loadConfig } from "../config/parser.js";

function readCheckpoints(dataDir: string): Map<string, CheckpointEntry> {
  const checkpointDir = join(dataDir, "checkpoints");
  const result = new Map<string, CheckpointEntry>();
  if (!existsSync(checkpointDir)) return result;

  try {
    for (const f of readdirSync(checkpointDir).filter(f => f.endsWith(".json"))) {
      try {
        const entry = JSON.parse(readFileSync(join(checkpointDir, f), "utf-8")) as CheckpointEntry;
        result.set(entry.path, entry);
      } catch {
        // skip corrupt checkpoint
      }
    }
  } catch {
    // ignore unreadable dir
  }
  return result;
}

function ago(isoDate: string | undefined): string {
  if (!isoDate) return "never";
  const diff = Date.now() - new Date(isoDate).getTime();
  if (diff < 5_000) return "just now";
  if (diff < 60_000) return `${Math.floor(diff / 1_000)}s ago`;
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  return new Date(isoDate).toLocaleString();
}

export function statusCommand(options: { configDir: string; dataDir: string }): void {
  const { configDir, dataDir } = options;

  // Load config to enumerate all configured monitors
  let configuredMonitors: Array<{ path: string; sourcetype: string; index: string; disabled?: boolean }> = [];
  try {
    const config = loadConfig(configDir);
    configuredMonitors = config.monitors;
  } catch {
    // config unavailable — fall back to checkpoint-only display
  }

  const checkpoints = readCheckpoints(dataDir);

  console.log("\n📊 SecOps Forwarder Status\n");

  if (configuredMonitors.length === 0 && checkpoints.size === 0) {
    console.log("   No checkpoint data found.");
    console.log(`   Data directory:  ${dataDir}`);
    console.log(`   Config directory: ${configDir}`);
    console.log("   The forwarder has not been started yet, or no files have been monitored.\n");
    return;
  }

  const pad = (s: string, n: number) => s.length > n ? "…" + s.slice(-(n - 1)) : s.padEnd(n);
  const colPath  = 38;
  const colST    = 18;
  const colState = 10;
  const colOff   = 12;
  const colEvt   = 10;
  const colLast  = 18;

  console.log(
    `  ${pad("File Path", colPath)} ${pad("Sourcetype", colST)} ${"State".padEnd(colState)} ` +
    `${"Offset".padEnd(colOff)} ${"Events".padEnd(colEvt)} Last Active`,
  );
  console.log(
    `  ${"-".repeat(colPath)} ${"-".repeat(colST)} ${"-".repeat(colState)} ` +
    `${"-".repeat(colOff)} ${"-".repeat(colEvt)} ${"-".repeat(colLast)}`,
  );

  // Build a unified list: configured monitors (with checkpoint data if available)
  // plus any checkpoint entries not in inputs.conf (e.g. glob expansions)
  const seen = new Set<string>();
  let totalEvents = 0;

  const printRow = (
    filePath: string,
    sourcetype: string,
    state: string,
    cp: CheckpointEntry | undefined,
  ) => {
    const offset   = cp ? cp.offset.toLocaleString() : "-";
    const events   = cp ? cp.eventsSent.toLocaleString() : "-";
    const lastRead = cp ? ago(cp.lastReadAt) : "-";
    console.log(
      `  ${pad(filePath, colPath)} ${pad(sourcetype, colST)} ${state.padEnd(colState)} ` +
      `${offset.padEnd(colOff)} ${events.padEnd(colEvt)} ${lastRead}`,
    );
    totalEvents += cp?.eventsSent ?? 0;
  };

  for (const m of configuredMonitors) {
    seen.add(m.path);
    const cp    = checkpoints.get(m.path);
    const state = m.disabled ? "disabled" : cp ? "active" : "waiting";
    printRow(m.path, m.sourcetype, state, cp);
  }

  // Any checkpoint paths not covered by inputs.conf (e.g. expanded globs)
  for (const [filePath, cp] of checkpoints) {
    if (seen.has(filePath)) continue;
    printRow(filePath, "-", "active", cp);
    totalEvents += cp.eventsSent; // already summed in printRow above, subtract duplicate
    totalEvents -= cp.eventsSent; // reset (printRow already adds it)
  }

  const activeCount  = [...checkpoints.values()].length;
  const disabledCount = configuredMonitors.filter(m => m.disabled).length;

  console.log(
    `\n  Configured: ${configuredMonitors.length}  |  ` +
    `Active (checkpointed): ${activeCount}  |  ` +
    `Disabled: ${disabledCount}  |  ` +
    `Total events sent: ${totalEvents.toLocaleString()}\n`,
  );
}
