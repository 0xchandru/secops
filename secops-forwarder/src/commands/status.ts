import { existsSync, readdirSync, readFileSync } from "fs";
import { join } from "path";
import type { CheckpointEntry } from "../tail/checkpoint.js";

function readCheckpoints(dataDir: string): CheckpointEntry[] {
  const checkpointDir = join(dataDir, "checkpoints");
  if (!existsSync(checkpointDir)) return [];

  try {
    return readdirSync(checkpointDir)
      .filter(f => f.endsWith(".json"))
      .map(f => {
        try {
          return JSON.parse(readFileSync(join(checkpointDir, f), "utf-8")) as CheckpointEntry;
        } catch {
          return null;
        }
      })
      .filter((e): e is CheckpointEntry => e !== null);
  } catch {
    return [];
  }
}

export function statusCommand(options: { dataDir: string }): void {
  const { dataDir } = options;
  const checkpoints = readCheckpoints(dataDir);

  console.log("\n📊 SecOps Forwarder Status\n");

  if (checkpoints.length === 0) {
    console.log("   No checkpoint data found.");
    console.log(`   Data directory: ${dataDir}`);
    console.log("   The forwarder has not been started yet, or no files have been monitored.\n");
    return;
  }

  const pad = (s: string, n: number) => s.padEnd(n);

  const colPath = 40;
  const colOffset = 12;
  const colEvents = 12;
  const colLast = 20;

  console.log(
    `  ${pad("File Path", colPath)} ${pad("Offset", colOffset)} ${pad("Events Sent", colEvents)} ${pad("Last Read", colLast)}`,
  );
  console.log(
    `  ${"-".repeat(colPath)} ${"-".repeat(colOffset)} ${"-".repeat(colEvents)} ${"-".repeat(colLast)}`,
  );

  let totalEvents = 0;
  for (const cp of checkpoints) {
    const shortPath = cp.path.length > colPath ? "…" + cp.path.slice(-(colPath - 1)) : cp.path;
    const lastRead = cp.lastReadAt ? new Date(cp.lastReadAt).toLocaleString() : "never";
    console.log(
      `  ${pad(shortPath, colPath)} ${pad(cp.offset.toLocaleString(), colOffset)} ${pad(cp.eventsSent.toLocaleString(), colEvents)} ${lastRead}`,
    );
    totalEvents += cp.eventsSent;
  }

  console.log(`\n  Total monitors: ${checkpoints.length}  |  Total events sent: ${totalEvents.toLocaleString()}\n`);
}
