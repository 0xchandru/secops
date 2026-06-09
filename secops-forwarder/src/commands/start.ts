import { join } from "path";
import { loadConfig } from "../config/parser.js";
import { validateConfig } from "../config/validator.js";
import { CheckpointStore } from "../tail/checkpoint.js";
import { FileTailMonitor } from "../tail/monitor.js";
import { applyProps } from "../pipeline/props.js";
import { applyTransforms, buildEvent } from "../pipeline/transforms.js";
import { ForwarderClient } from "../output/client.js";
import type { TailEvent } from "../tail/monitor.js";

export async function startCommand(options: { configDir: string; dataDir: string; verbose: boolean }): Promise<void> {
  const { configDir, dataDir, verbose } = options;

  const config = loadConfig(configDir);
  const validation = validateConfig(config);

  if (!validation.valid) {
    console.error("❌ Configuration has errors:");
    for (const e of validation.errors) {
      console.error(`   ${e.file} > ${e.field}: ${e.message}`);
    }
    process.exit(1);
  }

  for (const w of validation.warnings) {
    console.warn(`⚠  ${w.file} > ${w.field}: ${w.message}`);
  }

  const serverUrl = config.outputs.server.replace(/\/$/, "");
  console.log(`\n🚀 SecOps Forwarder starting`);
  console.log(`   Server:    ${serverUrl}`);
  console.log(`   Name:      ${config.outputs.forwarderName}`);
  console.log(`   Monitors:  ${config.monitors.filter(m => !m.disabled).length} active`);
  console.log(`   Batch:     ${config.outputs.batchSize} events / ${config.outputs.flushIntervalMs}ms`);
  console.log("");

  const checkpoints = new CheckpointStore(dataDir);
  const client = new ForwarderClient(config.outputs);
  client.start();

  const monitor = new FileTailMonitor(checkpoints);

  monitor.onLine((event: TailEvent) => {
    const props = config.props.get(event.sourcetype);
    const parsed = applyProps(event.line, props);
    const transformNames = props?.transforms ?? [];
    const transformed = applyTransforms(parsed, transformNames, config.transforms);
    const built = buildEvent(transformed, {
      sourcetype: event.sourcetype,
      index: event.index,
      host: event.host,
      source: event.source,
    });

    if (verbose) {
      process.stdout.write(`  → [${event.sourcetype}] ${event.line.slice(0, 80)}\n`);
    }

    client.push(built as any);
  });

  for (const stanza of config.monitors) {
    if (stanza.disabled) {
      console.log(`   ⏸  Skipped (disabled): ${stanza.path}`);
      continue;
    }
    const props = config.props.get(stanza.sourcetype);
    const enrichedStanza = {
      ...stanza,
      lineBreaker: props?.lineBreaker ?? stanza.lineBreaker,
    };
    console.log(`   👁  Monitoring: ${stanza.path} (${stanza.sourcetype})`);
    monitor.startMonitor(enrichedStanza);
  }

  const heartbeatInterval = setInterval(async () => {
    const stats = monitor.getMonitorStats();
    await client.sendHeartbeat(stats);

    const cs = client.getStats();
    if (verbose) {
      process.stdout.write(`\r   EPS: ${cs.eps.toFixed(1)}  Sent: ${cs.totalSent}  Queued: ${cs.queued}  Failed: ${cs.totalFailed}   `);
    }
  }, config.outputs.heartbeatIntervalMs);

  const shutdown = async () => {
    console.log("\n\n⏹  Shutting down forwarder...");
    clearInterval(heartbeatInterval);
    monitor.stop();
    await client.drainAndStop();
    const stats = client.getStats();
    console.log(`   Total sent:   ${stats.totalSent}`);
    console.log(`   Total failed: ${stats.totalFailed}`);
    console.log("   Checkpoints saved. Goodbye.");
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  console.log("✅ Forwarder running. Press Ctrl+C to stop.\n");

  await new Promise(() => {});
}
