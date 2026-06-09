import { loadConfig } from "../config/parser.js";
import { validateConfig } from "../config/validator.js";
import { existsSync } from "fs";
import { join } from "path";

export function testConfigCommand(options: { configDir: string }): void {
  const { configDir } = options;

  const confs = ["inputs.conf", "outputs.conf", "props.conf", "transforms.conf"];
  console.log(`\n🔍 Validating config directory: ${configDir}\n`);

  for (const conf of confs) {
    const fp = join(configDir, conf);
    const exists = existsSync(fp);
    console.log(`   ${exists ? "✓" : "⚠"} ${conf}${exists ? "" : " (not found — using defaults)"}`);
  }

  console.log("");

  let config;
  try {
    config = loadConfig(configDir);
  } catch (err: any) {
    console.error(`❌ Failed to parse config: ${err.message}`);
    process.exit(1);
  }

  const result = validateConfig(config);

  if (result.errors.length > 0) {
    console.log("❌ Errors:\n");
    for (const e of result.errors) {
      console.log(`   [${e.file}] ${e.field}: ${e.message}`);
    }
  }

  if (result.warnings.length > 0) {
    console.log("⚠  Warnings:\n");
    for (const w of result.warnings) {
      console.log(`   [${w.file}] ${w.field}: ${w.message}`);
    }
  }

  if (result.errors.length === 0 && result.warnings.length === 0) {
    console.log("✅ Configuration is valid — no issues found.\n");
  }

  console.log("\n📋 Summary:\n");
  const server = config.outputs.server || "(not set)";
  const tokenSet = config.outputs.token ? "✓ set" : "✗ not set";
  console.log(`   outputs.conf:`);
  console.log(`     server:       ${server}`);
  console.log(`     token:        ${tokenSet}`);
  console.log(`     batchSize:    ${config.outputs.batchSize}`);
  console.log(`     flushInterval: ${config.outputs.flushIntervalMs}ms`);
  console.log(`     name:         ${config.outputs.forwarderName}`);
  console.log("");
  console.log(`   inputs.conf: ${config.monitors.length} monitor stanza(s)`);
  for (const m of config.monitors) {
    console.log(`     [monitor://${m.path}]`);
    console.log(`       sourcetype=${m.sourcetype}  index=${m.index}${m.disabled ? "  DISABLED" : ""}`);
  }
  console.log("");
  console.log(`   props.conf: ${config.props.size} sourcetype stanza(s)`);
  console.log(`   transforms.conf: ${config.transforms.size} transform stanza(s)`);
  console.log("");

  if (!result.valid) {
    process.exit(1);
  }
}
