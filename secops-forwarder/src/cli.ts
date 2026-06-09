import { resolve } from "path";
import { startCommand } from "./commands/start.js";
import { statusCommand } from "./commands/status.js";
import { testConfigCommand } from "./commands/test-config.js";

const VERSION = "1.0.0";

function usage(): void {
  console.log(`
secops-forwarder ${VERSION} — Splunk-style universal log forwarder

Usage:
  secops-forwarder <command> [options]

Commands:
  start          Start the forwarder (monitors files and ships events)
  status         Show monitor status and checkpoint positions
  test-config    Validate all .conf files and report errors

Options:
  --config-dir   Directory containing inputs.conf, outputs.conf, etc.
                 (default: ./conf)
  --data-dir     Directory for checkpoint files and state
                 (default: ./.secops-forwarder)
  --verbose, -v  Show each forwarded event in real time
  --help, -h     Show this help message
  --version      Print version

Examples:
  secops-forwarder start
  secops-forwarder start --config-dir /etc/secops-forwarder/conf
  secops-forwarder test-config --config-dir ./conf
  secops-forwarder status
`);
}

function parseArgs(argv: string[]): {
  command: string;
  configDir: string;
  dataDir: string;
  verbose: boolean;
} {
  const args = argv.slice(2);
  let command = "";
  let configDir = "./conf";
  let dataDir = "./.secops-forwarder";
  let verbose = false;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--help" || arg === "-h") {
      usage();
      process.exit(0);
    }
    if (arg === "--version") {
      console.log(`secops-forwarder ${VERSION}`);
      process.exit(0);
    }
    if (arg === "--verbose" || arg === "-v") {
      verbose = true;
    } else if (arg === "--config-dir" && args[i + 1]) {
      configDir = args[++i];
    } else if (arg === "--data-dir" && args[i + 1]) {
      dataDir = args[++i];
    } else if (!arg.startsWith("--") && !command) {
      command = arg;
    }
  }

  return {
    command,
    configDir: resolve(configDir),
    dataDir: resolve(dataDir),
    verbose,
  };
}

async function main(): Promise<void> {
  const { command, configDir, dataDir, verbose } = parseArgs(process.argv);

  switch (command) {
    case "start":
      await startCommand({ configDir, dataDir, verbose });
      break;

    case "status":
      statusCommand({ configDir, dataDir });
      break;

    case "test-config":
      testConfigCommand({ configDir });
      break;

    case "":
    case "help":
      usage();
      break;

    default:
      console.error(`Unknown command: "${command}"\n`);
      usage();
      process.exit(1);
  }
}

main().catch(err => {
  console.error(`Fatal error: ${err.message}`);
  process.exit(1);
});
