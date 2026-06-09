import type { ForwarderConfig } from "./types.js";

export interface ValidationError {
  file: string;
  field: string;
  message: string;
}

export interface ValidationResult {
  valid: boolean;
  errors: ValidationError[];
  warnings: ValidationError[];
}

export function validateConfig(config: ForwarderConfig): ValidationResult {
  const errors: ValidationError[] = [];
  const warnings: ValidationError[] = [];

  if (!config.outputs.server) {
    errors.push({ file: "outputs.conf", field: "server", message: "server URL is required" });
  } else {
    try {
      new URL(config.outputs.server);
    } catch {
      errors.push({ file: "outputs.conf", field: "server", message: `"${config.outputs.server}" is not a valid URL` });
    }
  }

  if (!config.outputs.token) {
    errors.push({ file: "outputs.conf", field: "token", message: "API token is required" });
  }

  if (config.outputs.batchSize < 1 || config.outputs.batchSize > 10_000) {
    errors.push({ file: "outputs.conf", field: "batchSize", message: "batchSize must be between 1 and 10,000" });
  }

  if (config.outputs.flushIntervalMs < 100) {
    warnings.push({ file: "outputs.conf", field: "flushInterval", message: "flushInterval below 100ms may cause high CPU usage" });
  }

  if (config.monitors.length === 0) {
    warnings.push({ file: "inputs.conf", field: "[monitor://...]", message: "No monitor stanzas defined — nothing will be forwarded" });
  }

  for (const monitor of config.monitors) {
    if (!monitor.path) {
      errors.push({ file: "inputs.conf", field: "path", message: "monitor stanza has empty path" });
    }
    if (!monitor.sourcetype) {
      warnings.push({ file: "inputs.conf", field: `[monitor://${monitor.path}] sourcetype`, message: "sourcetype not set — defaulting to 'generic'" });
    }
  }

  for (const [name, transform] of config.transforms) {
    if (!transform.regex) {
      errors.push({ file: "transforms.conf", field: `[${name}] REGEX`, message: "REGEX is required for transform stanza" });
    } else {
      try {
        new RegExp(transform.regex);
      } catch (e: any) {
        errors.push({ file: "transforms.conf", field: `[${name}] REGEX`, message: `Invalid regex: ${e.message}` });
      }
    }
  }

  return { valid: errors.length === 0, errors, warnings };
}
