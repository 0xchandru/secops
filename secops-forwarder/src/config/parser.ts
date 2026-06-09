import { readFileSync, existsSync } from "fs";
import { join } from "path";
import type { ForwarderConfig, MonitorStanza, OutputsConfig, PropsStanza, TransformStanza } from "./types.js";

export interface IniSection {
  name: string;
  entries: Map<string, string>;
}

export function parseIniFile(filePath: string): IniSection[] {
  if (!existsSync(filePath)) return [];
  const content = readFileSync(filePath, "utf-8");
  const sections: IniSection[] = [];
  let current: IniSection | null = null;

  for (const rawLine of content.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;

    if (line.startsWith("[") && line.endsWith("]")) {
      current = { name: line.slice(1, -1).trim(), entries: new Map() };
      sections.push(current);
      continue;
    }

    if (current && line.includes("=")) {
      const eqIdx = line.indexOf("=");
      const key = line.slice(0, eqIdx).trim().toLowerCase();
      const value = line.slice(eqIdx + 1).trim();
      current.entries.set(key, value);
    }
  }

  return sections;
}

export function parseInputsConf(configDir: string): MonitorStanza[] {
  const sections = parseIniFile(join(configDir, "inputs.conf"));
  const monitors: MonitorStanza[] = [];

  for (const section of sections) {
    if (!section.name.startsWith("monitor://")) continue;
    const rawPath = section.name.slice("monitor://".length);

    monitors.push({
      path: rawPath,
      sourcetype: section.entries.get("sourcetype") ?? "generic",
      index: section.entries.get("index") ?? "main",
      host: section.entries.get("host"),
      followTail: section.entries.get("followtail") === "1" || section.entries.get("followtail") === "true",
      disabled: section.entries.get("disabled") === "1" || section.entries.get("disabled") === "true",
      ignoreOlderThan: section.entries.get("ignoreolderthan"),
      whitelistRegex: section.entries.get("whitelist"),
      blacklistRegex: section.entries.get("blacklist"),
    });
  }

  return monitors;
}

export function parseOutputsConf(configDir: string): OutputsConfig {
  const sections = parseIniFile(join(configDir, "outputs.conf"));
  const entries = sections[0]?.entries ?? new Map<string, string>();

  return {
    server: entries.get("server") ?? "http://localhost:8080",
    token: entries.get("token") ?? "",
    batchSize: Number(entries.get("batchsize") ?? entries.get("batch_size") ?? 100),
    flushIntervalMs: Number(entries.get("flushinterval") ?? entries.get("flush_interval") ?? 5000),
    maxRetries: Number(entries.get("maxretries") ?? entries.get("max_retries") ?? 5),
    retryBaseMs: Number(entries.get("retrybasems") ?? entries.get("retry_base_ms") ?? 1000),
    heartbeatIntervalMs: Number(entries.get("heartbeatinterval") ?? entries.get("heartbeat_interval") ?? 30000),
    forwarderName: entries.get("name") ?? entries.get("forwarder_name") ?? `forwarder-${process.pid}`,
  };
}

export function parsePropsConf(configDir: string): Map<string, PropsStanza> {
  const sections = parseIniFile(join(configDir, "props.conf"));
  const map = new Map<string, PropsStanza>();

  for (const section of sections) {
    const transforms = section.entries.get("transforms")?.split(",").map(t => t.trim()).filter(Boolean) ?? [];
    map.set(section.name, {
      sourcetype: section.name,
      timePrefix: section.entries.get("time_prefix") ?? section.entries.get("timeprefix"),
      timeFormat: section.entries.get("time_format") ?? section.entries.get("timeformat"),
      lineBreaker: section.entries.get("line_breaker") ?? section.entries.get("linebreaker"),
      shouldLinemerge: section.entries.get("should_linemerge") !== "false",
      maxLineLength: Number(section.entries.get("maxlinelength") ?? 10000),
      transforms,
    });
  }

  return map;
}

export function parseTransformsConf(configDir: string): Map<string, TransformStanza> {
  const sections = parseIniFile(join(configDir, "transforms.conf"));
  const map = new Map<string, TransformStanza>();

  for (const section of sections) {
    map.set(section.name, {
      name: section.name,
      regex: section.entries.get("regex") ?? "",
      format: section.entries.get("format"),
      writeMeta: section.entries.get("write_meta") === "true" || section.entries.get("writemeta") === "true",
      defaultValue: section.entries.get("default"),
    });
  }

  return map;
}

export function loadConfig(configDir: string): ForwarderConfig {
  return {
    monitors: parseInputsConf(configDir),
    outputs: parseOutputsConf(configDir),
    props: parsePropsConf(configDir),
    transforms: parseTransformsConf(configDir),
  };
}

export type { ForwarderConfig };
