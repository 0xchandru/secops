import { parseLogViaRegistry } from "./registry";
import type { ParsedEvent } from "./types";

// Import parser modules to trigger self-registration
import "./syslog";
import "./windows-eventlog";
import "./firewall";
import "./cef";
import "./ecs-json";
import "./leef";
import "./cloudtrail";
import "./apache-nginx";
import "./vpc-flow";
import "./dns-query";
import "./xml";

export type SourceType = "syslog" | "windows_eventlog" | "firewall" | "cef" | "ecs" | "leef" | "cloudtrail" | "apache" | "nginx" | "vpc_flow" | "dns" | "xml" | "generic";

export function parseLog(raw: string, sourceType: string, sourceHost: string): ParsedEvent | null {
  return parseLogViaRegistry(raw, sourceType, sourceHost, parseGeneric);
}

function parseGeneric(raw: string, sourceHost: string, sourceType: string): ParsedEvent {
  let obj: Record<string, any> = {};
  try { obj = JSON.parse(raw); } catch {}

  return {
    sourceType,
    sourceHost: obj.hostname ?? obj.host ?? sourceHost,
    category: obj.category ?? "system",
    action: obj.action ?? obj.event_type ?? obj.eventType ?? "generic_event",
    outcome: obj.outcome,
    severity: obj.severity ?? "info",
    userName: obj.username ?? obj.user,
    srcIp: obj.source_ip ?? obj.src_ip ?? obj.sourceIp,
    dstIp: obj.dest_ip ?? obj.dst_ip ?? obj.destIp,
    processName: obj.process ?? obj.process_name,
    processCommandLine: obj.command_line ?? obj.process_command_line,
    message: obj.message ?? obj.msg ?? raw.slice(0, 500),
    rawLog: raw,
    eventType: obj.event_type ?? sourceType,
  };
}

export { ParsedEvent };
export { registerParser, getRegisteredParsers } from "./registry";
export type { ParserPlugin } from "./registry";
