import { registerParser } from "./registry";
import type { ParsedEvent } from "./types";

// Elastic Common Schema (ECS) JSON parser
// Handles ECS-formatted JSON logs from Elastic Agent, Filebeat, etc.

const ECS_SEVERITY_MAP: Record<string, string> = {
  debug: "info", informational: "info", info: "info",
  notice: "low", warning: "medium", warn: "medium",
  error: "high", err: "high",
  critical: "critical", alert: "critical", emergency: "critical",
};

export function parseEcsJson(raw: string, sourceHost: string): ParsedEvent | null {
  let obj: Record<string, any>;
  try { obj = JSON.parse(raw); } catch { return null; }

  // ECS events should have at minimum an ecs.version or event.kind field
  if (!obj.ecs?.version && !obj.event?.kind && !obj.event?.category) return null;

  const event    = obj.event ?? {};
  const source   = obj.source ?? {};
  const dest     = obj.destination ?? {};
  const user     = obj.user ?? {};
  const process  = obj.process ?? {};
  const host     = obj.host ?? {};
  const network  = obj.network ?? {};
  const http     = obj.http ?? {};
  const dns      = obj.dns ?? {};
  const file     = obj.file ?? {};
  const url      = obj.url ?? {};
  const registry = obj.registry ?? {};
  const observer = obj.observer ?? {};

  const logLevel = (obj.log?.level ?? event.severity_name ?? event.severity ?? "info").toString().toLowerCase();
  const severity = ECS_SEVERITY_MAP[logLevel] ?? "info";

  // Parse @timestamp
  let parsedTimestamp: Date | undefined;
  const ts = obj["@timestamp"] ?? event.created ?? event.start;
  if (ts) {
    const d = new Date(ts);
    if (!isNaN(d.getTime())) parsedTimestamp = d;
  }

  // Build tags from event.category array + event.type array + host.os.family
  const tags: string[] = ["ecs"];
  if (Array.isArray(event.category)) event.category.forEach((c: string) => tags.push(c));
  if (Array.isArray(event.type)) event.type.forEach((t: string) => tags.push(t));
  if (host.os?.family) tags.push(host.os.family);

  const userAgent = obj.user_agent?.original ?? http.request?.body?.content;

  return {
    sourceType: "ecs",
    sourceHost: host.hostname ?? host.name ?? host.ip?.[0] ?? sourceHost,
    parsedTimestamp,
    category: Array.isArray(event.category) ? event.category[0] : (event.category ?? "process"),
    action: event.action ?? event.type?.[0] ?? event.kind ?? "ecs_event",
    outcome: event.outcome,
    severity,
    userName: user.name ?? user.id,
    userDomain: user.domain,
    targetUserName: user.target?.name,
    userId: user.id,
    srcIp: source.ip ?? source.address,
    srcPort: source.port,
    dstIp: dest.ip ?? dest.address,
    dstPort: dest.port,
    protocol: network.protocol ?? network.transport,
    bytesIn: source.bytes ?? network.bytes,
    bytesOut: dest.bytes,
    direction: network.direction,
    packetCount: source.packets ?? network.packets,
    processName: process.name ?? process.executable,
    processId: process.pid,
    processCommandLine: process.command_line,
    parentProcessName: process.parent?.name ?? process.parent?.executable,
    parentProcessId: process.parent?.pid,
    // HTTP context
    httpMethod: http.request?.method,
    httpUrl: url.full ?? url.original,
    httpStatusCode: http.response?.status_code,
    httpUserAgent: userAgent,
    httpReferrer: http.request?.referrer,
    // DNS context
    dnsQuery: dns.question?.name,
    dnsResponseCode: dns.response_code,
    dnsRecordType: dns.question?.type,
    // File context
    fileName: file.name,
    filePath: file.path,
    fileHash: file.hash?.sha256 ?? file.hash?.sha1 ?? file.hash?.md5,
    // Registry
    registryKey: registry.path ?? registry.key,
    registryValue: registry.value,
    // Vendor
    vendorName: observer.vendor ?? obj.agent?.type,
    vendorProduct: observer.product ?? observer.type,
    message: obj.message ?? event.reason ?? raw.slice(0, 500),
    rawLog: raw,
    eventType: event.kind ?? "ecs",
    tags,
  };
}

registerParser({
  name: "ecs-json",
  sourceTypes: ["ecs", "ecs_json", "elastic"],
  priority: 10,
  canParse: (raw) => {
    if (!raw.startsWith("{")) return false;
    try {
      const obj = JSON.parse(raw);
      return !!(obj.ecs?.version || obj.event?.kind || obj.event?.category);
    } catch { return false; }
  },
  parse: (raw, sourceHost) => parseEcsJson(raw, sourceHost),
});
