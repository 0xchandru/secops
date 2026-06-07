import { registerParser } from "./registry";
import type { ParsedEvent } from "./types";

// IBM QRadar LEEF (Log Event Extended Format) parser
// Format: LEEF:Version|Vendor|Product|Version|EventID|<tab-separated key=value pairs>

const LEEF_HEADER = /^LEEF:\s*(\d+(?:\.\d+)?)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)/s;

const LEEF_SEVERITY_MAP: Record<string, string> = {
  "1": "info", "2": "info", "3": "low", "4": "low",
  "5": "medium", "6": "medium", "7": "high", "8": "high",
  "9": "critical", "10": "critical",
};

function parseLeefExtensions(ext: string, version: string): Record<string, string> {
  const result: Record<string, string> = {};
  let sep = "\t";
  if (version.startsWith("2") && ext.length > 0 && !ext.startsWith("src=") && !ext.startsWith("dst=")) {
    const customSepMatch = ext.match(/^(.+?)(?=\w+=)/);
    if (customSepMatch) {
      sep = customSepMatch[1];
      ext = ext.slice(sep.length);
    }
  }

  const pairs = ext.split(sep);
  for (const pair of pairs) {
    const idx = pair.indexOf("=");
    if (idx > 0) {
      result[pair.slice(0, idx).trim()] = pair.slice(idx + 1).trim();
    }
  }
  return result;
}

function parseLeefTimestamp(ext: Record<string, string>): Date | undefined {
  const raw = ext.devTime ?? ext.devTimeFormat ?? ext.calLanguage;
  if (!raw) return undefined;
  // Epoch ms
  if (/^\d{10,13}$/.test(raw)) {
    const ms = raw.length <= 10 ? parseInt(raw) * 1000 : parseInt(raw);
    const d = new Date(ms);
    if (!isNaN(d.getTime())) return d;
  }
  const d = new Date(raw);
  return isNaN(d.getTime()) ? undefined : d;
}

export function parseLeef(raw: string, sourceHost: string): ParsedEvent | null {
  const m = LEEF_HEADER.exec(raw);
  if (!m) return null;

  const [, version, vendor, product, , eventId, extensionStr] = m;
  const ext = parseLeefExtensions(extensionStr, version);

  const severity = LEEF_SEVERITY_MAP[ext.sev ?? ext.severity ?? "1"] ?? "info";

  const tags: string[] = ["leef"];
  if (vendor) tags.push(vendor.toLowerCase().replace(/\s+/g, "-"));

  const bytesIn  = ext.srcBytes ? parseInt(ext.srcBytes) : undefined;
  const bytesOut = ext.dstBytes ? parseInt(ext.dstBytes) : undefined;

  return {
    sourceType: "leef",
    sourceHost: ext.devName ?? ext.identHostName ?? sourceHost,
    parsedTimestamp: parseLeefTimestamp(ext),
    category: ext.cat ?? product?.toLowerCase() ?? "network",
    action: eventId || ext.action || "leef_event",
    outcome: ext.outcome ?? (ext.action?.toLowerCase().includes("deny") ? "failure" : "success"),
    severity,
    userName: ext.usrName ?? ext.srcUserName ?? ext.dstUserName,
    targetUserName: ext.dstUserName,
    userId: ext.identUserId,
    srcIp: ext.src ?? ext.srcIP,
    srcPort: ext.srcPort ? parseInt(ext.srcPort, 10) : undefined,
    dstIp: ext.dst ?? ext.dstIP,
    dstPort: ext.dstPort ? parseInt(ext.dstPort, 10) : undefined,
    protocol: ext.proto ?? ext.protocol,
    bytesIn,
    bytesOut,
    direction: ext.direction,
    processName: ext.srcProcName ?? ext.dstProcName,
    processId: ext.srcProcId ? parseInt(ext.srcProcId) : undefined,
    httpMethod: ext.reqMethod,
    httpUrl: ext.url ?? ext.reqUrl,
    httpStatusCode: ext.respCode ? parseInt(ext.respCode) : undefined,
    httpUserAgent: ext.userAgent,
    dnsQuery: ext.queryDomain ?? ext.domainOrigin,
    fileName: ext.fileName,
    filePath: ext.filePath,
    fileHash: ext.fileHash ?? ext.md5 ?? ext.sha256,
    vendorName: vendor || undefined,
    vendorProduct: product || undefined,
    deviceAction: ext.action,
    deviceEventClassId: eventId || undefined,
    message: ext.msg ?? `${vendor} ${product}: ${eventId}`,
    rawLog: raw,
    eventType: "leef",
    tags,
  };
}

registerParser({
  name: "leef",
  sourceTypes: ["leef", "qradar"],
  priority: 10,
  canParse: (raw) => /^LEEF:\s*\d/.test(raw),
  parse: (raw, sourceHost) => parseLeef(raw, sourceHost),
});
