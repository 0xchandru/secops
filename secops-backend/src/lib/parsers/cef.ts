import { registerParser } from "./registry";
import type { ParsedEvent } from "./types";

// CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
const CEF_HEADER = /^CEF:\s*(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)/;

const CEF_SEVERITY_MAP: Record<string, string> = {
  "0": "info", "1": "info", "2": "info", "3": "info",
  "4": "low", "5": "medium", "6": "medium",
  "7": "high", "8": "high", "9": "critical", "10": "critical",
  low: "low", medium: "medium", high: "high", unknown: "info",
};

function parseExtensions(ext: string): Record<string, string> {
  const result: Record<string, string> = {};
  const re = /(\w+)=((?:(?!\s+\w+=).)*)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(ext)) !== null) {
    result[m[1]] = m[2].trim();
  }
  return result;
}

/**
 * Parse CEF timestamp from rt/end/start extension fields.
 * Handles epoch-ms, "MMM dd yyyy HH:mm:ss.SSS zzz", ISO 8601.
 */
function parseCefTimestamp(ext: Record<string, string>): Date | undefined {
  const raw = ext.rt ?? ext.end ?? ext.start ?? ext.deviceReceiptTime;
  if (!raw) return undefined;
  // Epoch milliseconds (all digits)
  if (/^\d{10,13}$/.test(raw)) {
    const ms = raw.length <= 10 ? parseInt(raw) * 1000 : parseInt(raw);
    const d = new Date(ms);
    if (!isNaN(d.getTime())) return d;
  }
  const d = new Date(raw);
  return isNaN(d.getTime()) ? undefined : d;
}

export function parseCef(raw: string, sourceHost: string): ParsedEvent | null {
  const m = CEF_HEADER.exec(raw);
  if (!m) return null;

  const [, , vendor, product, , signatureId, name, sevStr, extensionStr] = m;
  const ext = parseExtensions(extensionStr);

  const severity = CEF_SEVERITY_MAP[sevStr.toLowerCase()] ?? "info";

  const tags: string[] = ["cef"];
  if (vendor) tags.push(vendor.toLowerCase().replace(/\s+/g, "-"));

  const bytesIn  = ext.in  ? parseInt(ext.in)  : undefined;
  const bytesOut = ext.out ? parseInt(ext.out) : undefined;

  return {
    sourceType: "cef",
    sourceHost: ext.dvchost ?? ext.dvc ?? sourceHost,
    parsedTimestamp: parseCefTimestamp(ext),
    category: ext.cat ?? product?.toLowerCase() ?? "network",
    action: name || signatureId || "cef_event",
    outcome: ext.outcome ?? (ext.act?.toLowerCase().includes("block") ? "failure" : "success"),
    severity,
    userName: ext.suser ?? ext.duser,
    targetUserName: ext.duser,
    userId: ext.suid ?? ext.duid,
    srcIp: ext.src ?? ext.sourceAddress,
    srcPort: ext.spt ? parseInt(ext.spt, 10) : undefined,
    dstIp: ext.dst ?? ext.destinationAddress,
    dstPort: ext.dpt ? parseInt(ext.dpt, 10) : undefined,
    protocol: ext.proto ?? ext.transportProtocol,
    processName: ext.sproc ?? ext.dproc,
    processId: ext.spid ? parseInt(ext.spid) : undefined,
    processCommandLine: ext.cs1 ?? ext.cs2,
    filePath: ext.filePath ?? ext.fname,
    fileName: ext.fname,
    fileHash: ext.fileHash ?? ext.cs3,
    httpMethod: ext.requestMethod,
    httpUrl: ext.request ?? ext.requestUrl,
    httpUserAgent: ext.requestClientApplication,
    bytesIn,
    bytesOut,
    direction: ext.deviceDirection === "0" ? "inbound" : ext.deviceDirection === "1" ? "outbound" : undefined,
    vendorName: vendor || undefined,
    vendorProduct: product || undefined,
    deviceAction: ext.act,
    deviceEventClassId: signatureId || undefined,
    message: ext.msg ?? `${vendor} ${product}: ${name}`,
    rawLog: raw,
    eventType: "cef",
    tags,
  };
}

registerParser({
  name: "cef",
  sourceTypes: ["cef"],
  priority: 10,
  canParse: (raw) => /^CEF:\s*\d+\|/.test(raw),
  parse: (raw, sourceHost) => parseCef(raw, sourceHost),
});
