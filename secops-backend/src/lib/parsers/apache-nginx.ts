import type { ParsedEvent } from "./types";
import { registerParser } from "./registry";

// Common Log Format (CLF) / Combined Log Format
// Examples:
//   192.168.1.100 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
//   192.168.1.100 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 4523 "http://example.com/" "Mozilla/5.0"
const CLF_RE = /^(\S+) (\S+) (\S+) \[([^\]]+)\] "(\S+) (\S+) \S+" (\d{3}) (\d+|-)(?: "([^"]*)" "([^"]*)")?/;

// Nginx error log
// Example: 2024/01/15 08:23:45 [error] 1234#0: *5678 upstream timed out, client: 10.0.0.1, server: example.com
const NGINX_ERR_RE = /^(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] (\d+)#\d+:.*client:\s*([\d.]+)/;

function parseAccessTimestamp(ts: string): Date | undefined {
  // "10/Oct/2000:13:55:36 -0700"
  try {
    const cleaned = ts.replace(/(\d{2})\/(\w{3})\/(\d{4}):(\d{2}:\d{2}:\d{2})/, "$2 $1, $3 $4");
    const d = new Date(cleaned);
    if (!isNaN(d.getTime())) return d;
  } catch {}
  return undefined;
}

function severityFromStatus(code: number): string {
  if (code >= 500) return "high";
  if (code >= 400) return "medium";
  if (code >= 300) return "low";
  return "info";
}

function categoryFromStatus(code: number): string {
  if (code >= 500) return "web_error";
  if (code === 401 || code === 403) return "authentication";
  if (code >= 400) return "web_error";
  return "web_access";
}

function parseCLF(raw: string, sourceHost: string): ParsedEvent | null {
  const m = CLF_RE.exec(raw);
  if (!m) return null;

  const [, srcIp, , user, timestamp, method, url, statusStr, bytesStr, referrer, userAgent] = m;
  const status = Number(statusStr);
  const bytes = bytesStr === "-" ? 0 : Number(bytesStr);

  return {
    sourceType: "apache",
    sourceHost,
    category: categoryFromStatus(status),
    action: `${method} ${statusStr}`,
    outcome: status < 400 ? "success" : "failure",
    severity: severityFromStatus(status),
    eventType: "http_access",
    message: `${method} ${url} ${statusStr}`,
    rawLog: raw,
    parsedTimestamp: parseAccessTimestamp(timestamp),
    srcIp,
    userName: user !== "-" ? user : undefined,
    httpMethod: method,
    httpUrl: url,
    httpStatusCode: status,
    httpUserAgent: userAgent,
    httpReferrer: referrer && referrer !== "-" ? referrer : undefined,
    bytesOut: bytes,
    vendorName: "Apache/Nginx",
    vendorProduct: "Web Server",
    tags: status >= 500 ? ["server-error"] : status === 401 || status === 403 ? ["auth-failure"] : [],
  };
}

function parseNginxError(raw: string, sourceHost: string): ParsedEvent | null {
  const m = NGINX_ERR_RE.exec(raw);
  if (!m) return null;

  const [, timestamp, level, pid, clientIp] = m;
  const severityMap: Record<string, string> = {
    emerg: "critical", alert: "critical", crit: "critical",
    error: "high", warn: "medium", notice: "low", info: "info", debug: "info",
  };

  return {
    sourceType: "nginx",
    sourceHost,
    category: "web_error",
    action: `nginx_${level}`,
    outcome: "failure",
    severity: severityMap[level] ?? "medium",
    eventType: "nginx_error",
    message: raw.slice(raw.indexOf("]") + 2).trim(),
    rawLog: raw,
    parsedTimestamp: new Date(timestamp.replace(/\//g, "-")),
    srcIp: clientIp,
    processId: Number(pid),
    vendorName: "Nginx",
    vendorProduct: "Nginx",
    tags: ["web-error"],
  };
}

registerParser({
  name: "apache-nginx",
  sourceTypes: ["apache", "nginx", "httpd", "web_access"],
  priority: 35,
  canParse(raw: string): boolean {
    return CLF_RE.test(raw) || NGINX_ERR_RE.test(raw);
  },
  parse(raw: string, sourceHost: string): ParsedEvent | null {
    return parseCLF(raw, sourceHost) ?? parseNginxError(raw, sourceHost);
  },
});
