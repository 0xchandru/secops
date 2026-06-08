export interface ExtractedIOC {
  value: string;
  type: "ip" | "domain" | "url" | "md5" | "sha256" | "sha1";
  field: string;
  confidence: "high" | "medium";
}

const PRIVATE_IP_RE = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.|0\.|255\.)/;
const IP_RE = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi;
const SHA256_RE = /\b[a-f0-9]{64}\b/gi;
const SHA1_RE = /\b[a-f0-9]{40}\b/gi;
const MD5_RE = /\b[a-f0-9]{32}\b/gi;

export function isPrivateIp(ip: string): boolean {
  return PRIVATE_IP_RE.test(ip);
}

function detectHashType(hash: string): "sha256" | "sha1" | "md5" {
  if (hash.length === 64) return "sha256";
  if (hash.length === 40) return "sha1";
  return "md5";
}

export function extractIocsFromAlert(alert: {
  sourceIp?: string | null;
  destIp?: string | null;
  description?: string | null;
  context?: Record<string, any> | null;
}): ExtractedIOC[] {
  const seen = new Set<string>();
  const iocs: ExtractedIOC[] = [];

  const add = (ioc: ExtractedIOC) => {
    const key = `${ioc.type}:${ioc.value.toLowerCase()}`;
    if (!seen.has(key)) {
      seen.add(key);
      iocs.push(ioc);
    }
  };

  const ctx = (alert.context ?? {}) as Record<string, any>;

  // Structured fields — high confidence
  const directIp = (field: string, ip?: string | null) => {
    if (ip && !isPrivateIp(ip)) add({ value: ip, type: "ip", field, confidence: "high" });
  };

  directIp("sourceIp", alert.sourceIp);
  directIp("destIp", alert.destIp);
  directIp("srcIp", ctx.srcIp);
  directIp("dstIp", ctx.dstIp);

  if (ctx.dnsQuery && typeof ctx.dnsQuery === "string") {
    add({ value: ctx.dnsQuery, type: "domain", field: "dnsQuery", confidence: "high" });
  }

  if (ctx.fileHash && typeof ctx.fileHash === "string") {
    add({ value: ctx.fileHash, type: detectHashType(ctx.fileHash), field: "fileHash", confidence: "high" });
  }

  if (ctx.httpUrl && typeof ctx.httpUrl === "string") {
    add({ value: ctx.httpUrl, type: "url", field: "httpUrl", confidence: "high" });
  }

  // Extract from description — medium confidence
  const desc = alert.description ?? "";
  for (const m of desc.matchAll(SHA256_RE)) {
    add({ value: m[0], type: "sha256", field: "description", confidence: "medium" });
  }
  for (const m of desc.matchAll(SHA1_RE)) {
    if (m[0].length === 40) add({ value: m[0], type: "sha1", field: "description", confidence: "medium" });
  }
  for (const m of desc.matchAll(MD5_RE)) {
    if (m[0].length === 32) add({ value: m[0], type: "md5", field: "description", confidence: "medium" });
  }
  for (const m of desc.matchAll(IP_RE)) {
    if (!isPrivateIp(m[0])) add({ value: m[0], type: "ip", field: "description", confidence: "medium" });
  }

  return iocs;
}
