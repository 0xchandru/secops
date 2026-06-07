import type { ParsedEvent } from "./types";
import { registerParser } from "./registry";

// iptables / nftables kernel log
const IPTABLES_RE = /\b(ACCEPT|DROP|REJECT)\b.*?SRC=([\d.a-f:]+).*?DST=([\d.a-f:]+).*?PROTO=(\S+)(?:.*?SPT=(\d+))?(?:.*?DPT=(\d+))?/i;

// pf (BSD) log: pass/block
const PF_RE = /\b(pass|block)\b.*?\b(in|out)\b on (\S+):.*?(\d+\.\d+\.\d+\.\d+)\.(\d+)\s*>\s*(\d+\.\d+\.\d+\.\d+)\.(\d+).*?proto\s+(\S+)/i;

const ACTION_MAP: Record<string, string> = {
  ACCEPT: "connection_allowed",
  DROP:   "connection_blocked",
  REJECT: "connection_rejected",
  pass:   "connection_allowed",
  block:  "connection_blocked",
};

function parseSeverity(action: string): string {
  const a = action.toUpperCase();
  if (a === "ACCEPT" || a === "PASS") return "info";
  return "low";
}

// Extract optional fields from iptables log
const LEN_RE   = /\bLEN=(\d+)/;
const TTL_RE   = /\bTTL=(\d+)/;
const IN_RE    = /\bIN=(\S+)/;
const OUT_RE   = /\bOUT=(\S+)/;
const MAC_RE   = /\bMAC=(\S+)/;
const MARK_RE  = /\bMARK=(\S+)/;

export function parseFirewall(raw: string, sourceHost: string): ParsedEvent | null {
  // Try iptables/nftables first
  let m = IPTABLES_RE.exec(raw);
  if (m) {
    const [, action, srcIp, dstIp, protocol, srcPortStr, dstPortStr] = m;
    const actionNorm = ACTION_MAP[action] ?? "firewall_event";
    const inIface  = IN_RE.exec(raw)?.[1];
    const outIface = OUT_RE.exec(raw)?.[1];
    const lenMatch = LEN_RE.exec(raw);
    const bytesIn  = lenMatch ? parseInt(lenMatch[1]) : undefined;

    const tags: string[] = ["firewall", "iptables"];
    if (action !== "ACCEPT") tags.push("blocked");

    return {
      sourceType: "firewall",
      sourceHost,
      category: "firewall",
      action: actionNorm,
      outcome: action === "ACCEPT" ? "success" : "failure",
      severity: parseSeverity(action),
      srcIp,
      dstIp,
      protocol: protocol.toLowerCase(),
      srcPort: srcPortStr ? parseInt(srcPortStr) : undefined,
      dstPort: dstPortStr ? parseInt(dstPortStr) : undefined,
      direction: inIface ? "inbound" : outIface ? "outbound" : undefined,
      networkInterface: inIface || outIface,
      bytesIn,
      eventType: "firewall",
      vendorName: "Linux",
      vendorProduct: "iptables",
      deviceAction: action,
      message: `${action}: ${srcIp}:${srcPortStr ?? "*"} → ${dstIp}:${dstPortStr ?? "*"} (${protocol})`,
      rawLog: raw,
      tags,
    };
  }

  // Try pf log
  m = PF_RE.exec(raw);
  if (m) {
    const [, action, dir, iface, srcIp, srcPort, dstIp, dstPort, proto] = m;
    const actionNorm = ACTION_MAP[action.toLowerCase()] ?? "firewall_event";
    const tags: string[] = ["firewall", "pf"];
    if (action.toLowerCase() === "block") tags.push("blocked");

    return {
      sourceType: "firewall",
      sourceHost,
      category: "firewall",
      action: actionNorm,
      outcome: action.toLowerCase() === "pass" ? "success" : "failure",
      severity: parseSeverity(action),
      srcIp,
      dstIp,
      protocol: proto.toLowerCase(),
      srcPort: parseInt(srcPort),
      dstPort: parseInt(dstPort),
      direction: dir === "in" ? "inbound" : "outbound",
      networkInterface: iface,
      eventType: "firewall",
      vendorName: "BSD",
      vendorProduct: "pf",
      deviceAction: action,
      message: `${action} ${dir} on ${iface}: ${srcIp}:${srcPort} → ${dstIp}:${dstPort} (${proto})`,
      rawLog: raw,
      tags,
    };
  }

  return null;
}

registerParser({
  name: "firewall",
  sourceTypes: ["firewall", "iptables", "nftables", "pf"],
  priority: 10,
  canParse: (raw) => /\b(ACCEPT|DROP|REJECT)\b.*SRC=/.test(raw) || /\b(pass|block)\b.*\bon\b/.test(raw),
  parse: (raw, sourceHost) => parseFirewall(raw, sourceHost),
});
