import type { ParsedEvent } from "./types";
import { registerParser } from "./registry";

// AWS VPC Flow Log format (v2):
// version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status
// Example: 2 123456789012 eni-abc12345 10.0.1.5 52.94.76.89 49321 443 6 12 840 1620140661 1620140721 ACCEPT OK
const VPC_FLOW_RE = /^(\d+)\s+(\d+)\s+(eni-\S+)\s+([\d.]+)\s+([\d.]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(ACCEPT|REJECT)\s+(\S+)/;

const PROTOCOL_MAP: Record<number, string> = {
  1: "icmp", 6: "tcp", 17: "udp", 47: "gre", 50: "esp", 58: "icmpv6",
};

function isWellKnownPort(port: number): string | undefined {
  const map: Record<number, string> = {
    22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 143: "imap", 443: "https", 445: "smb", 993: "imaps",
    995: "pop3s", 1433: "mssql", 3306: "mysql", 3389: "rdp",
    5432: "postgres", 5900: "vnc", 6379: "redis", 8080: "http-proxy",
    8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
  };
  return map[port];
}

registerParser({
  name: "vpc-flow",
  sourceTypes: ["vpc_flow", "aws_vpc", "vpcflow"],
  priority: 30,
  canParse(raw: string): boolean {
    return VPC_FLOW_RE.test(raw);
  },
  parse(raw: string, sourceHost: string): ParsedEvent | null {
    const m = VPC_FLOW_RE.exec(raw);
    if (!m) return null;

    const [, version, accountId, interfaceId, srcAddr, dstAddr, srcPortStr, dstPortStr, protoNum, packets, bytes, startTs, endTs, action, logStatus] = m;
    const srcPort = Number(srcPortStr);
    const dstPort = Number(dstPortStr);
    const protocol = PROTOCOL_MAP[Number(protoNum)] ?? `proto-${protoNum}`;
    const service = isWellKnownPort(dstPort) ?? isWellKnownPort(srcPort);

    const isReject = action === "REJECT";
    const severity = isReject ? "medium" : "info";

    const tags: string[] = ["vpc-flow", `action:${action.toLowerCase()}`];
    if (service) tags.push(service);
    if (isReject) tags.push("blocked");
    if (dstPort === 22) tags.push("ssh-access");
    if (dstPort === 3389) tags.push("rdp-access");

    return {
      sourceType: "vpc_flow",
      sourceHost: interfaceId,
      category: "network",
      action: `flow_${action.toLowerCase()}`,
      outcome: isReject ? "failure" : "success",
      severity,
      eventType: "vpc_flow_log",
      message: `${srcAddr}:${srcPort} → ${dstAddr}:${dstPort} ${protocol.toUpperCase()} ${action} (${packets} pkts, ${bytes} bytes)`,
      rawLog: raw,
      parsedTimestamp: new Date(Number(startTs) * 1000),
      srcIp: srcAddr,
      srcPort,
      dstIp: dstAddr,
      dstPort,
      protocol,
      bytesIn: isReject ? 0 : Number(bytes),
      bytesOut: 0,
      packetCount: Number(packets),
      direction: "inbound",
      networkInterface: interfaceId,
      vendorName: "AWS",
      vendorProduct: "VPC Flow Logs",
      deviceAction: action,
      tags,
    };
  },
});
