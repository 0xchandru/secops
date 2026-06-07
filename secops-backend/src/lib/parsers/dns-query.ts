import type { ParsedEvent } from "./types";
import { registerParser } from "./registry";

// DNS query log formats:
// 1. BIND/named: "client @0x7f 10.0.0.1#12345 (example.com): query: example.com IN A + (10.0.0.53)"
// 2. Unbound: "[1234:0] info: 10.0.0.1 example.com. A IN"
// 3. Pi-hole/dnsmasq: "query[A] example.com from 10.0.0.1"
// 4. Windows DNS Server: "PACKET 0000003D ... Rcv ... UDP Qry [1234] Q  example.com A"

const BIND_QUERY = /client\s+(?:@\S+\s+)?([\d.]+)#(\d+)\s+\(([^)]+)\):\s*query:\s*(\S+)\s+IN\s+(\S+)/;
const BIND_RESPONSE = /client\s+(?:@\S+\s+)?([\d.]+)#(\d+).*:\s*(?:query|response).*?:\s*(\S+)\s+IN\s+(\S+).*?(NOERROR|NXDOMAIN|SERVFAIL|REFUSED|FORMERR)/i;
const UNBOUND_RE = /\[(\d+):(\d+)\]\s+\S+:\s+([\d.]+)\s+(\S+?)\.\s+(\S+)\s+IN/;
const DNSMASQ_RE = /(?:query|reply|forwarded|cached)\[(\S+)\]\s+(\S+)\s+(?:from|is|to)\s+([\d.]+)/i;

const RESPONSE_CODES: Record<string, string> = {
  NOERROR: "success", NXDOMAIN: "nxdomain", SERVFAIL: "servfail",
  REFUSED: "refused", FORMERR: "formerr",
};

const SUSPICIOUS_TLDS = new Set(["tk", "ml", "ga", "cf", "gq", "xyz", "top", "buzz", "club", "work", "bid", "stream"]);

function domainSeverity(domain: string): { severity: string; tags: string[] } {
  const tags: string[] = [];
  const parts = domain.split(".");
  const tld = parts[parts.length - 1]?.toLowerCase();

  // Long subdomain chain
  if (parts.length > 5) tags.push("long-subdomain-chain");

  // Suspicious TLD
  if (tld && SUSPICIOUS_TLDS.has(tld)) tags.push("suspicious-tld");

  // Very long domain (potential DGA or tunneling)
  if (domain.length > 60) tags.push("potential-dga");

  // High entropy check (simple: count unique chars / length)
  const unique = new Set(domain.replace(/\./g, "")).size;
  if (domain.length > 20 && unique / domain.length > 0.7) tags.push("high-entropy-domain");

  const severity = tags.length >= 2 ? "high" : tags.length === 1 ? "medium" : "info";
  return { severity, tags };
}

registerParser({
  name: "dns-query",
  sourceTypes: ["dns", "bind", "named", "unbound", "dnsmasq", "pihole"],
  priority: 32,
  canParse(raw: string): boolean {
    return BIND_QUERY.test(raw) || UNBOUND_RE.test(raw) || DNSMASQ_RE.test(raw) || BIND_RESPONSE.test(raw);
  },
  parse(raw: string, sourceHost: string): ParsedEvent | null {
    let srcIp: string | undefined;
    let domain: string | undefined;
    let recordType: string | undefined;
    let responseCode: string | undefined;

    // Try BIND response (has response code)
    let m = BIND_RESPONSE.exec(raw);
    if (m) {
      srcIp = m[1];
      domain = m[3];
      recordType = m[4];
      responseCode = m[5]?.toUpperCase();
    }

    // Try BIND query
    if (!domain) {
      m = BIND_QUERY.exec(raw);
      if (m) {
        srcIp = m[1];
        domain = m[4];
        recordType = m[5];
      }
    }

    // Try Unbound
    if (!domain) {
      m = UNBOUND_RE.exec(raw);
      if (m) {
        srcIp = m[3];
        domain = m[4].replace(/\.$/, "");
        recordType = m[5];
      }
    }

    // Try dnsmasq/Pi-hole
    if (!domain) {
      m = DNSMASQ_RE.exec(raw);
      if (m) {
        recordType = m[1];
        domain = m[2];
        srcIp = m[3];
      }
    }

    if (!domain) return null;

    const { severity, tags } = domainSeverity(domain);
    tags.unshift("dns");

    const outcomeStr = responseCode ? (RESPONSE_CODES[responseCode] ?? responseCode) : undefined;

    return {
      sourceType: "dns",
      sourceHost,
      category: "network",
      action: responseCode ? `dns_response_${responseCode.toLowerCase()}` : "dns_query",
      outcome: responseCode === "NOERROR" ? "success" : responseCode ? "failure" : undefined,
      severity,
      eventType: "dns_query",
      message: `DNS ${recordType ?? "?"} query for ${domain}${responseCode ? ` → ${responseCode}` : ""}`,
      rawLog: raw,
      srcIp,
      dnsQuery: domain,
      dnsRecordType: recordType,
      dnsResponseCode: responseCode ?? outcomeStr,
      vendorName: "DNS",
      vendorProduct: "DNS Server",
      tags,
    };
  },
});
