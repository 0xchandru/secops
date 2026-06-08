import type { ParsedEvent } from "./types";
import { registerParser } from "./registry";

// Windows Event ID → severity + category mapping
const WIN_EVENT_SEVERITY: Record<number, string> = {
  // Critical / High auth events
  4625: "high",    // Failed login
  4648: "high",    // Explicit credential logon (pass-the-hash indicator)
  4740: "high",    // Account lockout
  4719: "high",    // System audit policy changed
  4964: "high",    // Special groups logon
  4765: "high",    // SID History added
  4766: "high",    // SID History add attempt failed
  7045: "high",    // New service installed
  4697: "high",    // Service installed in system

  // Medium
  4720: "medium",  // User account created
  4722: "medium",  // User account enabled
  4723: "medium",  // Password change attempt
  4724: "medium",  // Password reset attempt
  4726: "medium",  // User account deleted
  4728: "medium",  // Member added to global group
  4729: "medium",  // Member removed from global group
  4732: "medium",  // Member added to local group
  4733: "medium",  // Member removed from local group
  4756: "medium",  // Member added to universal group
  4757: "medium",  // Member removed from universal group
  4768: "medium",  // Kerberos TGT requested
  4769: "medium",  // Kerberos service ticket requested
  4771: "medium",  // Kerberos pre-auth failed
  4776: "medium",  // NTLM auth attempt

  // Low / Info
  4624: "info",    // Successful logon
  4634: "info",    // Logoff
  4647: "info",    // User initiated logoff
  4663: "info",    // Object access
  4688: "info",    // Process created
  4698: "info",    // Scheduled task created
  4702: "info",    // Scheduled task updated
};

const WIN_EVENT_CATEGORY: Record<number, string> = {
  4624: "authentication", 4625: "authentication", 4634: "authentication",
  4647: "authentication", 4648: "authentication", 4740: "authentication",
  4768: "authentication", 4769: "authentication", 4771: "authentication",
  4776: "authentication", 4964: "authentication",
  4720: "iam", 4722: "iam", 4723: "iam", 4724: "iam", 4726: "iam",
  4728: "iam", 4729: "iam", 4732: "iam", 4733: "iam", 4756: "iam", 4757: "iam",
  4688: "process", 4698: "scheduled_task", 4702: "scheduled_task",
  4697: "system", 7045: "system", 4719: "audit",
  4663: "file", 4765: "iam", 4766: "iam",
};

const WIN_EVENT_ACTION: Record<number, string> = {
  4624: "login_success", 4625: "login_failure", 4634: "logoff",
  4647: "user_logoff", 4648: "explicit_cred_logon", 4740: "account_lockout",
  4720: "user_created", 4722: "user_enabled", 4723: "password_change",
  4724: "password_reset", 4726: "user_deleted", 4728: "group_member_added",
  4729: "group_member_removed", 4732: "local_group_member_added",
  4733: "local_group_member_removed", 4756: "universal_group_member_added",
  4688: "process_created", 4698: "scheduled_task_created",
  4697: "service_installed", 7045: "service_installed",
  4719: "audit_policy_changed", 4768: "kerberos_tgt", 4769: "kerberos_ticket",
  4771: "kerberos_preauth_failed", 4776: "ntlm_auth",
};

const WIN_LEVEL_SEVERITY: Record<number, string> = {
  1: "critical", 2: "high", 3: "medium", 4: "info", 5: "info", 0: "info",
};

function extractXmlText(xml: string, tag: string): string | undefined {
  const re = new RegExp(`<${tag}[^>]*>([^<]*)<\/${tag}>`, "i");
  const m = re.exec(xml);
  return m ? m[1].trim() : undefined;
}

function extractXmlAttr(xml: string, tag: string, attr: string): string | undefined {
  const re = new RegExp(`<${tag}[^>]+${attr}=['"]([^'"]+)['"]`, "i");
  const m = re.exec(xml);
  return m ? m[1].trim() : undefined;
}

function extractEventData(xml: string): Record<string, string> {
  const fields: Record<string, string> = {};
  // <Data Name='FieldName'>value</Data>
  const re = /<Data\s+Name=['"]([^'"]+)['"]>([^<]*)<\/Data>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(xml)) !== null) {
    const key = m[1];
    const val = m[2].trim();
    if (val && val !== "-") fields[key] = val;
  }
  return fields;
}

function extractAllTags(xml: string): Record<string, string> {
  const fields: Record<string, string> = {};
  const re = /<(\w[\w:.-]*)[^>]*>([^<]{1,200})<\/\1>/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(xml)) !== null) {
    const tag = m[1].toLowerCase().replace(/^[a-z]+:/i, "");
    const val = m[2].trim();
    if (val && !fields[tag]) fields[tag] = val;
  }
  return fields;
}

function parseWindowsEventXml(raw: string, sourceHost: string): ParsedEvent | null {
  const eventIdStr = extractXmlText(raw, "EventID");
  if (!eventIdStr) return null;

  const eventId = parseInt(eventIdStr);
  const levelStr = extractXmlText(raw, "Level");
  const level = levelStr ? parseInt(levelStr) : 4;
  const channel = extractXmlText(raw, "Channel") ?? "Unknown";
  const computer = extractXmlText(raw, "Computer") ?? sourceHost;
  const systemTime = extractXmlAttr(raw, "TimeCreated", "SystemTime");
  const parsedTimestamp = systemTime ? new Date(systemTime) : undefined;
  const provider = extractXmlAttr(raw, "Provider", "Name") ?? "Windows";
  const recordId = extractXmlText(raw, "EventRecordID");

  const eventData = extractEventData(raw);

  const severity = WIN_EVENT_SEVERITY[eventId] ?? WIN_LEVEL_SEVERITY[level] ?? "info";
  const category = WIN_EVENT_CATEGORY[eventId] ?? "system";
  const action = WIN_EVENT_ACTION[eventId] ?? `windows_event_${eventId}`;

  const tags: string[] = ["windows", channel.toLowerCase()];
  if (eventId === 4625 || eventId === 4771) tags.push("failed-login");
  if (eventId === 4648 || eventId === 4624) tags.push("logon");
  if (eventId >= 4720 && eventId <= 4726) tags.push("user-management");

  const srcIp = eventData["IpAddress"] && !["127.0.0.1", "::1", "-", "LOCAL"].includes(eventData["IpAddress"])
    ? eventData["IpAddress"] : undefined;
  const srcPort = eventData["IpPort"] ? parseInt(eventData["IpPort"]) : undefined;

  const messageParts: string[] = [];
  messageParts.push(`Windows Event ${eventId} on ${computer}`);
  if (eventData["TargetUserName"] && eventData["TargetUserName"] !== "-") {
    messageParts.push(`User: ${eventData["TargetDomainName"] ? eventData["TargetDomainName"] + "\\" : ""}${eventData["TargetUserName"]}`);
  }
  if (srcIp) messageParts.push(`from ${srcIp}`);
  if (eventData["LogonType"]) messageParts.push(`(LogonType ${eventData["LogonType"]})`);

  return {
    sourceType: "windows_eventlog",
    sourceHost: computer,
    category,
    action,
    outcome: action.endsWith("success") || action.endsWith("created") || action.endsWith("enabled") ? "success"
      : action.endsWith("failure") || action.endsWith("failed") || action.endsWith("lockout") ? "failure"
      : undefined,
    severity,
    parsedTimestamp,
    tags,
    message: messageParts.join(" · "),
    rawLog: raw,
    eventType: `windows_${eventId}`,
    userName: eventData["SubjectUserName"] && eventData["SubjectUserName"] !== "-" ? eventData["SubjectUserName"] : undefined,
    targetUserName: eventData["TargetUserName"] && eventData["TargetUserName"] !== "-" ? eventData["TargetUserName"] : undefined,
    userDomain: eventData["TargetDomainName"] ?? eventData["SubjectDomainName"],
    srcIp,
    srcPort: srcPort && !isNaN(srcPort) ? srcPort : undefined,
    logonType: eventData["LogonType"] ? parseInt(eventData["LogonType"]) : undefined,
    processName: eventData["NewProcessName"] ?? eventData["ProcessName"],
    processId: eventData["NewProcessId"] ? parseInt(eventData["NewProcessId"]) : undefined,
    processCommandLine: eventData["CommandLine"],
    registryKey: eventData["ObjectName"],
    facilityName: channel,
    vendorName: "Microsoft",
    vendorProduct: provider,
    deviceEventClassId: String(eventId),
  };
}

function parseGenericXml(raw: string, sourceHost: string): ParsedEvent | null {
  const tags = extractAllTags(raw);

  const severity = tags["severity"] ?? tags["level"] ?? tags["priority"] ?? "info";
  const normalizedSev = ["critical", "high", "medium", "low", "info"].includes(severity.toLowerCase())
    ? severity.toLowerCase()
    : "info";

  const message = tags["message"] ?? tags["msg"] ?? tags["description"] ?? tags["text"]
    ?? tags["summary"] ?? raw.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim().slice(0, 500);

  return {
    sourceType: "xml",
    sourceHost: tags["hostname"] ?? tags["host"] ?? tags["computer"] ?? sourceHost,
    category: tags["category"] ?? tags["facility"] ?? "system",
    action: tags["action"] ?? tags["eventtype"] ?? tags["type"] ?? "xml_event",
    severity: normalizedSev,
    message,
    rawLog: raw,
    eventType: tags["eventtype"] ?? tags["type"] ?? "xml",
    userName: tags["username"] ?? tags["user"],
    srcIp: tags["sourceaddress"] ?? tags["srcip"] ?? tags["sourceip"] ?? tags["src"],
    dstIp: tags["destinationaddress"] ?? tags["dstip"] ?? tags["destip"] ?? tags["dst"],
    processName: tags["processname"] ?? tags["process"] ?? tags["application"],
    tags: ["xml"],
  };
}

const WIN_EVENT_NS_RE = /xmlns[^=]*=["'][^"']*microsoft[^"']*win[^"']*["']/i;
const WIN_EVENT_TAG_RE = /<Event[\s>]/i;

registerParser({
  name: "xml",
  sourceTypes: ["xml", "windows_xml", "winevent"],
  priority: 9,
  canParse: (raw) => {
    const trimmed = raw.trimStart();
    return trimmed.startsWith("<?xml") || trimmed.startsWith("<Event") || (trimmed.startsWith("<") && /<\w+[^>]*>/.test(trimmed));
  },
  parse: (raw: string, sourceHost: string): ParsedEvent | null => {
    if (WIN_EVENT_TAG_RE.test(raw) || WIN_EVENT_NS_RE.test(raw)) {
      return parseWindowsEventXml(raw, sourceHost);
    }
    return parseGenericXml(raw, sourceHost);
  },
});

export { parseWindowsEventXml, parseGenericXml };
