import type { ParsedEvent } from "./types";
import { registerParser } from "./registry";

// Comprehensive Windows EventID mapping
const EVENT_MAP: Record<number, { category: string; action: string; severity: string }> = {
  // --- Authentication ---
  4624: { category: "authentication", action: "login_success",        severity: "info" },
  4625: { category: "authentication", action: "login_failure",        severity: "medium" },
  4634: { category: "authentication", action: "logoff",               severity: "info" },
  4647: { category: "authentication", action: "user_initiated_logoff", severity: "info" },
  4648: { category: "authentication", action: "explicit_logon",       severity: "low" },
  4672: { category: "authentication", action: "special_privilege_logon", severity: "low" },
  4776: { category: "authentication", action: "ntlm_authentication",  severity: "info" },
  4768: { category: "authentication", action: "kerberos_tgt_request", severity: "info" },
  4769: { category: "authentication", action: "kerberos_service_ticket", severity: "info" },
  4771: { category: "authentication", action: "kerberos_preauth_failure", severity: "medium" },

  // --- Process tracking ---
  4688: { category: "process",        action: "process_create",       severity: "info" },
  4689: { category: "process",        action: "process_terminate",    severity: "info" },
  1:    { category: "process",        action: "process_create",       severity: "info" },   // Sysmon
  3:    { category: "network",        action: "network_connection",   severity: "info" },   // Sysmon
  5:    { category: "process",        action: "process_terminate",    severity: "info" },   // Sysmon
  7:    { category: "process",        action: "image_load",           severity: "info" },   // Sysmon
  8:    { category: "process",        action: "create_remote_thread", severity: "medium" }, // Sysmon
  10:   { category: "process",        action: "process_access",       severity: "low" },    // Sysmon
  11:   { category: "file",           action: "file_create",          severity: "info" },   // Sysmon
  12:   { category: "registry",       action: "registry_create",      severity: "info" },   // Sysmon
  13:   { category: "registry",       action: "registry_modify",      severity: "low" },    // Sysmon
  15:   { category: "file",           action: "file_stream_create",   severity: "low" },    // Sysmon
  22:   { category: "dns",            action: "dns_query",            severity: "info" },   // Sysmon

  // --- Object access ---
  4657: { category: "registry",       action: "registry_modify",      severity: "low" },
  4660: { category: "file",           action: "file_delete",          severity: "low" },
  4663: { category: "file",           action: "file_access",          severity: "info" },

  // --- Account management ---
  4720: { category: "iam",            action: "user_created",         severity: "medium" },
  4722: { category: "iam",            action: "user_enabled",         severity: "medium" },
  4723: { category: "iam",            action: "password_change_attempt", severity: "low" },
  4724: { category: "iam",            action: "password_reset",       severity: "medium" },
  4725: { category: "iam",            action: "user_disabled",        severity: "medium" },
  4726: { category: "iam",            action: "user_deleted",         severity: "high" },
  4728: { category: "iam",            action: "member_added_to_global_group", severity: "medium" },
  4732: { category: "iam",            action: "member_added_to_local_group",  severity: "medium" },
  4756: { category: "iam",            action: "member_added_to_universal_group", severity: "medium" },

  // --- Policy / System ---
  4670: { category: "system",         action: "permissions_changed",  severity: "low" },
  4697: { category: "system",         action: "service_install",      severity: "medium" },
  7045: { category: "system",         action: "service_install",      severity: "medium" },
  7036: { category: "system",         action: "service_state_change", severity: "info" },

  // --- Firewall ---
  5156: { category: "firewall",       action: "connection_allowed",   severity: "info" },
  5157: { category: "firewall",       action: "connection_blocked",   severity: "low" },

  // --- PowerShell ---
  4104: { category: "process",        action: "powershell_script_block", severity: "medium" },
  4103: { category: "process",        action: "powershell_module_log",   severity: "info" },

  // --- Scheduled tasks ---
  4698: { category: "scheduled_task", action: "scheduled_task_created",   severity: "medium" },
  4699: { category: "scheduled_task", action: "scheduled_task_deleted",   severity: "low" },
  4702: { category: "scheduled_task", action: "scheduled_task_updated",   severity: "low" },
};

// Logon types
const LOGON_TYPE_MAP: Record<string, string> = {
  "2": "Interactive", "3": "Network", "4": "Batch", "5": "Service",
  "7": "Unlock", "8": "NetworkCleartext", "9": "NewCredentials",
  "10": "RemoteInteractive", "11": "CachedInteractive",
};

export function parseWindowsEventLog(raw: string, sourceHost: string): ParsedEvent | null {
  try {
    let eventId: number | undefined;
    let computer: string | undefined;
    let eventData: Record<string, string> = {};
    let channel: string | undefined;
    let providerName: string | undefined;

    // XML format
    if (raw.includes("<Event") || raw.includes("<EventID")) {
      eventId = extractXmlInt(raw, "EventID");
      computer = extractXmlText(raw, "Computer");
      channel = extractXmlText(raw, "Channel");
      providerName = extractXmlAttr(raw, "Provider", "Name");
      const dataRegex = /<Data Name="([^"]+)">([^<]*)<\/Data>/g;
      let m;
      while ((m = dataRegex.exec(raw)) !== null) {
        eventData[m[1]] = m[2];
      }
    } else if (raw.startsWith("{")) {
      const obj = JSON.parse(raw);
      eventId = obj.EventID ?? obj.event_id;
      computer = obj.Computer ?? obj.computer ?? obj.hostname;
      channel = obj.Channel ?? obj.channel;
      providerName = obj.ProviderName ?? obj.provider_name;
      eventData = obj.EventData ?? obj;
    } else {
      return null;
    }

    if (!eventId) return null;

    const mapping = EVENT_MAP[eventId] ?? {
      category: "system",
      action: `event_${eventId}`,
      severity: "info",
    };

    const logonTypeStr = eventData.LogonType;
    const logonType = logonTypeStr ? parseInt(logonTypeStr) : undefined;
    const logonTypeName = logonTypeStr ? LOGON_TYPE_MAP[logonTypeStr] : undefined;

    // Determine outcome
    let outcome: string | undefined;
    if ([4624, 4672, 4768, 4769, 4776].includes(eventId)) outcome = "success";
    else if ([4625, 4771].includes(eventId)) outcome = "failure";

    // Build tags
    const tags: string[] = ["windows"];
    if (providerName === "Microsoft-Windows-Sysmon") tags.push("sysmon");
    if (mapping.category === "authentication") tags.push("authentication");
    if (mapping.category === "iam") tags.push("user-management");
    if ([4104, 4103].includes(eventId)) tags.push("powershell");

    // Build rich message
    let message = `Windows Event ${eventId}: ${mapping.action}`;
    if (logonTypeName) message += ` (${logonTypeName})`;
    if (eventData.TargetUserName) message += ` user=${eventData.TargetUserName}`;
    if (eventData.IpAddress && eventData.IpAddress !== "-") message += ` from=${eventData.IpAddress}`;

    return {
      sourceType: "windows_eventlog",
      sourceHost: computer || sourceHost,
      category: mapping.category,
      action: mapping.action,
      severity: mapping.severity,
      outcome,
      userName: eventData.TargetUserName || eventData.SubjectUserName || eventData.User,
      userDomain: eventData.TargetDomainName || eventData.SubjectDomainName,
      targetUserName: eventData.TargetUserName,
      logonType,
      processName: eventData.NewProcessName || eventData.Image || eventData.ProcessName,
      processId: eventData.NewProcessId ? parseInt(eventData.NewProcessId, 16) : (eventData.ProcessId ? parseInt(eventData.ProcessId) : undefined),
      processCommandLine: eventData.CommandLine || eventData.ProcessCommandLine,
      parentProcessName: eventData.ParentImage || eventData.ParentProcessName,
      parentProcessId: eventData.ParentProcessId ? parseInt(eventData.ParentProcessId, 16) : undefined,
      srcIp: eventData.IpAddress !== "-" ? eventData.IpAddress : undefined,
      srcPort: eventData.IpPort ? parseInt(eventData.IpPort) : undefined,
      dstIp: eventData.DestinationIp,
      dstPort: eventData.DestinationPort ? parseInt(eventData.DestinationPort) : undefined,
      protocol: eventData.Protocol,
      registryKey: eventData.TargetObject || eventData.ObjectName,
      registryValue: eventData.Details,
      filePath: eventData.ObjectName || eventData.TargetFilename,
      fileName: (eventData.TargetFilename ?? eventData.ObjectName)?.split("\\").pop(),
      fileHash: eventData.Hashes?.split(",")[0]?.split("=")[1],
      dnsQuery: eventData.QueryName,
      vendorName: "Microsoft",
      vendorProduct: channel ?? "Windows Security",
      deviceEventClassId: String(eventId),
      eventType: `EventID-${eventId}`,
      message,
      rawLog: raw,
      tags,
    };
  } catch {
    return null;
  }
}

function extractXmlText(xml: string, tag: string): string | undefined {
  const m = new RegExp(`<${tag}[^>]*>([^<]+)<\/${tag}>`).exec(xml);
  return m?.[1];
}

function extractXmlInt(xml: string, tag: string): number | undefined {
  const v = extractXmlText(xml, tag);
  return v ? parseInt(v) : undefined;
}

function extractXmlAttr(xml: string, tag: string, attr: string): string | undefined {
  const m = new RegExp(`<${tag}[^>]*${attr}="([^"]*)"`, "i").exec(xml);
  return m?.[1];
}

registerParser({
  name: "windows-eventlog",
  sourceTypes: ["windows_eventlog", "windows", "winlog"],
  priority: 10,
  canParse: (raw) => (raw.includes("<EventID") || (raw.startsWith("{") && /"EventID"/i.test(raw))),
  parse: (raw, sourceHost) => parseWindowsEventLog(raw, sourceHost),
});
