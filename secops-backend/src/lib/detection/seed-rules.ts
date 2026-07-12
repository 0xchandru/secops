import { db, rulesTable } from "../../db";
import { sql } from "drizzle-orm";
import { logger } from "../logger";

interface SeedRule {
  name: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  logSource?: string;
  mitreIds?: string[];
  mitreTactic?: string;
  tags?: string[];
  yamlContent: string;
}

const SEED_RULES: SeedRule[] = [
  // ── 1: Brute Force Authentication ─────────────────────────────
  {
    name: "Brute Force Authentication",
    description: "Detects five or more failed authentication attempts from the same source IP within a five-minute window, consistent with automated credential-stuffing or password-spraying attacks.",
    severity: "high",
    logSource: "auth",
    mitreIds: ["T1110"],
    mitreTactic: "Credential Access",
    tags: ["authentication", "brute-force", "__seeded"],
    yamlContent: `name: Brute Force Authentication
description: Five or more failed logins from the same source IP within 5 minutes
severity: high
type: threshold
match:
  category: authentication
  action: login_failure
threshold:
  field: srcIp
  count: 5
  timeframe: 5m
filter:
  srcIp|cidr:
    - 127.0.0.0/8
mitre:
  tactic: Credential Access
  technique_id: T1110
  technique_name: Brute Force
alert:
  title_template: "Brute force: {count} failed logins from {srcIp}"
  context_fields: [srcIp, userName, sourceHost, category]
tags: [authentication, brute-force]
max_alerts_per_hour: 10
dedup_window: 10m
`,
  },

  // ── 2: Suspicious PowerShell Execution ────────────────────────
  {
    name: "Suspicious PowerShell Execution",
    description: "Detects PowerShell invocations that use obfuscation, encoded commands, or web download cradles — techniques that are strongly associated with initial access and post-exploitation payloads.",
    severity: "high",
    logSource: "windows",
    mitreIds: ["T1059.001"],
    mitreTactic: "Execution",
    tags: ["powershell", "execution", "lolbin", "__seeded"],
    yamlContent: `name: Suspicious PowerShell Execution
description: PowerShell invocation with download, obfuscation, or encoded-command patterns
severity: high
type: simple
match:
  category: process
  action: process_create
  processName|contains|any:
    - powershell.exe
    - pwsh.exe
  processCommandLine|contains|any:
    - -EncodedCommand
    - -enc
    - DownloadString
    - DownloadFile
    - IEX
    - Invoke-Expression
    - Invoke-WebRequest
    - Net.WebClient
    - FromBase64String
    - -ExecutionPolicy Bypass
    - -NoProfile -NonInteractive
    - -WindowStyle Hidden
filter:
  processCommandLine|contains|any:
    - MicrosoftEdgeUpdate
    - Windows\\System32\\WindowsPowerShell
    - -NonInteractive -NoProfile -Command "exit"
mitre:
  tactic: Execution
  technique_id: T1059.001
  technique_name: "Command and Scripting Interpreter: PowerShell"
alert:
  title_template: "Suspicious PowerShell on {sourceHost} by {userName}"
  context_fields: [processCommandLine, processName, parentProcessName, userName, sourceHost]
tags: [powershell, execution, lolbin]
dedup_window: 5m
`,
  },

  // ── 3: LSASS Memory Access ─────────────────────────────────────
  {
    name: "LSASS Memory Access",
    description: "Detects processes opening a handle to lsass.exe for memory read access. This is the primary method used by credential-dumping tools such as Mimikatz, ProcDump, and comsvcs.dll.",
    severity: "critical",
    logSource: "windows",
    mitreIds: ["T1003.001"],
    mitreTactic: "Credential Access",
    tags: ["credential-dumping", "lsass", "mimikatz", "__seeded"],
    yamlContent: `name: LSASS Memory Access
description: Process opened a handle to lsass.exe for memory reading — credential dump indicator
severity: critical
type: simple
match:
  category: process
  action: process_access
  targetProcessName: lsass.exe
  grantedAccess|contains|any:
    - "0x1010"
    - "0x1410"
    - "0x147a"
    - "0x1fffff"
    - "0x1f3fff"
filter:
  processName|contains|any:
    - MsMpEng.exe
    - svchost.exe
    - taskmgr.exe
    - csrss.exe
    - wininit.exe
    - lsm.exe
mitre:
  tactic: Credential Access
  technique_id: T1003.001
  technique_name: "OS Credential Dumping: LSASS Memory"
alert:
  title_template: "LSASS memory access by {processName} on {sourceHost}"
  context_fields: [processName, processCommandLine, grantedAccess, userName, sourceHost, processId]
tags: [credential-dumping, lsass, mimikatz]
dedup_window: 5m
`,
  },

  // ── 4: PsExec / SMB Admin Share Lateral Movement ──────────────
  {
    name: "PsExec-style Lateral Movement",
    description: "Detects service installation events whose binary path matches patterns associated with PsExec, PAExec, RemCom, or similar remote execution tools used for lateral movement over SMB.",
    severity: "critical",
    logSource: "windows",
    mitreIds: ["T1021.002"],
    mitreTactic: "Lateral Movement",
    tags: ["lateral-movement", "psexec", "smb", "__seeded"],
    yamlContent: `name: PsExec-style Lateral Movement
description: Service installation matching PsExec, PAExec, or RemCom lateral movement tools
severity: critical
type: simple
match:
  category: service
  action: service_install
  servicePath|contains|any:
    - PSEXESVC
    - PSEXE
    - PAExec
    - RemCom
    - csexec
    - \\Admin$\\
mitre:
  tactic: Lateral Movement
  technique_id: T1021.002
  technique_name: "Remote Services: SMB/Windows Admin Shares"
alert:
  title_template: "PsExec lateral movement on {sourceHost} — service: {serviceName}"
  context_fields: [serviceName, servicePath, userName, sourceHost, srcIp]
tags: [lateral-movement, psexec, smb]
dedup_window: 15m
`,
  },

  // ── 5: Scheduled Task Persistence ─────────────────────────────
  {
    name: "Scheduled Task Created for Persistence",
    description: "Detects schtasks.exe invocations that create or modify scheduled tasks. Attackers use scheduled tasks as a reliable persistence mechanism that survives reboots.",
    severity: "high",
    logSource: "windows",
    mitreIds: ["T1053.005"],
    mitreTactic: "Persistence",
    tags: ["persistence", "scheduled-task", "__seeded"],
    yamlContent: `name: Scheduled Task Created for Persistence
description: Schtasks.exe used to create or modify a scheduled task
severity: high
type: simple
match:
  category: process
  action: process_create
  processName|contains: schtasks.exe
  processCommandLine|contains:
    - /create
filter:
  processCommandLine|contains|any:
    - Microsoft\\Windows\\UpdateOrchestrator
    - Microsoft\\Windows\\WindowsUpdate
    - Microsoft\\Windows\\Defrag
    - MicrosoftEdge
mitre:
  tactic: Persistence
  technique_id: T1053.005
  technique_name: "Scheduled Task/Job: Scheduled Task"
alert:
  title_template: "Scheduled task created on {sourceHost} by {userName}"
  context_fields: [processCommandLine, userName, sourceHost, parentProcessName, processId]
tags: [persistence, scheduled-task]
dedup_window: 10m
`,
  },

  // ── 6: Office Application Spawning a Shell ─────────────────────
  {
    name: "Office Application Spawning Shell",
    description: "Detects a Microsoft Office process (Word, Excel, PowerPoint, Outlook) spawning a command interpreter or scripting host — the canonical indicator of a malicious macro payload from a phishing document.",
    severity: "critical",
    logSource: "windows",
    mitreIds: ["T1566.001"],
    mitreTactic: "Initial Access",
    tags: ["phishing", "macro", "office", "initial-access", "__seeded"],
    yamlContent: `name: Office Application Spawning Shell
description: Office application (Word/Excel/PowerPoint/Outlook) spawning a command interpreter
severity: critical
type: simple
match:
  category: process
  action: process_create
  parentProcessName|contains|any:
    - WINWORD.EXE
    - EXCEL.EXE
    - POWERPNT.EXE
    - OUTLOOK.EXE
    - MSPUB.EXE
    - VISIO.EXE
  processName|contains|any:
    - cmd.exe
    - powershell.exe
    - pwsh.exe
    - wscript.exe
    - cscript.exe
    - mshta.exe
    - regsvr32.exe
    - rundll32.exe
    - certutil.exe
    - bitsadmin.exe
mitre:
  tactic: Initial Access
  technique_id: T1566.001
  technique_name: "Phishing: Spearphishing Attachment"
alert:
  title_template: "Office macro shell: {parentProcessName} spawned {processName} on {sourceHost}"
  context_fields: [parentProcessName, processName, processCommandLine, userName, sourceHost]
tags: [phishing, macro, office, initial-access]
dedup_window: 5m
`,
  },

  // ── 7: Windows Registry Run Key Persistence ────────────────────
  {
    name: "Registry Run Key Persistence",
    description: "Detects writes to HKCU or HKLM Run/RunOnce registry keys. These keys execute a program at every user logon or system boot and are a common persistence mechanism.",
    severity: "high",
    logSource: "windows",
    mitreIds: ["T1547.001"],
    mitreTactic: "Persistence",
    tags: ["registry", "persistence", "__seeded"],
    yamlContent: `name: Registry Run Key Persistence
description: Write to a Run or RunOnce registry key used for logon/boot persistence
severity: high
type: simple
match:
  category: registry
  action: registry_set
  registryKey|contains|any:
    - \\CurrentVersion\\Run\\
    - \\CurrentVersion\\RunOnce\\
    - \\CurrentVersion\\RunServices\\
    - \\CurrentVersion\\RunServicesOnce\\
filter:
  processName|contains|any:
    - msiexec.exe
    - msiinstall.exe
    - setup.exe
    - install.exe
mitre:
  tactic: Persistence
  technique_id: T1547.001
  technique_name: "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder"
alert:
  title_template: "Run key persistence on {sourceHost} by {userName}: {registryKey}"
  context_fields: [registryKey, registryValue, processName, userName, sourceHost]
tags: [registry, persistence]
dedup_window: 10m
`,
  },

  // ── 8: RDP Login from External IP ─────────────────────────────
  {
    name: "RDP Login from External IP",
    description: "Detects a successful RDP (logon type 10 — RemoteInteractive) authentication from a source IP outside RFC-1918 private ranges. Externally-sourced RDP sessions are a significant indicator of unauthorized access.",
    severity: "high",
    logSource: "windows",
    mitreIds: ["T1021.001"],
    mitreTactic: "Lateral Movement",
    tags: ["rdp", "external-access", "__seeded"],
    yamlContent: `name: RDP Login from External IP
description: Successful RDP (logon type 10) from a non-private source IP address
severity: high
type: simple
match:
  category: authentication
  action: login_success
  logonType: 10
filter:
  srcIp|cidr:
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16
    - 127.0.0.0/8
    - 169.254.0.0/16
    - ::1/128
mitre:
  tactic: Lateral Movement
  technique_id: T1021.001
  technique_name: "Remote Services: Remote Desktop Protocol"
alert:
  title_template: "External RDP login: {userName} from {srcIp} to {sourceHost}"
  context_fields: [userName, srcIp, sourceHost, logonType, workstationName]
tags: [rdp, external-access]
dedup_window: 30m
`,
  },

  // ── 9: Pass-the-Hash ───────────────────────────────────────────
  {
    name: "Pass-the-Hash Attack",
    description: "Detects NTLM network logons (type 3) using NtLmSsp authentication from a non-domain-controller host — the hallmark pattern of a pass-the-hash lateral movement attack.",
    severity: "critical",
    logSource: "windows",
    mitreIds: ["T1550.002"],
    mitreTactic: "Lateral Movement",
    tags: ["lateral-movement", "pass-the-hash", "ntlm", "__seeded"],
    yamlContent: `name: Pass-the-Hash Attack
description: NTLM network logon (type 3) via NtLmSsp from a non-domain-controller
severity: critical
type: simple
match:
  category: authentication
  action: login_success
  logonType: 3
  authPackage: NtLmSsp
  logonProcess: NtLmSsp
filter:
  srcIp|cidr:
    - 127.0.0.0/8
mitre:
  tactic: Lateral Movement
  technique_id: T1550.002
  technique_name: "Use Alternate Authentication Material: Pass the Hash"
alert:
  title_template: "Pass-the-Hash: {userName} authenticated from {srcIp} to {sourceHost}"
  context_fields: [userName, srcIp, sourceHost, logonType, authPackage, workstationName]
tags: [lateral-movement, pass-the-hash, ntlm]
dedup_window: 30m
`,
  },

  // ── 10: Excessive DNS Queries / C2 Beaconing ──────────────────
  {
    name: "DNS Beaconing / C2 Query Spike",
    description: "Detects a single host issuing an abnormally high volume of DNS queries within a short window. This pattern is consistent with C2 beaconing over DNS or DNS tunneling for data exfiltration.",
    severity: "high",
    logSource: "dns",
    mitreIds: ["T1071.004"],
    mitreTactic: "Command and Control",
    tags: ["dns", "c2", "beaconing", "tunneling", "__seeded"],
    yamlContent: `name: DNS Beaconing / C2 Query Spike
description: Excessive DNS queries from a single host — consistent with C2 beaconing or DNS tunneling
severity: high
type: threshold
match:
  category: dns
  action: dns_query
threshold:
  field: sourceHost
  count: 100
  timeframe: 5m
filter:
  dnsQuery|contains|any:
    - microsoft.com
    - windowsupdate.com
    - office.com
    - googleapis.com
    - akamai.net
mitre:
  tactic: Command and Control
  technique_id: T1071.004
  technique_name: "Application Layer Protocol: DNS"
alert:
  title_template: "DNS spike: {count} queries from {sourceHost} in 5 minutes"
  context_fields: [sourceHost, srcIp, dnsQuery, dnsType]
tags: [dns, c2, beaconing, tunneling]
max_alerts_per_hour: 5
dedup_window: 15m
`,
  },

  // ── 11: Large Outbound Data Transfer ──────────────────────────
  {
    name: "Large Outbound Data Transfer",
    description: "Detects a single network session that transfers more than 100 MB of data to a non-private external IP address. Such transfers are anomalous in most enterprise environments and may indicate data exfiltration.",
    severity: "high",
    logSource: "network",
    mitreIds: ["T1048"],
    mitreTactic: "Exfiltration",
    tags: ["exfiltration", "network", "data-transfer", "__seeded"],
    yamlContent: `name: Large Outbound Data Transfer
description: Single session outbound transfer of more than 100 MB to an external IP
severity: high
type: simple
match:
  category: network
  direction: outbound
  bytesOut|gt: 104857600
filter:
  dstIp|cidr:
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16
    - 127.0.0.0/8
    - 169.254.0.0/16
mitre:
  tactic: Exfiltration
  technique_id: T1048
  technique_name: "Exfiltration Over Alternative Protocol"
alert:
  title_template: "Large outbound transfer: {bytesOut} bytes to {dstIp} from {sourceHost}"
  context_fields: [srcIp, dstIp, dstPort, bytesOut, protocol, sourceHost, userName]
tags: [exfiltration, network, data-transfer]
max_alerts_per_hour: 5
dedup_window: 1h
`,
  },

  // ── 12: AWS Root Account API Activity ─────────────────────────
  {
    name: "AWS Root Account API Activity",
    description: "Detects any AWS API call made using the root account. The root account should never be used for day-to-day operations; any activity is a high-confidence indicator of compromise or unauthorized privileged access.",
    severity: "critical",
    logSource: "cloudtrail",
    mitreIds: ["T1078.004"],
    mitreTactic: "Privilege Escalation",
    tags: ["aws", "root-account", "cloudtrail", "cloud", "__seeded"],
    yamlContent: `name: AWS Root Account API Activity
description: Any AWS API call authenticated as the root account user
severity: critical
type: simple
match:
  sourceType: cloudtrail
  userIdentityType: Root
  errorCode|not|contains:
    - AccessDenied
    - NotAuthorized
filter:
  action|contains|any:
    - CheckMfa
    - GetSessionToken
mitre:
  tactic: Privilege Escalation
  technique_id: T1078.004
  technique_name: "Valid Accounts: Cloud Accounts"
alert:
  title_template: "AWS root account used: {action} from {srcIp}"
  context_fields: [action, srcIp, userName, sourceHost, userIdentityType, httpUserAgent]
tags: [aws, root-account, cloudtrail, cloud]
dedup_window: 15m
`,
  },
];

/**
 * Clears ALL existing detection rules and reseeds from the SEED_RULES constant.
 * This is intentionally destructive — it replaces the rule set on every call so
 * that the code is always the source of truth for the default ruleset.
 *
 * User-created rules will be removed. If you need to preserve custom rules,
 * export them before restarting the server or change this function to filter
 * by the `__seeded` tag.
 */
export async function seedDefaultRules(): Promise<number> {
  // Delete all existing rules to start from a clean slate
  await db.delete(rulesTable);
  logger.info("Cleared rules table — reseeding from code");

  let inserted = 0;
  for (const rule of SEED_RULES) {
    try {
      await db.insert(rulesTable).values({
        name: rule.name,
        description: rule.description,
        severity: rule.severity,
        enabled: true,
        yamlContent: rule.yamlContent,
        logSource: rule.logSource,
        mitreIds: rule.mitreIds,
        mitreTactic: rule.mitreTactic,
        tags: rule.tags,
      });
      inserted++;
    } catch (err) {
      logger.warn({ err, ruleName: rule.name }, "Failed to insert seed rule");
    }
  }

  logger.info({ inserted }, "Seeded detection rules");
  return inserted;
}
