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

const DEFAULT_RULES: SeedRule[] = [
  // ── Rule 1: Brute Force Login Attempt ──────────────────────────
  {
    name: "Brute Force Login Attempt",
    description: "Detects multiple failed login attempts from the same source IP within a short time window, indicating a possible brute-force attack.",
    severity: "high",
    logSource: "windows_eventlog",
    mitreIds: ["T1110"],
    mitreTactic: "Credential Access",
    tags: ["authentication", "brute-force"],
    yamlContent: `name: Brute Force Login Attempt
description: Multiple failed logins from same source IP
severity: high
type: threshold
match:
  category: "authentication"
  action: "login_failure"
threshold:
  field: srcIp
  count: 5
  timeframe: "5m"
mitre:
  tactic: Credential Access
  technique_id: T1110
  technique_name: Brute Force
alert:
  title_template: "Brute Force: {count} failed logins from {srcIp}"
  context_fields: [srcIp, userName, sourceHost]
tags: [authentication, brute-force]
max_alerts_per_hour: 10
dedup_window: "10m"
`,
  },

  // ── Rule 2: Suspicious PowerShell Execution ────────────────────
  {
    name: "Suspicious PowerShell Execution",
    description: "Detects PowerShell commands containing obfuscation or download techniques commonly used by attackers.",
    severity: "high",
    logSource: "windows_eventlog",
    mitreIds: ["T1059.001"],
    mitreTactic: "Execution",
    tags: ["powershell", "execution"],
    yamlContent: `name: Suspicious PowerShell Execution
description: PowerShell with suspicious download/obfuscation patterns
severity: high
type: simple
match:
  processCommandLine|contains|any:
    - "DownloadString"
    - "IEX"
    - "-enc"
    - "-EncodedCommand"
    - "hidden"
    - "Invoke-WebRequest"
    - "FromBase64String"
    - "Invoke-Expression"
    - "Net.WebClient"
    - "Bypass"
mitre:
  tactic: Execution
  technique_id: T1059.001
  technique_name: "Command and Scripting Interpreter: PowerShell"
alert:
  title_template: "Suspicious PowerShell on {sourceHost} by {userName}"
  context_fields: [processCommandLine, userName, sourceHost, processName]
tags: [powershell, execution]
`,
  },

  // ── Rule 3: PsExec-style Lateral Movement ─────────────────────
  {
    name: "PsExec-style Lateral Movement",
    description: "Detects service installation events matching PsExec, PAExec, or RemCom tools commonly used for lateral movement.",
    severity: "critical",
    logSource: "windows_eventlog",
    mitreIds: ["T1021.002"],
    mitreTactic: "Lateral Movement",
    tags: ["lateral-movement", "psexec"],
    yamlContent: `name: PsExec-style Lateral Movement
description: Service install matching PsExec/PAExec/RemCom lateral movement tools
severity: critical
type: simple
match:
  action: "service_install"
  rawLog|contains|any:
    - "PSEXESVC"
    - "PSEXE"
    - "PAExec"
    - "RemCom"
    - "csexec"
mitre:
  tactic: Lateral Movement
  technique_id: T1021.002
  technique_name: "Remote Services: SMB/Windows Admin Shares"
alert:
  title_template: "PsExec lateral movement detected on {sourceHost}"
  context_fields: [sourceHost, userName, message]
tags: [lateral-movement, psexec]
`,
  },

  // ── Rule 4: SSH Brute Force ────────────────────────────────────
  {
    name: "SSH Brute Force",
    description: "Detects multiple SSH authentication failures from the same source IP, indicating a brute-force SSH attack.",
    severity: "medium",
    logSource: "syslog",
    mitreIds: ["T1110"],
    mitreTactic: "Credential Access",
    tags: ["ssh", "brute-force"],
    yamlContent: `name: SSH Brute Force
description: Multiple SSH auth failures from same source
severity: medium
type: threshold
match:
  category: "authentication"
  action: "login_failure"
  processName: "sshd"
threshold:
  field: srcIp
  count: 5
  timeframe: "5m"
mitre:
  tactic: Credential Access
  technique_id: T1110
  technique_name: Brute Force
alert:
  title_template: "SSH Brute Force: {count} failures from {srcIp}"
  context_fields: [srcIp, userName, sourceHost]
tags: [ssh, brute-force]
max_alerts_per_hour: 10
dedup_window: "10m"
`,
  },

  // ── Rule 5: Firewall Connection Blocked – Repeated ─────────────
  {
    name: "Firewall Connection Blocked – Repeated",
    description: "Detects repeated blocked connections from the same source IP, indicating port scanning or reconnaissance.",
    severity: "medium",
    logSource: "firewall",
    mitreIds: ["T1046"],
    mitreTactic: "Discovery",
    tags: ["firewall", "port-scan"],
    yamlContent: `name: "Firewall Connection Blocked \u2013 Repeated"
description: Repeated blocked connections from same source IP
severity: medium
type: threshold
match:
  category: "firewall"
  action: "connection_blocked"
threshold:
  field: srcIp
  count: 5
  timeframe: "5m"
mitre:
  tactic: Discovery
  technique_id: T1046
  technique_name: Network Service Discovery
alert:
  title_template: "Port Scan: {count} blocked connections from {srcIp}"
  context_fields: [srcIp, dstIp, dstPort, protocol, sourceHost]
tags: [firewall, port-scan]
max_alerts_per_hour: 10
dedup_window: "10m"
`,
  },

  // ── Rule 6: DNS Query to Known C2 Domain ───────────────────────
  {
    name: "DNS Query to Known C2 Domain",
    description: "Detects DNS queries to domains known to be associated with command and control infrastructure.",
    severity: "critical",
    logSource: "syslog",
    mitreIds: ["T1071.004"],
    mitreTactic: "Command and Control",
    tags: ["dns", "c2", "ioc"],
    yamlContent: `name: DNS Query to Known C2 Domain
description: DNS query to known malicious C2 domain
severity: critical
type: simple
match:
  category: "dns"
  dnsQuery|contains|any:
    - "evil-c2-server.xyz"
    - "cobalt-beacon.malware.xyz"
    - "cobaltstrikeC2.darknet.org"
    - "cobaltstrike"
    - "malware.xyz"
    - "darknet.org"
mitre:
  tactic: Command and Control
  technique_id: T1071.004
  technique_name: "Application Layer Protocol: DNS"
alert:
  title_template: "C2 DNS query: {dnsQuery} from {sourceHost}"
  context_fields: [dnsQuery, sourceHost, srcIp, userName, processName]
tags: [dns, c2, ioc]
`,
  },

  // ── Rule 7: RDP Logon from External IP ─────────────────────────
  {
    name: "RDP Logon from External IP",
    description: "Detects successful RDP (RemoteInteractive) logins from non-RFC1918 IP addresses.",
    severity: "high",
    logSource: "windows_eventlog",
    mitreIds: ["T1021.001"],
    mitreTactic: "Lateral Movement",
    tags: ["rdp", "external-access"],
    yamlContent: `name: RDP Logon from External IP
description: Successful RDP login from non-private IP address
severity: high
type: simple
match:
  category: "authentication"
  action: "login_success"
  logonType: 10
  srcIp|not|cidr:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
    - "127.0.0.0/8"
mitre:
  tactic: Lateral Movement
  technique_id: T1021.001
  technique_name: "Remote Services: Remote Desktop Protocol"
alert:
  title_template: "External RDP login: {userName} from {srcIp} to {sourceHost}"
  context_fields: [srcIp, userName, sourceHost, logonType]
tags: [rdp, external-access]
`,
  },

  // ── Rule 8: New User Account Created ───────────────────────────
  {
    name: "New User Account Created",
    description: "Detects creation of new user accounts which may indicate persistence by an attacker.",
    severity: "medium",
    logSource: "windows_eventlog",
    mitreIds: ["T1136.001"],
    mitreTactic: "Persistence",
    tags: ["iam", "user-creation"],
    yamlContent: `name: New User Account Created
description: New user account created
severity: medium
type: simple
match:
  category: "iam"
  action: "user_created"
mitre:
  tactic: Persistence
  technique_id: T1136.001
  technique_name: "Create Account: Local Account"
alert:
  title_template: "New user created: {targetUserName} on {sourceHost}"
  context_fields: [targetUserName, userName, sourceHost, userDomain]
tags: [iam, user-creation]
`,
  },

  // ── Rule 9: Suspicious HTTP POST to External IP ────────────────
  {
    name: "Suspicious HTTP POST to External IP",
    description: "Detects large HTTP POST requests to external (non-RFC1918) IP addresses, indicating possible data exfiltration.",
    severity: "high",
    logSource: "cef",
    mitreIds: ["T1041"],
    mitreTactic: "Exfiltration",
    tags: ["exfiltration", "http"],
    yamlContent: `name: Suspicious HTTP POST to External IP
description: Large HTTP POST to non-private external IP
severity: high
type: simple
match:
  httpMethod: "POST"
  dstIp|not|cidr:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
    - "127.0.0.0/8"
  bytesOut|gt: 1000000
mitre:
  tactic: Exfiltration
  technique_id: T1041
  technique_name: Exfiltration Over C2 Channel
alert:
  title_template: "Data exfiltration: {bytesOut} bytes POST to {dstIp} by {userName}"
  context_fields: [srcIp, dstIp, httpUrl, bytesOut, userName, sourceHost]
tags: [exfiltration, http]
`,
  },

  // ── Rule 10: Windows Registry Run Key Modification ─────────────
  {
    name: "Windows Registry Run Key Modification",
    description: "Detects modifications to Windows Run/RunOnce registry keys used for persistence.",
    severity: "high",
    logSource: "windows_eventlog",
    mitreIds: ["T1547.001"],
    mitreTactic: "Persistence",
    tags: ["registry", "persistence"],
    yamlContent: `name: Windows Registry Run Key Modification
description: Modification of Run/RunOnce registry keys for persistence
severity: high
type: simple
match:
  category: "registry"
  action: "registry_modify"
  registryKey|contains|any:
    - "CurrentVersion\\\\Run"
    - "CurrentVersion\\\\RunOnce"
mitre:
  tactic: Persistence
  technique_id: T1547.001
  technique_name: "Boot or Logon Autostart Execution: Registry Run Keys"
alert:
  title_template: "Registry Run key modified on {sourceHost} by {userName}"
  context_fields: [registryKey, registryValue, userName, sourceHost, processName]
tags: [registry, persistence]
`,
  },

  // ── Rule 11: Kerberoasting – SPN Request Spike ─────────────────
  {
    name: "Kerberoasting – SPN Request Spike",
    description: "Detects a spike in Kerberos service ticket requests from a single user, indicating potential Kerberoasting attack.",
    severity: "high",
    logSource: "windows_eventlog",
    mitreIds: ["T1558.003"],
    mitreTactic: "Credential Access",
    tags: ["kerberos", "kerberoasting"],
    yamlContent: `name: "Kerberoasting \u2013 SPN Request Spike"
description: Spike in Kerberos service ticket requests from single user
severity: high
type: threshold
match:
  category: "authentication"
  action: "kerberos_service_ticket"
threshold:
  field: userName
  count: 5
  timeframe: "5m"
mitre:
  tactic: Credential Access
  technique_id: T1558.003
  technique_name: "Steal or Forge Kerberos Tickets: Kerberoasting"
alert:
  title_template: "Kerberoasting: {count} SPN requests by {userName}"
  context_fields: [userName, srcIp, sourceHost]
tags: [kerberos, kerberoasting]
max_alerts_per_hour: 5
dedup_window: "15m"
`,
  },

  // ── Rule 12: CloudTrail – Root Account Usage ───────────────────
  {
    name: "CloudTrail – Root Account Usage",
    description: "Detects any API activity performed by the AWS root account, which should rarely be used in production.",
    severity: "critical",
    logSource: "cloudtrail",
    mitreIds: ["T1078.004"],
    mitreTactic: "Privilege Escalation",
    tags: ["aws", "root-account", "cloudtrail"],
    yamlContent: `name: "CloudTrail \u2013 Root Account Usage"
description: AWS root account API activity detected
severity: critical
type: simple
match:
  sourceType: "cloudtrail"
  tags|contains: "root-user"
mitre:
  tactic: Privilege Escalation
  technique_id: T1078.004
  technique_name: "Valid Accounts: Cloud Accounts"
alert:
  title_template: "AWS Root account activity: {action} from {srcIp}"
  context_fields: [action, srcIp, userName, sourceHost, httpUserAgent]
tags: [aws, root-account, cloudtrail]
`,
  },

  // ── Rule 13: Credential Dumping Tool Detected ──────────────────
  {
    name: "Credential Dumping Tool Detected",
    description: "Detects execution of known credential dumping tools like Mimikatz, ProcDump targeting LSASS, or LaZagne.",
    severity: "critical",
    logSource: "windows_eventlog",
    mitreIds: ["T1003"],
    mitreTactic: "Credential Access",
    tags: ["credential-dumping", "mimikatz"],
    yamlContent: `name: Credential Dumping Tool Detected
description: Execution of known credential dumping tools
severity: critical
type: simple
match:
  category: "process"
  action: "process_create"
  processCommandLine|contains|any:
    - "mimikatz"
    - "sekurlsa"
    - "lsass"
    - "procdump"
    - "lazagne"
    - "comsvcs.dll"
    - "MiniDump"
    - "logonpasswords"
mitre:
  tactic: Credential Access
  technique_id: T1003
  technique_name: OS Credential Dumping
alert:
  title_template: "Credential dumping on {sourceHost}: {processName}"
  context_fields: [processName, processCommandLine, userName, sourceHost, parentProcessName]
tags: [credential-dumping, mimikatz]
`,
  },

  // ── Rule 14: Login After Account Creation (Sequence) ───────────
  {
    name: "Login After Account Creation",
    description: "Detects when a newly created user account logs in shortly after creation, which may indicate attacker persistence.",
    severity: "high",
    logSource: "windows_eventlog",
    mitreIds: ["T1136.001"],
    mitreTactic: "Persistence",
    tags: ["sequence", "persistence", "iam"],
    yamlContent: `name: Login After Account Creation
description: Newly created account logs in shortly after creation
severity: high
type: sequence
sequence:
  steps:
    - match:
        category: "iam"
        action: "user_created"
    - match:
        category: "authentication"
        action: "login_success"
  timeframe: "30m"
  by_field: userName
mitre:
  tactic: Persistence
  technique_id: T1136.001
  technique_name: "Create Account: Local Account"
alert:
  title_template: "New account {userName} logged in shortly after creation on {sourceHost}"
  context_fields: [userName, sourceHost, srcIp, targetUserName]
tags: [sequence, persistence, iam]
`,
  },

  // ── Rule 15: Excessive DNS Queries – Possible Tunneling ────────
  {
    name: "Excessive DNS Queries – Possible Tunneling",
    description: "Detects an excessive number of DNS queries from a single host, which may indicate DNS tunneling for data exfiltration.",
    severity: "high",
    logSource: "syslog",
    mitreIds: ["T1071.004"],
    mitreTactic: "Command and Control",
    tags: ["dns", "tunneling", "exfiltration"],
    yamlContent: `name: "Excessive DNS Queries \u2013 Possible Tunneling"
description: Excessive DNS queries from a single host
severity: high
type: threshold
match:
  category: "dns"
  action: "dns_query"
threshold:
  field: sourceHost
  count: 10
  timeframe: "5m"
mitre:
  tactic: Command and Control
  technique_id: T1071.004
  technique_name: "Application Layer Protocol: DNS"
alert:
  title_template: "DNS tunneling suspect: {count} queries from {sourceHost}"
  context_fields: [sourceHost, dnsQuery, srcIp]
tags: [dns, tunneling, exfiltration]
max_alerts_per_hour: 5
dedup_window: "10m"
`,
  },

  // ── Rule 16: Pass-the-Hash Detection ──────────────────────────
  {
    name: "Pass-the-Hash Attack Detected",
    description: "Detects NTLM authentication with anomalous logon type 3 (Network) from a workstation, a known pass-the-hash indicator.",
    severity: "critical",
    logSource: "windows_eventlog",
    mitreIds: ["T1550.002"],
    mitreTactic: "Lateral Movement",
    tags: ["lateral-movement", "pass-the-hash", "ntlm"],
    yamlContent: `name: Pass-the-Hash Attack Detected
description: NTLM network logon with NTHash from non-DC host
severity: critical
type: simple
match:
  category: "authentication"
  action: "login_success"
  logonType: 3
  processName: "NtLmSsp"
  srcIp|not|cidr:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
    - "127.0.0.0/8"
mitre:
  tactic: Lateral Movement
  technique_id: T1550.002
  technique_name: "Use Alternate Authentication Material: Pass the Hash"
alert:
  title_template: "Pass-the-Hash: {userName} from {srcIp} to {sourceHost}"
  context_fields: [userName, srcIp, sourceHost, logonType, processName]
tags: [lateral-movement, pass-the-hash, ntlm]
dedup_window: "30m"
`,
  },

  // ── Rule 17: Scheduled Task Created for Persistence ────────────
  {
    name: "Scheduled Task Created for Persistence",
    description: "Detects creation of scheduled tasks, a common persistence mechanism used by malware and attackers.",
    severity: "high",
    logSource: "windows_eventlog",
    mitreIds: ["T1053.005"],
    mitreTactic: "Persistence",
    tags: ["persistence", "scheduled-task"],
    yamlContent: `name: Scheduled Task Created for Persistence
description: Scheduled task creation detected via schtasks or Task Scheduler API
severity: high
type: simple
match:
  category: "process"
  action: "process_create"
  processName|contains|any:
    - "schtasks.exe"
    - "taskschd.msc"
  processCommandLine|contains|any:
    - "/create"
    - "/sc"
    - "/tr"
filter:
  processCommandLine|contains:
    - "Microsoft\\\\Windows\\\\UpdateOrchestrator"
mitre:
  tactic: Persistence
  technique_id: T1053.005
  technique_name: "Scheduled Task/Job: Scheduled Task"
alert:
  title_template: "Scheduled task created on {sourceHost} by {userName}"
  context_fields: [processCommandLine, userName, sourceHost, processName, parentProcessName]
tags: [persistence, scheduled-task]
`,
  },

  // ── Rule 18: Large Outbound DNS Response – Data Exfil ──────────
  {
    name: "Large Outbound Data Transfer – Potential Exfiltration",
    description: "Detects unusually large outbound network transfers that may indicate data exfiltration activity.",
    severity: "high",
    logSource: "firewall",
    mitreIds: ["T1048"],
    mitreTactic: "Exfiltration",
    tags: ["exfiltration", "network", "data-transfer"],
    yamlContent: `name: Large Outbound Data Transfer
description: Single session outbound transfer exceeding 500MB
severity: high
type: simple
match:
  category: "network"
  direction: "outbound"
  bytesOut|gt: 524288000
  dstIp|not|cidr:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
mitre:
  tactic: Exfiltration
  technique_id: T1048
  technique_name: "Exfiltration Over Alternative Protocol"
alert:
  title_template: "Large outbound transfer: {bytesOut} bytes to {dstIp} from {sourceHost}"
  context_fields: [srcIp, dstIp, dstPort, bytesOut, protocol, sourceHost]
tags: [exfiltration, network, data-transfer]
max_alerts_per_hour: 5
dedup_window: "1h"
`,
  },

  // ── Rule 19: Privilege Escalation via Token Impersonation ───────
  {
    name: "Token Impersonation / Privilege Escalation",
    description: "Detects token impersonation techniques used for privilege escalation, such as those leveraged by Juicy Potato, Rogue Potato, or similar tools.",
    severity: "critical",
    logSource: "windows_eventlog",
    mitreIds: ["T1134"],
    mitreTactic: "Privilege Escalation",
    tags: ["privilege-escalation", "token-impersonation"],
    yamlContent: `name: Token Impersonation Privilege Escalation
description: Token impersonation technique detected (JuicyPotato, RoguePotato, etc.)
severity: critical
type: simple
match:
  category: "process"
  action: "process_create"
  processCommandLine|contains|any:
    - "JuicyPotato"
    - "RoguePotato"
    - "PrintSpoofer"
    - "GodPotato"
    - "SweetPotato"
    - "SeImpersonatePrivilege"
mitre:
  tactic: Privilege Escalation
  technique_id: T1134
  technique_name: "Access Token Manipulation"
alert:
  title_template: "Token impersonation attempt on {sourceHost} by {userName}"
  context_fields: [processCommandLine, userName, sourceHost, processName, parentProcessName]
tags: [privilege-escalation, token-impersonation]
`,
  },

  // ── Rule 20: Suspicious Process Spawned by Office App ──────────
  {
    name: "Office Application Spawning Shell",
    description: "Detects when Microsoft Office applications spawn command interpreters or scripting engines — a common initial access technique via malicious macros.",
    severity: "critical",
    logSource: "windows_eventlog",
    mitreIds: ["T1566.001"],
    mitreTactic: "Initial Access",
    tags: ["phishing", "macro", "office", "initial-access"],
    yamlContent: `name: Office Application Spawning Shell
description: Office application (Word/Excel/PowerPoint) spawning cmd/PowerShell
severity: critical
type: simple
match:
  category: "process"
  action: "process_create"
  parentProcessName|contains|any:
    - "WINWORD.EXE"
    - "EXCEL.EXE"
    - "POWERPNT.EXE"
    - "OUTLOOK.EXE"
    - "winword"
    - "excel"
    - "powerpnt"
    - "outlook"
  processName|contains|any:
    - "cmd.exe"
    - "powershell.exe"
    - "wscript.exe"
    - "cscript.exe"
    - "mshta.exe"
    - "regsvr32.exe"
    - "rundll32.exe"
mitre:
  tactic: Initial Access
  technique_id: T1566.001
  technique_name: "Phishing: Spearphishing Attachment"
alert:
  title_template: "Office macro shell: {parentProcessName} spawned {processName} on {sourceHost}"
  context_fields: [processName, parentProcessName, processCommandLine, userName, sourceHost]
tags: [phishing, macro, office, initial-access]
`,
  },

  // ── Rule 21: AWS IAM Policy Change ─────────────────────────────
  {
    name: "AWS IAM Policy Change",
    description: "Detects modifications to IAM policies, roles, or users in AWS CloudTrail, which could indicate privilege escalation or persistent access establishment.",
    severity: "high",
    logSource: "cloudtrail",
    mitreIds: ["T1098"],
    mitreTactic: "Persistence",
    tags: ["aws", "iam", "cloudtrail", "cloud"],
    yamlContent: `name: AWS IAM Policy Change
description: IAM policy/role/user modification detected in CloudTrail
severity: high
type: simple
match:
  sourceType: "cloudtrail"
  action|contains|any:
    - "PutUserPolicy"
    - "AttachUserPolicy"
    - "AttachRolePolicy"
    - "CreatePolicy"
    - "CreateUser"
    - "AddUserToGroup"
    - "UpdateLoginProfile"
    - "CreateAccessKey"
mitre:
  tactic: Persistence
  technique_id: T1098
  technique_name: "Account Manipulation"
alert:
  title_template: "AWS IAM change: {action} by {userName} from {srcIp}"
  context_fields: [action, userName, srcIp, sourceHost, httpUserAgent]
tags: [aws, iam, cloudtrail, cloud]
dedup_window: "5m"
`,
  },

  // ── Rule 22: LSASS Memory Access (Credential Dumping) ──────────
  {
    name: "LSASS Memory Access",
    description: "Detects attempts to access LSASS memory, a primary method for extracting credentials from Windows systems.",
    severity: "critical",
    logSource: "windows_eventlog",
    mitreIds: ["T1003.001"],
    mitreTactic: "Credential Access",
    tags: ["credential-dumping", "lsass"],
    yamlContent: `name: LSASS Memory Access
description: Process opened a handle to LSASS for memory reading
severity: critical
type: simple
match:
  category: "process"
  action: "process_access"
  processName: "lsass.exe"
filter:
  processCommandLine|contains|any:
    - "\\\\Windows\\\\System32\\\\antimalware"
    - "MsMpEng.exe"
    - "svchost.exe"
mitre:
  tactic: Credential Access
  technique_id: T1003.001
  technique_name: "OS Credential Dumping: LSASS Memory"
alert:
  title_template: "LSASS memory access by {processName} on {sourceHost}"
  context_fields: [processName, processCommandLine, userName, sourceHost, processId]
tags: [credential-dumping, lsass]
dedup_window: "5m"
`,
  },

  // ── Rule 23: VPC Flow – Internal Port Scan ─────────────────────
  {
    name: "Internal Port Scan Detected",
    description: "Detects rapid connections from one internal host to many different ports on another host, indicating a port scan.",
    severity: "medium",
    logSource: "vpc_flow",
    mitreIds: ["T1046"],
    mitreTactic: "Discovery",
    tags: ["discovery", "port-scan", "internal"],
    yamlContent: `name: Internal Port Scan Detected
description: Rapid blocked connections from internal host to many ports
severity: medium
type: threshold
match:
  category: "network"
  action: "connection_blocked"
  srcIp|cidr:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
threshold:
  field: srcIp
  count: 20
  timeframe: "2m"
mitre:
  tactic: Discovery
  technique_id: T1046
  technique_name: "Network Service Discovery"
alert:
  title_template: "Internal port scan: {count} connections from {srcIp}"
  context_fields: [srcIp, dstIp, dstPort, protocol, sourceHost]
tags: [discovery, port-scan, internal]
max_alerts_per_hour: 5
dedup_window: "15m"
`,
  },

  // ── Rule 24: Cleartext Credential in HTTP Request ───────────────
  {
    name: "Cleartext Credentials in HTTP Request",
    description: "Detects HTTP requests containing common cleartext credential patterns in URLs or query strings.",
    severity: "high",
    logSource: "proxy",
    mitreIds: ["T1552.004"],
    mitreTactic: "Credential Access",
    tags: ["credential-access", "http", "cleartext"],
    yamlContent: `name: Cleartext Credentials in HTTP Request
description: Credential-like strings detected in HTTP URL or User-Agent
severity: high
type: simple
match:
  category: "network"
  httpMethod|contains|any:
    - "GET"
    - "POST"
  httpUrl|contains|any:
    - "password="
    - "passwd="
    - "pwd="
    - "pass="
    - "secret="
    - "api_key="
    - "token="
mitre:
  tactic: Credential Access
  technique_id: T1552.004
  technique_name: "Unsecured Credentials: Private Keys"
alert:
  title_template: "Cleartext credential in HTTP from {srcIp} to {dstIp}"
  context_fields: [srcIp, dstIp, httpUrl, httpMethod, userName, sourceHost]
tags: [credential-access, http, cleartext]
max_alerts_per_hour: 20
dedup_window: "5m"
`,
  },

  // ── Rule 25: Suspicious WMI Lateral Movement ───────────────────
  {
    name: "WMI Lateral Movement",
    description: "Detects usage of Windows Management Instrumentation (WMI) for remote execution, a common lateral movement technique.",
    severity: "high",
    logSource: "windows_eventlog",
    mitreIds: ["T1047"],
    mitreTactic: "Lateral Movement",
    tags: ["lateral-movement", "wmi"],
    yamlContent: `name: WMI Lateral Movement
description: WMI used for remote process execution
severity: high
type: simple
match:
  category: "process"
  action: "process_create"
  parentProcessName|contains|any:
    - "wmiprvse.exe"
    - "WmiPrvSE.exe"
  processName|contains|any:
    - "cmd.exe"
    - "powershell.exe"
    - "cscript.exe"
    - "wscript.exe"
    - "mshta.exe"
mitre:
  tactic: Lateral Movement
  technique_id: T1047
  technique_name: "Windows Management Instrumentation"
alert:
  title_template: "WMI remote execution: {processName} on {sourceHost}"
  context_fields: [processName, parentProcessName, processCommandLine, userName, sourceHost]
tags: [lateral-movement, wmi]
dedup_window: "10m"
`,
  },
];

/**
 * Seeds the rules table with default detection rules if empty.
 * Skips rules that already exist (matched by name).
 */
export async function seedDefaultRules(): Promise<number> {
  const [{ count }] = await db.select({ count: sql<number>`count(*)` }).from(rulesTable);
  if (Number(count) > 0) {
    logger.info({ existingRules: Number(count) }, "Rules already exist, skipping seed");
    return 0;
  }

  let inserted = 0;
  for (const rule of DEFAULT_RULES) {
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

  logger.info({ inserted }, "Seeded default detection rules");
  return inserted;
}
