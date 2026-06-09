# SecOps Console — SPL & Detection Rule Guide

Your personal reference for writing SPL search queries and building custom detection rules in SecOps Console.

---

## Table of Contents

1. [SPL Search Language](#1-spl-search-language)
2. [Detection Rule YAML Format](#2-detection-rule-yaml-format)
3. [Rule Types](#3-rule-types)
4. [Field Modifiers](#4-field-modifiers)
5. [MITRE ATT&CK Mapping](#5-mitre-attck-mapping)
6. [Detection Rule Examples](#6-detection-rule-examples)
7. [SPL Saved Alerts](#7-spl-saved-alerts)
8. [Testing Your Rules](#8-testing-your-rules)
9. [Normalised Field Reference](#9-normalised-field-reference)
10. [Common SPL Patterns](#10-common-spl-patterns)

---

## 1. SPL Search Language

SecOps Console supports a Splunk-inspired search language in the Log Explorer. Queries run against the `raw_logs` table.

### Basic Syntax

```
[field=value] [AND|OR field=value] [| pipe command]
```

### Free-text search
Searches the `message` field for any word or phrase.

```
failed login
authentication failure
powershell bypass
```

### Field equality
```
action=login_failure
severity=critical
category=authentication
processName=powershell.exe
```

### Comparison operators
```
risk_score>=75
risk_score>50
port<1024
bytesOut>1000000
```

### Wildcards
Use `*` as a wildcard character.

```
process=powershell*
hostname=DC*
src_ip=10.0.*
dns_query=*.malware.*
```

### Boolean logic
```
severity=critical OR severity=high
src_ip=10.0.0.5 AND action=login_failure
category=authentication AND NOT action=login_success
process=powershell* AND NOT user=SYSTEM
```

### Pipe operators

```
# Count events grouped by a field
* | stats count by hostname
action=login_failure | stats count by src_ip

# Sort results
* | sort -risk_score
action=login_failure | stats count by username | sort -count

# Limit results
severity=critical | head 20
```

### Field aliases (short names)

| Alias | Full Field |
|---|---|
| `src` / `src_ip` | `sourceIp` |
| `dst` / `dst_ip` | `destIp` |
| `host` | `hostname` |
| `user` | `username` |
| `process` / `proc` | `processName` |
| `cmd` | `processCommandLine` |
| `risk` | `riskScore` |
| `country` | `srcGeoCountry` |
| `dns_query` | `dnsQuery` |
| `status_code` | `httpStatusCode` |
| `port` | `destPort` |
| `proto` | `protocol` |

### Time range

Use the time picker in the UI, or add `earliest=` / `latest=` filters:

```
earliest=-24h severity=critical
earliest=-1h action=login_failure
```

---

## 2. Detection Rule YAML Format

Rules are stored as Sigma-compatible YAML. Here is the full structure:

```yaml
# ── Required fields ─────────────────────────────
name: My Detection Rule Name
description: 'What this rule detects and why it matters'
severity: high           # critical | high | medium | low | info
type: simple             # simple | threshold | sequence | spl_saved_search

# ── Log source ──────────────────────────────────
logsource:
  category: windows      # windows | linux | aws | azure | network | dns | proxy | auth | endpoint
  product: '*'           # '*' means any product within that category

# ── Detection conditions ─────────────────────────
detection:
  selection:
    field_name: "value"
    field_name|modifier: "value"
    field_name|modifier|any:
      - "value1"
      - "value2"
  condition: selection   # boolean expression over selection names

# ── MITRE ATT&CK ──────────────────────────────────
mitre:
  tactic: Execution
  technique_id: T1059.001
  technique_name: "Command and Scripting Interpreter: PowerShell"

# ── Alert output ──────────────────────────────────
alert:
  title_template: "Rule fired on {sourceHost} by {userName}"
  context_fields: [processCommandLine, userName, sourceHost]

# ── Tags ──────────────────────────────────────────
tags: [powershell, execution]

# ── Deduplication & rate limiting (optional) ─────
dedup_window: "10m"      # suppress duplicate alerts within this window
max_alerts_per_hour: 10  # maximum alerts fired per hour for this rule
```

---

## 3. Rule Types

### `simple` — Single-event matching

Fires once per matching event. Most common rule type.

```yaml
type: simple
detection:
  selection:
    category: "authentication"
    action: "login_success"
    logonType: 10
    srcIp|not|cidr:
      - "10.0.0.0/8"
      - "192.168.0.0/16"
  condition: selection
```

### `threshold` — Count-based matching

Fires when N events matching the condition occur within a time window, grouped by a field.

```yaml
type: threshold
detection:
  selection:
    category: "authentication"
    action: "login_failure"
  condition: selection
threshold:
  field: srcIp          # group events by this field
  count: 5              # fire when this many events occur
  timeframe: "5m"       # within this time window
```

Supported timeframes: `1m`, `5m`, `10m`, `15m`, `30m`, `1h`, `6h`, `24h`

### `sequence` — Ordered multi-step correlation

Fires when two or more events match in order, with the same value in a correlation field.

```yaml
type: sequence
sequence:
  steps:
    - match:
        category: "iam"
        action: "user_created"
    - match:
        category: "authentication"
        action: "login_success"
  timeframe: "30m"      # both steps must occur within this window
  by_field: userName    # both events must share the same value for this field
```

### `spl_saved_search` — Scheduled SPL query

Runs a SPL query on a schedule and fires an alert when results exceed the threshold.

Created from the **Save as Alert** button in the Log Explorer.

```yaml
type: spl_saved_search
splQuery: "action=login_failure | stats count by src_ip"
splThreshold: 10          # fire if result count >= this
scheduleInterval: "5m"   # run every 5 minutes
```

---

## 4. Field Modifiers

Modifiers change how a field value is compared. Chain them with `|`.

| Modifier | Meaning | Example |
|---|---|---|
| `contains` | Substring match | `processCommandLine\|contains: "IEX"` |
| `any` | Match any value in list | `processName\|contains\|any: ["cmd.exe", "powershell.exe"]` |
| `not` | Negate the condition | `srcIp\|not\|cidr: "10.0.0.0/8"` |
| `re` | PCRE regex match | `httpUrl\|re: ".*\\.php\\?cmd=.*"` |
| `startswith` | Prefix match | `processName\|startswith: "svchost"` |
| `endswith` | Suffix match | `filePath\|endswith: ".ps1"` |
| `gt` | Greater than (numeric) | `bytesOut\|gt: 1000000` |
| `gte` | Greater than or equal | `riskScore\|gte: 75` |
| `lt` | Less than (numeric) | `dstPort\|lt: 1024` |
| `lte` | Less than or equal | `severity_score\|lte: 3` |
| `cidr` | IP subnet check | `srcIp\|cidr: "192.168.0.0/16"` |
| `exists` | Field presence check | `processCommandLine\|exists: true` |

### Combining modifiers

```yaml
# Contains AND any of these values
processCommandLine|contains|any:
  - "mimikatz"
  - "sekurlsa"
  - "lsadump"

# NOT in any of these subnets
srcIp|not|cidr:
  - "10.0.0.0/8"
  - "172.16.0.0/12"
  - "192.168.0.0/16"

# Regex match (case sensitive by default)
httpUrl|re: "(?i).*(union|select|drop|insert|update).*"
```

---

## 5. MITRE ATT&CK Mapping

Every rule should reference the relevant ATT&CK technique. The Rule Builder includes a searchable MITRE picker.

Common mappings:

| Tactic | Technique ID | Name |
|---|---|---|
| Initial Access | T1078 | Valid Accounts |
| Initial Access | T1566.001 | Phishing: Spearphishing Attachment |
| Execution | T1059.001 | PowerShell |
| Execution | T1059.003 | Windows Command Shell |
| Persistence | T1547.001 | Registry Run Keys |
| Persistence | T1053.005 | Scheduled Task |
| Persistence | T1136.001 | Create Account: Local Account |
| Privilege Escalation | T1134 | Access Token Manipulation |
| Privilege Escalation | T1055 | Process Injection |
| Defense Evasion | T1218 | Signed Binary Proxy Execution |
| Credential Access | T1110 | Brute Force |
| Credential Access | T1003 | OS Credential Dumping |
| Credential Access | T1558.003 | Kerberoasting |
| Credential Access | T1550.002 | Pass the Hash |
| Discovery | T1046 | Network Service Discovery |
| Lateral Movement | T1021.001 | Remote Desktop Protocol |
| Lateral Movement | T1021.002 | SMB/Windows Admin Shares |
| Collection | T1074 | Data Staged |
| Exfiltration | T1041 | Exfiltration Over C2 Channel |
| Exfiltration | T1048 | Exfiltration Over Alternative Protocol |
| Command & Control | T1071.004 | Application Layer Protocol: DNS |
| Command & Control | T1095 | Non-Application Layer Protocol |

---

## 6. Detection Rule Examples

### Example 1 — Office Macro Dropper (simple)

Detects Microsoft Office applications spawning command shells — typical malicious macro behaviour.

```yaml
name: Office Application Spawning Shell
description: 'Office app (Word/Excel/Outlook) spawning cmd or PowerShell — likely macro dropper'
severity: critical
type: simple
logsource:
  category: windows
  product: '*'
detection:
  selection:
    category: "process"
    action: "process_create"
    parentProcessName|contains|any:
      - "WINWORD.EXE"
      - "EXCEL.EXE"
      - "OUTLOOK.EXE"
      - "POWERPNT.EXE"
    processName|contains|any:
      - "cmd.exe"
      - "powershell.exe"
      - "wscript.exe"
      - "mshta.exe"
  condition: selection
mitre:
  tactic: Initial Access
  technique_id: T1566.001
  technique_name: "Phishing: Spearphishing Attachment"
alert:
  title_template: "Macro dropper: {parentProcessName} spawned {processName} on {sourceHost}"
  context_fields: [parentProcessName, processName, processCommandLine, userName, sourceHost]
tags: [phishing, macro, office, initial-access]
dedup_window: "5m"
```

---

### Example 2 — Admin Share Enumeration (threshold)

Detects repeated SMB connections to admin shares (C$, ADMIN$, IPC$) from a single source.

```yaml
name: Admin Share Enumeration
description: 'Multiple connections to administrative shares from same source — possible lateral movement recon'
severity: high
type: threshold
logsource:
  category: network
  product: '*'
detection:
  selection:
    category: "network"
    action: "network_connection"
    dstPort: 445
    rawLog|contains|any:
      - "ADMIN$"
      - "C$"
      - "IPC$"
  condition: selection
threshold:
  field: srcIp
  count: 5
  timeframe: "10m"
mitre:
  tactic: Lateral Movement
  technique_id: T1021.002
  technique_name: "Remote Services: SMB/Windows Admin Shares"
alert:
  title_template: "Admin share enumeration from {srcIp} — {count} connections"
  context_fields: [srcIp, dstIp, dstPort, userName, sourceHost]
tags: [lateral-movement, smb, enumeration]
max_alerts_per_hour: 5
dedup_window: "15m"
```

---

### Example 3 — LOLBIN Execution via Certutil (simple)

Detects `certutil.exe` used as a Living-off-the-Land Binary for file downloads.

```yaml
name: Certutil LOLBIN File Download
description: 'certutil.exe used to download a remote file — common attacker technique to bypass AV'
severity: high
type: simple
logsource:
  category: windows
  product: '*'
detection:
  selection:
    category: "process"
    action: "process_create"
    processName|contains: "certutil"
    processCommandLine|contains|any:
      - "-urlcache"
      - "-decode"
      - "-encode"
      - "http://"
      - "https://"
  condition: selection
mitre:
  tactic: Defense Evasion
  technique_id: T1140
  technique_name: "Deobfuscate/Decode Files or Information"
alert:
  title_template: "Certutil LOLBIN on {sourceHost} by {userName}"
  context_fields: [processCommandLine, userName, sourceHost, processName, parentProcessName]
tags: [lolbin, certutil, defense-evasion]
dedup_window: "10m"
```

---

### Example 4 — High-Volume Outbound DNS (threshold + SPL)

Option A — Detection Rule:

```yaml
name: DNS Exfiltration Candidate
description: 'Single host generating 20+ DNS queries per minute — possible tunneling or DGA'
severity: high
type: threshold
logsource:
  category: dns
  product: '*'
detection:
  selection:
    category: "dns"
    action: "dns_query"
  condition: selection
threshold:
  field: sourceHost
  count: 20
  timeframe: "1m"
mitre:
  tactic: Command and Control
  technique_id: T1071.004
  technique_name: "Application Layer Protocol: DNS"
alert:
  title_template: "DNS flood from {sourceHost} — {count} queries in 1 min"
  context_fields: [sourceHost, dnsQuery, srcIp]
tags: [dns, tunneling, exfiltration]
max_alerts_per_hour: 5
dedup_window: "10m"
```

Option B — SPL Saved Alert (from Log Explorer):

```
category=dns | stats count by hostname | sort -count
```
Save as alert → threshold: 20, interval: 1m

---

### Example 5 — Suspicious Process Injection (sequence)

Detects `VirtualAllocEx` followed by `WriteProcessMemory` patterns associated with process injection.

```yaml
name: Process Injection Pattern
description: 'Remote thread creation into another process — classic process injection indicator'
severity: critical
type: sequence
logsource:
  category: windows
  product: '*'
sequence:
  steps:
    - match:
        category: "process"
        action: "process_access"
    - match:
        category: "process"
        action: "create_remote_thread"
  timeframe: "2m"
  by_field: sourceHost
mitre:
  tactic: Defense Evasion
  technique_id: T1055
  technique_name: "Process Injection"
alert:
  title_template: "Process injection detected on {sourceHost}"
  context_fields: [processName, userName, sourceHost, processCommandLine]
tags: [process-injection, defense-evasion]
dedup_window: "30m"
```

---

### Example 6 — Failed Login then Immediate Success (sequence)

Classic pattern of a successful brute-force attack — multiple failures then a success.

```yaml
name: Brute Force Followed by Successful Login
description: 'Failed login attempts from same IP followed by a success — brute force compromise indicator'
severity: critical
type: sequence
logsource:
  category: authentication
  product: '*'
sequence:
  steps:
    - match:
        category: "authentication"
        action: "login_failure"
    - match:
        category: "authentication"
        action: "login_success"
  timeframe: "10m"
  by_field: srcIp
mitre:
  tactic: Credential Access
  technique_id: T1110
  technique_name: Brute Force
alert:
  title_template: "Brute force success: {userName} from {srcIp} on {sourceHost}"
  context_fields: [srcIp, userName, sourceHost, logonType]
tags: [brute-force, credential-access]
dedup_window: "1h"
```

---

## 7. SPL Saved Alerts

Save any SPL query as a recurring detection alert via the **Save as Alert** button in the Log Explorer.

### How it works

1. Write a SPL query in the Log Explorer
2. Click **Save as Alert** (top right)
3. Configure name, severity, trigger mode, threshold, and schedule interval
4. The scheduler runs your query every N minutes
5. If results ≥ threshold, an alert is created automatically

### Useful SPL alert queries

**Failed logins by country (geo anomaly)**
```
action=login_failure | stats count by src_country | sort -count
```
Threshold: 5, Interval: 15m — fire when 5+ countries have failures in 15 min

**New admin account activity**
```
category=iam AND (action=user_created OR action=member_added_to_global_group)
```
Threshold: 1, Interval: 5m — fire on any IAM change

**Large DNS responses (data exfil)**
```
category=dns AND dns_query=* | stats count by hostname | sort -count
```
Threshold: 50, Interval: 5m

**After-hours authentication**
```
action=login_success AND NOT src_ip=10.0.0.0/8
```
Threshold: 1, Interval: 1m — fire on any external success login

**Lateral movement to many hosts**
```
action=login_success AND category=authentication | stats count by src_ip
```
Threshold: 10, Interval: 5m

---

## 8. Testing Your Rules

### From the Rule Builder

1. Open Rule Builder → set conditions
2. Click **Test Rule** (runs against last 1000 real logs)
3. Check the matched count and sample events
4. Adjust conditions and re-test until match rate looks right

### Via API

```bash
curl -X POST http://localhost:8080/api/rules/<ruleId>/test \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"sampleSize": 500}'
```

Response:
```json
{
  "matched": 12,
  "total": 500,
  "passed": true,
  "examples": ["Windows Event 4688: process_create user=jsmith from=10.0.1.5"]
}
```

### With sample logs

Send sample data from the `sample-logs/` directory and watch the Alert Queue for newly created alerts.

```bash
# Ingest brute-force sample and check for alert
while IFS= read -r line; do
  curl -s -X POST http://localhost:8080/api/ingest-log \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"source\":\"windows_eventlog\",\"message\":$(python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))' <<< "$line")}"
done < sample-logs/01-brute-force-windows.jsonl

# List recent alerts
curl -s http://localhost:8080/api/alerts?limit=5 \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

---

## 9. Normalised Field Reference

These are the fields available after log parsing. Use them in both SPL queries and detection rule conditions.

### Network fields

| Field | Type | Description |
|---|---|---|
| `sourceIp` / `srcIp` | string | Source IP address |
| `destIp` / `dstIp` | string | Destination IP address |
| `sourcePort` / `srcPort` | number | Source port |
| `destPort` / `dstPort` | number | Destination port |
| `protocol` | string | Network protocol (TCP, UDP, ICMP) |
| `direction` | string | `inbound` or `outbound` |
| `bytesIn` | number | Bytes received |
| `bytesOut` | number | Bytes sent |

### Host & identity fields

| Field | Type | Description |
|---|---|---|
| `hostname` | string | Source host / computer name |
| `userName` | string | Primary user |
| `targetUserName` | string | Target user (e.g., account being created) |
| `userId` | string | User SID or numeric ID |
| `userDomain` | string | Domain name |
| `logonType` | number | Windows logon type (2=interactive, 3=network, 10=RDP) |

### Process fields

| Field | Type | Description |
|---|---|---|
| `processName` | string | Process executable name |
| `processId` | number | Process ID |
| `processCommandLine` | string | Full command line including arguments |
| `parentProcessName` | string | Parent process name |
| `parentProcessId` | number | Parent process ID |

### DNS fields

| Field | Type | Description |
|---|---|---|
| `dnsQuery` | string | DNS query domain |
| `dnsRecordType` | string | Record type (A, TXT, MX, etc.) |
| `dnsResponseCode` | string | Response code (NOERROR, NXDOMAIN) |

### HTTP fields

| Field | Type | Description |
|---|---|---|
| `httpMethod` | string | HTTP method (GET, POST, PUT) |
| `httpUrl` | string | Full URL |
| `httpStatusCode` | number | HTTP response code |
| `httpUserAgent` | string | User-agent string |

### File & registry fields

| Field | Type | Description |
|---|---|---|
| `filePath` | string | Full file path |
| `fileHash` | string | MD5/SHA256 hash |
| `registryKey` | string | Full registry key path |
| `registryValue` | string | Registry value data |

### Classification fields

| Field | Type | Description |
|---|---|---|
| `category` | string | Log category (authentication, process, dns, iam, network, firewall, registry) |
| `action` | string | Specific action (login_success, login_failure, process_create, dns_query, etc.) |
| `outcome` | string | `success`, `failure`, or `blocked` |
| `severity` | string | `critical`, `high`, `medium`, `low`, `info` |
| `riskScore` | number | Computed 0–100 risk score |
| `sourceType` | string | Log format (windows_eventlog, syslog, cef, cloudtrail, etc.) |

### Geo/enrichment fields

| Field | Type | Description |
|---|---|---|
| `srcGeoCountry` | string | Source IP country code |
| `srcGeoCity` | string | Source IP city |
| `dstGeoCountry` | string | Destination IP country code |
| `assetCriticality` | string | Asset criticality from asset database |

---

## 10. Common SPL Patterns

Copy-paste these directly into the Log Explorer.

### Authentication investigations

```
# All failed logins in the last hour
action=login_failure earliest=-1h

# Failed logins from a specific IP
src_ip=203.0.113.45 AND action=login_failure

# Successful logins from outside the corporate network
action=login_success AND NOT src_ip=10.0.0.0/8 AND NOT src_ip=192.168.0.0/16

# Logins by a specific user
user=jsmith AND category=authentication

# RDP logins (logon type 10)
action=login_success AND logonType=10

# Multiple failed logins grouped by source
action=login_failure | stats count by src_ip | sort -count

# Brute force candidates (>10 failures from same IP)
action=login_failure | stats count by src_ip | sort -count
```

### Process & execution investigations

```
# All PowerShell executions
process=powershell*

# PowerShell with suspicious flags
process=powershell* AND (cmd=-enc OR cmd=-nop OR cmd=hidden)

# Scripts with encoded commands
cmd=-EncodedCommand

# Processes spawned by Office apps
parentProcessName=WINWORD* OR parentProcessName=EXCEL*

# New scheduled tasks
category=scheduled_task

# Process creation by hostname
category=process AND hostname=WORKSTATION01*
```

### Network & DNS investigations

```
# DNS queries to suspicious TLDs
dns_query=*.xyz OR dns_query=*.tk OR dns_query=*.top

# All DNS queries from a host
category=dns AND host=WORKSTATION05

# Outbound connections to non-standard ports
dst_port>49152 AND category=network AND direction=outbound

# Large outbound transfers
bytesOut>10485760 AND direction=outbound

# Connections to specific IP
dst_ip=185.220.101.55

# Blocked firewall connections
category=firewall AND action=connection_blocked
```

### Threat hunting queries

```
# High-risk events in last 24h
risk_score>=80 earliest=-24h

# All critical events
severity=critical

# Events from high-risk countries
country=RU OR country=CN OR country=KP OR country=IR

# Credential dumping indicators
cmd=mimikatz OR cmd=sekurlsa OR cmd=lsadump OR cmd=procdump

# Living-off-the-land binaries
process=certutil* OR process=bitsadmin* OR process=regsvr32* OR process=mshta*

# Lateral movement indicators
action=service_install OR (action=login_success AND logonType=3 AND NOT src_ip=10.0.0.0/8)

# Persistence mechanisms
category=registry AND action=registry_modify AND registryKey=*CurrentVersion*Run*

# C2 communication patterns
dns_query=*.xyz AND category=dns
bytesOut>524288000 AND direction=outbound
```

### Cloud (CloudTrail) investigations

```
# All CloudTrail events
sourceType=cloudtrail

# Root account usage
sourceType=cloudtrail AND category=authentication

# IAM changes
sourceType=cloudtrail AND category=iam

# S3 bucket policy changes
sourceType=cloudtrail AND action=PutBucketPolicy

# Failed API calls
sourceType=cloudtrail AND outcome=failure
```
