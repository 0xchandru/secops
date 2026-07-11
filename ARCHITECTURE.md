<div align="center">

# SecOps Console — Architecture Reference

</div>

> **Stack:** React 19 + TypeScript · Node.js 22 + Express 5 · PostgreSQL 15 · Redis 7  
> **Purpose:** Production-grade mini-SIEM demonstrating SOC L1 workflows, detection engineering, and real-time event processing

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Log Ingestion & Parser Registry](#2-log-ingestion--parser-registry)
3. [Detection Engine](#3-detection-engine)
4. [Enrichment Pipeline](#4-enrichment-pipeline)
5. [SPL Search Engine](#5-spl-search-engine)
6. [Alert Lifecycle & SOC Workflow](#6-alert-lifecycle--soc-workflow)
7. [Redis Pipeline Architecture](#7-redis-pipeline-architecture)
8. [Database Schema](#8-database-schema)
9. [RBAC & Auth Model](#9-rbac--auth-model)
10. [Real-time Streaming](#10-real-time-streaming)
11. [Scheduler](#11-scheduler)
12. [Frontend Architecture](#12-frontend-architecture)
13. [API Module Map](#13-api-module-map)
14. [Design Decisions](#14-design-decisions)

---

## 1. System Overview

```
┌──────────────────────────────────────────────────────────────────────────┐
│                     ANALYST UI  (React 19 + Vite 7)                      │
│                                                                          │
│  Dashboard · AlertQueue · AlertDetail · LogExplorer · RuleBuilder        │
│  MITRE Heatmap · Assets · AuditLog · Users · Settings · Notifications   │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │  TanStack Query v5 (server state) │ Zustand (client state)      │    │
│  │  WebSocket hooks (alerts, events, notifications)                │    │
│  └─────────────────────────────────────────────────────────────────┘    │
└──────────────┬────────────────────────────┬──────────────────────────────┘
               │ HTTP /api                  │ ws:// /ws/alerts
               │                            │ ws:// /ws/events/live
               │                            │ ws:// /ws/notifications
               ▼                            ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    API SERVER  (Express 5 + TypeScript)                   │
│                                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐ │
│  │  Auth /  │  │ Parser   │  │Detection │  │Enrichment│  │  SPL     │ │
│  │  RBAC    │  │ Registry │  │ Engine   │  │ Pipeline │  │  Search  │ │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────┘ │
│                                                                          │
│  ┌───────────────────────────┐   ┌──────────────────────────────────┐  │
│  │  Redis Streams Worker     │   │  Scheduler (node-cron)           │  │
│  │  Consumer group           │   │  SPL alerts · cache refresh      │  │
│  └───────────────────────────┘   └──────────────────────────────────┘  │
└──────────────┬───────────────────────────────────┬───────────────────────┘
               │                                   │
       ┌───────▼────────┐                ┌─────────▼────────┐
       │  PostgreSQL 15  │                │     Redis 7       │
       │                │                │                   │
       │  users         │                │  Streams          │
       │  roles         │                │  Pub/Sub          │
       │  permissions   │                │  Cache (auth,     │
       │  raw_logs      │                │  assets, stats)   │
       │  rules         │                │                   │
       │  alerts        │                └──────────────────┘
       │  alert_timeline│
       │  assets        │       ┌──────────────┐
       │  audit_logs    │       │ Syslog Recv  │
       │  notifications │       │ UDP + TCP    │
       │  api_keys      │       │ port 1514    │
       └────────────────┘       └──────────────┘
```

**Data flow in one sentence:** raw logs arrive via HTTP or UDP/TCP syslog → the parser registry normalises them into a `ParsedEvent` → the enrichment pipeline adds GeoIP and risk scores → the detection engine evaluates active rules → matching rules create alerts → alerts are pushed to analysts via WebSocket.

---

## 2. Log Ingestion & Parser Registry

### Ingestion Endpoints

| Endpoint | Use Case |
|---|---|
| `POST /api/ingest-log` | Single structured JSON event |
| `POST /api/ingest/bulk` | Array of events in one request |
| `POST /api/ingest/raw?source=<format>` | Raw log text (syslog, CEF, …) |
| UDP/TCP `:1514` | Network syslog forwarding |

### Parser Selection Logic

The registry selects a parser using priority routing — explicit `source` field first, then auto-detection heuristics:

```
Raw Log Text / JSON
      │
      ▼
  Format Detection
  ┌──────────────────────────────────────────────────────────┐
  │  sourceType field?   ──► route to named parser           │
  │  Starts with "<"?    ──► SyslogParser                    │
  │  Has EventID field?  ──► WindowsEventLogParser           │
  │  Has CEF:0 header?   ──► CEFParser                       │
  │  Has ecs.version?    ──► ECSJsonParser                   │
  │  Has LEEF:1.0?       ──► LEEFParser                      │
  │  Has eventSource?    ──► CloudTrailParser                │
  │  Fallback            ──► GenericParser                   │
  └──────────────────────────────────────────────────────────┘
      │
      ▼
  ParsedEvent (80+ normalised fields)
```

### Parser Coverage

| Parser | Source Types | Coverage |
|---|---|---|
| `SyslogParser` | syslog, rsyslog, syslog-ng | 20+ programs (sshd, sudo, cron, nginx, named, …) |
| `WindowsEventLogParser` | windows_eventlog | 40+ EventIDs, Sysmon event types 1–25 |
| `FirewallParser` | firewall | ASA, iptables, pfSense, Palo Alto |
| `CEFParser` | cef | ArcSight Common Event Format |
| `ECSJsonParser` | ecs | Elastic Common Schema JSON |
| `LEEFParser` | leef | IBM QRadar LEEF 1.0 and 2.0 |
| `CloudTrailParser` | cloudtrail | AWS CloudTrail management + data events |
| `DNSParser` | dns | BIND, Windows DNS, Zeek |
| `GenericParser` | * | Key=Value, JSON, and free-text fallback |

### Normalised Event Model

Every parser outputs a `ParsedEvent` with these field groups:

| Group | Fields |
|---|---|
| Network | `sourceIp`, `destIp`, `sourcePort`, `destPort`, `protocol`, `direction` |
| Host | `hostname`, `deviceType`, `osType` |
| Identity | `username`, `userId`, `domain` |
| Process | `processName`, `processId`, `processCommandLine`, `parentProcess` |
| HTTP | `httpMethod`, `httpUrl`, `httpStatus`, `userAgent` |
| DNS | `dnsQuery`, `dnsResponseCode`, `dnsAnswers` |
| File | `filePath`, `fileHash`, `fileSize` |
| Registry | `registryKey`, `registryValue` |
| Vendor | `vendorProduct`, `vendorAction`, `logSource` |
| Enrichment | `srcGeoCountry`, `dstGeoCountry`, `srcGeoCity`, `assetCriticality`, `riskScore` |
| Timestamps | `parsedTimestamp` (extracted from log), `createdAt` (DB insert) |

---

## 3. Detection Engine

### Rule Evaluation Loop

```
Ingested Event
      │
      ▼
  Pre-filter Index
  (fast hash lookup by field presence — skip rules
   that can't possibly match this event's fields)
      │
      ├─► simple rule   ──► evaluate field conditions + modifiers ──► match? → create alert
      │
      ├─► threshold     ──► sliding window count by groupField ──► count ≥ N in window? → alert
      │
      └─► sequence      ──► ordered step state machine ──► all steps matched in order? → alert
```

### Field Modifiers

| Modifier | Operator | Example |
|---|---|---|
| `contains` | substring match | `processCommandLine\|contains: "powershell"` |
| `any` | match any value in list | `processCommandLine\|contains\|any: ["IEX", "DownloadString"]` |
| `re` | PCRE regex | `httpUrl\|re: ".*\.php\?cmd=.*"` |
| `gt` / `gte` | numeric comparison | `failedLoginCount\|gt: 5` |
| `lt` / `lte` | numeric comparison | `riskScore\|lte: 30` |
| `cidr` | IP subnet match | `sourceIp\|cidr: "10.0.0.0/8"` |
| `exists` | field presence check | `processCommandLine\|exists: true` |
| `not` | negation | `username\|not: "svc-*"` |
| `startswith` | prefix match | `processName\|startswith: "cmd"` |
| `endswith` | suffix match | `filePath\|endswith: ".ps1"` |

### Alert Deduplication & Rate Limiting

- Each rule can set `dedupWindow` (seconds). A second identical alert from the same rule within the window is suppressed.
- `rateLimit` caps how many alerts a rule can fire per minute, preventing storm conditions.
- Both values are tracked in a Redis hash per rule ID.

### Seeded Detection Rules (15)

| # | Rule | MITRE Tactic | MITRE ID |
|---|---|---|---|
| 1 | Brute Force Login Attempt | Credential Access | T1110 |
| 2 | Successful Login After Brute Force | Credential Access | T1110 |
| 3 | PowerShell Suspicious Execution | Execution | T1059.001 |
| 4 | PsExec-style Lateral Movement | Lateral Movement | T1021 |
| 5 | Kerberoasting Activity | Credential Access | T1558.003 |
| 6 | LSASS Credential Dumping | Credential Access | T1003.001 |
| 7 | Suspicious DNS Query | Command & Control | T1071.004 |
| 8 | CloudTrail Root Account Usage | Privilege Escalation | T1078 |
| 9 | Unusual Admin Login from New Country | Initial Access | T1078 |
| 10 | Outbound Traffic to Threat Country | Exfiltration | T1041 |
| 11 | Windows Service Created | Persistence | T1543.003 |
| 12 | Privilege Escalation via Sudo | Privilege Escalation | T1548 |
| 13 | Registry Run Key Persistence | Persistence | T1547.001 |
| 14 | Port Scan Detected | Discovery | T1046 |
| 15 | SSH Brute Force | Credential Access | T1110.003 |

---

## 4. Enrichment Pipeline

### Per-Event Enrichment (inline, on every ingest)

```
ParsedEvent
    │
    ├─► GeoIP lookup (sourceIp)  ──► srcGeoCountry, srcGeoCity, srcGeoLat/Lon
    ├─► GeoIP lookup (destIp)    ──► dstGeoCountry, dstGeoCity
    ├─► Asset cache lookup       ──► assetCriticality (critical/high/medium/low)
    └─► Risk score calculation   ──► riskScore (0–100)
```

### Risk Score Factors

| Factor | Max Weight | Signal |
|---|---|---|
| Severity | 30 | critical=30, high=22, medium=12, low=5 |
| Outcome | 20 | failure=20, blocked=15, success=10 |
| User | 15 | privileged username keywords (admin, root, sa, …) |
| Asset criticality | 15 | critical=+15, high=+10, medium=+5 |
| Network direction | 10 | inbound from unknown external = +10 |
| Geo-country | 10 | high-risk country code list |

### ThreatLens Enrichment (on-demand, per alert)

The ThreatLens panel on AlertDetail runs a 6-step enrichment pipeline against alert IPs, domains, and file hashes:

```
Alert IPs / Domains / Hashes
    │
    ├─► IP Reputation        (known threat actor ranges, TOR exits, scanners)
    ├─► Domain Intelligence  (DGA scoring, sinkhole, malware families)
    ├─► Vulnerability Scan   (CVE associations for affected hosts)
    ├─► Geolocation Context  (full city + ASN + organisation)
    ├─► Threat Intelligence  (MITRE technique cross-references)
    └─► Risk Assessment      (composite verdict: malicious / suspicious / benign)
```

---

## 5. SPL Search Engine

Queries are parsed into an AST then evaluated against `raw_logs` in PostgreSQL.

### Supported Syntax

```spl
# Free-text search (searches the message field)
failed authentication

# Field equality
action=login_failure

# Comparison operators
risk_score>=75
port<1024

# Boolean logic
src_ip=10.0.0.5 AND action=login_failure
severity=critical OR severity=high

# Wildcard
process=powershell* AND NOT user=svc*

# Pipe operators
* | stats count by hostname
* | sort -timestamp
* | head 100

# Combined example
src_country=RU AND action=login_success | stats count by username | sort -count
```

### Field Aliases

| Alias | Maps to |
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

---

## 6. Alert Lifecycle & SOC Workflow

### Status State Machine

```
                   ┌─────────────────────────┐
                   │          new            │  ← alert created by detection engine
                   └────────────┬────────────┘
                                │  investigate
                                ▼
                   ┌─────────────────────────┐
                   │      investigating      │  ← analyst opened the alert
                   └────────┬────────┬───────┘
                            │        │
                    resolve │        │ mark false positive
                            ▼        ▼
                   ┌──────────┐  ┌───────────────┐
                   │ resolved │  │ false_positive │
                   └──────────┘  └───────────────┘
                            ▲
                            │  reopen
                            └───────── (from any closed state)
```

### Alert Actions

| Action | Payload | Minimum Role |
|---|---|---|
| `investigate` | — | soc_l1+ |
| `resolve` | `{ resolutionNotes? }` | soc_l2+ |
| `false_positive` | — | soc_l2+ |
| `reopen` | — | soc_l2+ |
| `assign` | `{ assignTo: userId }` | soc_l1+ |
| `unassign` | — | soc_l1+ |
| `add_note` | `{ noteContent: string }` | soc_l1+ |
| `escalate` | `{ escalateTo: userId, reason: string }` | soc_l2+ |

### Escalation Routing

Escalation targets are determined by role priority: an soc_l2 analyst can escalate to soc_manager or admin; soc_l1 can escalate to soc_l2+. The `usersApi.escalationTargets(role)` endpoint returns only valid targets for the current user's role.

---

## 7. Redis Pipeline Architecture

### Log Ingestion Pipeline (async path)

```
POST /api/ingest/bulk
      │
      ▼
  XADD secops:log_queue  ──►  Consumer Group: secops-workers
                                      │
                                      ▼
                              Worker (src/workers/)
                              ┌─────────────────────────────┐
                              │ 1. Parse (parser registry)  │
                              │ 2. Normalise (ParsedEvent)  │
                              │ 3. Enrich (GeoIP + asset)   │
                              │ 4. Persist (raw_logs table) │
                              │ 5. Run detection engine     │
                              │ 6. Broadcast alert via WS   │
                              └─────────────────────────────┘
                              ├─► ACK on success
                              ├─► 3× retry on failure
                              └─► Dead-letter queue on 3rd fail
```

### Pub/Sub Channels

| Channel | Publisher | Subscriber |
|---|---|---|
| `secops:new_alert` | Detection engine | WebSocket handler → `AlertQueue` clients |
| `secops:new_event` | Worker | WebSocket handler → `LogExplorer` live tail |
| `secops:notification` | Any backend action | WebSocket handler → notification bell |

### Cache Keys

| Key Pattern | TTL | Contents |
|---|---|---|
| `secops:perm:{userId}` | 5 min | Effective permission set for a user |
| `secops:assets` | 5 min | Full asset criticality map |
| `secops:dashboard:stats` | 60 sec | Pre-computed dashboard aggregates |
| `secops:eps` | rolling | Events-per-second ring buffer |
| `secops:rule:dedup:{ruleId}` | configurable | Deduplication window per rule |
| `secops:rule:rate:{ruleId}` | 60 sec | Rate limit counter per rule |

---

## 8. Database Schema

### Core Tables

```
users                   roles                   permissions
├── id (uuid)           ├── id                  ├── id
├── username            ├── name                ├── resource
├── passwordHash        ├── displayName         ├── action
├── email               ├── priority            └── description
├── displayName         └── description
├── role (legacy)                               role_permissions
└── isActive                                    ├── roleId → roles.id
                                                └── permissionId → permissions.id
user_roles
├── userId → users.id
└── roleId → roles.id

raw_logs                                        rules
├── id (uuid)                                   ├── id (uuid)
├── source / sourceType                         ├── name / description
├── message (raw)                               ├── severity
├── severity / category                         ├── ruleType (simple/threshold/sequence/spl)
├── sourceIp / destIp / hostname                ├── yamlContent (Sigma YAML)
├── username / userId                           ├── splQuery / splThreshold
├── eventType / action / outcome                ├── scheduleInterval
├── processName / processCommandLine            ├── enabled / triggerCount
├── dnsQuery / httpMethod / filePath            ├── lastRunAt
├── srcGeoCountry / dstGeoCountry              ├── mitreIds / mitreTactic
├── riskScore / assetCriticality               └── exceptions (jsonb)
├── parsedTimestamp / createdAt
└── processed (bool)

alerts                  alert_timeline          alert_state_transitions
├── id (uuid)           ├── id                  ├── id
├── alertCode           ├── alertId             ├── alertId
├── title               ├── actorId             ├── fromStatus
├── description         ├── actorName           ├── toStatus
├── severity            ├── type                ├── actorId
├── status              ├── content             └── createdAt
├── source / ruleId     └── createdAt
├── ruleName
├── assignedToId        escalation_history      assets
├── mitreIds / mitreTactic  ├── id              ├── id
├── riskScore           ├── alertId             ├── hostname / ip
├── createdAt           ├── fromUserId          ├── assetType
└── resolvedAt          ├── toUserId            ├── criticality
                        ├── reason              └── owner
                        └── createdAt

audit_logs              notifications           api_keys
├── id                  ├── id                  ├── id
├── actorId             ├── userId              ├── userId
├── actorName           ├── type                ├── keyHash
├── action              ├── title               ├── name
├── resource            ├── message             └── lastUsedAt
├── resourceId          ├── read
├── details (jsonb)     └── createdAt           system_settings
└── createdAt                                   ├── key
                                                └── value
```

### Key Indexes

- **`raw_logs`:** `createdAt`, `severity`, `category`, `source`, `sourceIp`, `destIp`, `hostname`, `username`, `eventType`, `action`, `processed`
- **`alerts`:** `status`, `severity`, `createdAt`, `ruleId`, `assignedToId`
- **`audit_logs`:** `actorId`, `resource`, `createdAt`

---

## 9. RBAC & Auth Model

### Role Hierarchy

| Role | Priority | Key Capabilities |
|---|---|---|
| `admin` | 100 | Everything — user/role/permission management, system settings |
| `soc_manager` | 80 | Team management, rule oversight, escalation targets, all alert actions |
| `detection_engineer` | 70 | Rule creation/edit, threat hunting, SPL searches, log analysis |
| `soc_l2` | 60 | Alert triage, investigation, escalation, rule view |
| `soc_l1` | 40 | Alert view/investigate/assign, note-taking, basic triage |
| `viewer` | 20 | View all resources, no mutations |

### Auth Flow

```
POST /auth/login
      │
      ├─► bcrypt.compare(password, hash)
      ├─► load user_roles + permissions from DB
      ├─► cache effective permission set in Redis (5 min TTL)
      ├─► sign accessToken (15 min) + refreshToken (7 days)
      └─► return { accessToken, refreshToken, user }

Subsequent requests:
Authorization: Bearer <accessToken>
      │
      ├─► JWT verify → userId
      ├─► Redis cache hit? → return permissions (fast path)
      ├─► cache miss → query DB → cache → return permissions
      └─► RBAC middleware checks can(resource, action)
```

### Permission Check Pattern

```typescript
// Backend middleware
requirePermission('alerts', 'write')

// Frontend
const { can } = useAuthStore();
if (can('rules:create')) { /* show rule builder button */ }
```

---

## 10. Real-time Streaming

### WebSocket Channels

| Path | Direction | Payload |
|---|---|---|
| `/ws/alerts` | Server → Client | `{ type: "new_alert", data: AlertSummary }` |
| `/ws/events/live` | Server → Client | `{ type: "raw_log", data: ParsedEvent }` |
| `/ws/notifications` | Server → Client | `{ type: "notification", data: Notification }` |

### Connection Lifecycle

```
Client connects → authenticate via query param token
      │
      ├─► Subscribe to Redis Pub/Sub channel
      ├─► Heartbeat ping every 30 s
      └─► On disconnect → unsubscribe, clean up

New alert created
      │
      ▼
Detection engine → PUBLISH secops:new_alert → Redis
                                │
                                ▼
                    WS server subscriber → broadcast to all
                    connected /ws/alerts clients
```

---

## 11. Scheduler

All scheduled tasks run via `node-cron` in the main API process (or a dedicated worker process when `ENABLE_WORKER=true`).

| Task | Schedule | Interval | Purpose |
|---|---|---|---|
| SPL saved search evaluator | `* * * * *` | Every 1 min | Run each enabled `spl` rule, create alert if results ≥ threshold |
| Detection rule reload | `*/1 * * * *` | Every 1 min | Reload rule cache from database |
| Asset cache refresh | `*/5 * * * *` | Every 5 min | Refresh asset criticality map in Redis |
| Dashboard stats cache | `*/1 * * * *` | Every 1 min | Pre-compute dashboard aggregates into Redis |
| Stream cleanup | `0 2 * * *` | Daily 2 AM | Trim old Redis Streams entries |
| Data retention | `0 3 * * *` | Daily 3 AM | Delete `raw_logs` older than retention window |

### SPL Alert Schedule → Lookback Window Mapping

| Interval | Lookback |
|---|---|
| `1m` | 2 minutes |
| `5m` | 10 minutes |
| `15m` | 30 minutes |
| `1h` | 2 hours |
| `6h` | 12 hours |
| `24h` | 48 hours |

---

## 12. Frontend Architecture

### Page Map

| Page | Route | Key Features |
|---|---|---|
| Dashboard | `/` | Real-time stats, MITRE ring, EPS gauge, alert trends, drill-through cards |
| Alert Queue | `/alerts` | Filtering, group-by, bulk actions, WebSocket live updates |
| Alert Detail | `/alerts/:id` | 6-tab view: Overview · Timeline · Related · Enrichment · ThreatLens · Checklist |
| Log Explorer | `/logs` | SPL search, column picker, histogram, live tail, CSV export |
| Detection Rules | `/rules` | Rule list, enable/disable toggle, stats, MITRE mapping |
| Rule Builder | `/rules/new` · `/rules/:id/edit` | Visual condition editor, live Sigma YAML, MITRE picker, test runner |
| MITRE Heatmap | `/mitre` | Coverage matrix across 14 ATT&CK tactics |
| Assets | `/assets` | Asset CRUD, criticality management |
| Audit Log | `/audit` | Filterable audit trail |
| Users | `/users` | User CRUD and role assignment |
| Notifications | `/notifications` | In-app notification feed with read/unread management |
| Settings | `/settings` | Profile · Notifications (Email/Slack) · Security · API Keys · Integrations |

### State Architecture

```
┌──────────────────────────────────────────────────────────┐
│  TanStack Query v5                                       │
│  Server state: alerts, rules, logs, users, dashboard     │
│  Automatic background refetch · Cache invalidation       │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│  Zustand                                                 │
│  authStore — user, permissions, tokens, login/logout     │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│  WebSocket hooks                                         │
│  useAlertStream    → on new_alert, invalidate queries    │
│  useLiveEvents     → append to Log Explorer live buffer  │
│  useNotifications  → update notification bell count      │
└──────────────────────────────────────────────────────────┘
```

### API Client

All requests go through `src/lib/api.ts` which wraps `axios` with:

- Base URL from Vite env (`/api` in dev → Vite proxy → backend)
- `Authorization: Bearer <token>` header from Zustand auth store
- 401 interceptor → attempt token refresh → retry → logout on second failure
- Typed response wrappers per resource

---

## 13. API Module Map

```
secops-backend/src/modules/
├── auth/           POST /auth/login, /auth/refresh, /auth/logout, GET /auth/me
├── me/             GET+PATCH /me, POST /me/password, API key CRUD
├── users/          User CRUD, password reset, escalation targets, role assignment
├── roles/          Role CRUD, permission catalog, role-permission management
├── alerts/         List, detail, status change, assign, escalate, bulk, timeline
├── rules/          List, detail, create, update, delete, toggle, test, stats
├── logs/           SPL search, filter metadata, facets, histogram, host context
├── ingest/         Single, bulk, raw, pending queue, reprocess, manual detection
├── enrichment/     IP + domain lookup, ThreatLens report
├── dashboard/      GET /dashboard/stats (Redis-cached aggregates)
├── assets/         Asset CRUD, hostname/IP lookup
├── audit/          GET /audit with actor/resource/time filters
├── notifications/  List, mark read, mark all read, delete
└── settings/       GET/PATCH system config, test email, test Slack, ThreatLens
```

---

## 14. Design Decisions

| Decision | Rationale |
|---|---|
| **TypeScript end-to-end** | Single language eliminates context-switching; esbuild provides sub-second builds |
| **Drizzle ORM** | Type-safe SQL with plain SQL escape hatch; no runtime magic; fast startup |
| **Redis Streams for log pipeline** | Durable consumer-group semantics, ACK/retry built-in; comparable to Kafka at this scale |
| **GeoIP via `geoip-lite`** | Embedded MaxMind database; no external API call on the hot ingest path |
| **JWT with short-lived access tokens** | 15 min access + 7 day refresh balances security with UX; refresh is httpOnly-ready |
| **Pre-filter index in detection engine** | Skip rules that cannot possibly match based on field presence; critical throughput at high EPS |
| **Redis-cached permission sets** | A DB permission query on every request would serialise all API traffic under load |
| **Sigma-compatible YAML rule format** | Rules readable by industry tooling; pySigma can convert community rules directly |
| **Persistent secrets via Replit DB** | Sensitive values (SMTP password, Slack webhook, API keys) survive container restarts without plaintext `.env` |
