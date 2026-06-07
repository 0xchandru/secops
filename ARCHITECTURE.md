# SecOps Console — Complete SIEM Architecture, Build Plan & Career Guide

> **Project:** SecOps Console — Mini-SIEM with Detection Engine  
> **Author:** Chandru  
> **Stack:** React 19 + TypeScript (frontend) · Node.js + Express 5 + TypeScript (backend) · Python (analytics) · PostgreSQL 18 · Redis 7  
> **Purpose:** Production-grade portfolio project demonstrating SOC L1 engineering, real-time detection, and security operations workflow  
> **Last updated:** July 2025

---

## Table of Contents

1. [Project Evaluation](#1-project-evaluation)
2. [Architecture Direction](#2-architecture-direction)
3. [System Architecture](#3-system-architecture)
4. [SOC L1 Workflow](#4-soc-l1-workflow)
5. [Log Parsing & Normalization](#5-log-parsing--normalization)
6. [Detection Engine](#6-detection-engine)
7. [Database Design](#7-database-design)
8. [SPL-like Search Engine](#8-spl-like-search-engine--implemented)
9. [Risk Scoring & Enrichment](#9-risk-scoring--enrichment--implemented)
10. [Python Integration Plan](#10-python-integration-plan)
11. [Next Tasks — Exact Build Plan](#11-next-tasks--exact-build-plan)
12. [Scripts & Modules to Build](#12-scripts--modules-to-build)
13. [Advanced Enhancements](#13-advanced-enhancements)
14. [Development Roadmap](#14-development-roadmap)
15. [Build vs. Use Libraries](#15-build-vs-use-libraries)
16. [Interview Guidance](#16-interview-guidance)
17. [GitHub & LinkedIn Guidance](#17-github--linkedin-guidance)
18. [Appendix A: File Reference](#appendix-a-file-reference)
19. [Appendix B: Rule YAML Format](#appendix-b-rule-yaml-format)
20. [Appendix C: API Endpoint Reference](#appendix-c-api-endpoint-reference)

---

## 1. Project Evaluation

### 1.1 What Is Already Good

Your project is **significantly ahead of most portfolio SIEMs**. Here is an honest assessment of what works:

| Component | What You Built | Assessment |
|-----------|---------------|------------|
| **Detection engine** | 3 rule types (simple, threshold, sequence), 12+ field modifiers (contains, gt, lt, cidr, exists, not, startswith, endswith, re, any), pre-filter index, dedup, rate limiting. 15 seeded rules covering brute force, lateral movement, C2 domains, PowerShell, Kerberoasting, credential dumping, DNS tunneling | **Strong.** This is the core of a real SIEM. 15 production rules covering MITRE tactics from Initial Access to Exfiltration. |
| **Log parsing** | 7 production-grade parsers (syslog 350+ lines/20+ programs, Windows 40+ EventIDs/Sysmon, firewall +pf, CEF +vendor/timestamps, ECS +full namespaces, LEEF +vendor/timestamps, CloudTrail +tags/resources) with plugin registry, auto-detection, priority routing, 80+ field extraction | **Production-grade.** Each parser extracts rich fields comparable to Splunk/QRadar field extraction. Registry pattern matches Elastic Beats architecture. |
| **Alert triage workflow** | Status machine (new → investigating → resolved / false_positive), assignment, timeline annotations, bulk actions, related events | **Strong.** This is the SOC L1 daily workflow. |
| **RBAC** | 6 roles (admin → viewer), permission matrix, middleware enforcement, audit logging on every action | **Production-grade.** Better than most tutorial apps. |
| **Real-time streaming** | WebSocket for alerts and raw events, Redis pub/sub for cross-process broadcast, heartbeat detection | **Good.** Real SIEMs use event buses. Your Redis Streams + WebSocket combination is architecturally correct. |
| **Data pipeline** | Redis Streams consumer group, batch processing, dead letter queue, 3-retry logic. Pipeline persists 50+ fields to DB, handles parsed timestamps, SPL-like search engine with 50+ field aliases | **Strong.** Full event-driven architecture with comprehensive field persistence and query capabilities. |
| **Enrichment** | Dual GeoIP (src+dst), asset criticality cache, risk scoring engine (0-100, 6 factors), hostname/IP correlation | **Strong.** Dual-IP GeoIP enrichment + automated risk scoring with severity, outcome, user, asset, network direction, and geo-country factors. |
| **Frontend** | 14 pages, MITRE ATT&CK heatmap (deduplicated coverage), rule builder with YAML generation, dashboard with time-range selector + drill-through stat cards + MITRE coverage ring widget + real-time WebSocket updates, dark mode, Splunk-style log detail panel (10-section grouped field display), SPL-like search bar, dynamic filter pills, risk score badges, alert queue with date-range filter + group-by (rule/MITRE) + real-time WebSocket updates, alert detail with persistent investigation checklist + IOC extraction panel, log explorer with column picker (localStorage) + CSV export + time-range-aware histogram, audit log with React Query + 4 filter bar + CSV export, assets with CSV export, settings with password strength meter, accessibility aria-labels, ErrorBoundary crash resilience, safe date formatting across all pages | **Impressive.** Visually strong for portfolio with production-quality log exploration UX, advanced analyst workflows, and robust error handling. |
| **Rule builder** | Visual condition editor, YAML preview, test endpoint, full MITRE ATT&CK taxonomy picker (~60 techniques across 14 tactics, grouped by tactic, searchable), severity filter, edit mode | **Recently improved.** Good interview demo piece with comprehensive MITRE coverage. |
| **Scheduling** | Rule reload (60s), asset cache (5m), dashboard cache (60s), stream cleanup (2 AM), data retention (3 AM) | **Complete.** Most portfolio projects skip operational maintenance entirely. |

### 1.2 What Is Missing

These are the gaps that reduce your project's realism and interview value:

| Gap | Why It Matters | Priority |
|-----|----------------|----------|
| **~~No database indexes~~** | ~~Your queries will be slow on 10K+ rows.~~ | ✅ **DONE** — 11 indexes added on createdAt, severity, category, source, sourceIp, destIp, hostname, username, eventType, action, processed |
| **~~No timestamp parsing from logs~~** | ~~You use `new Date()` instead of extracting the actual event timestamp~~ | ✅ **DONE** — All 7 parsers extract `parsedTimestamp` from log content. Pipeline uses parsed timestamp for DB insertion. |
| **No threat intelligence** | Real SOC L1 analysts check IPs against threat feeds (AbuseIPDB, OTX) before triaging. Your enrichment has GeoIP but no reputation data | **HIGH — key interview topic** |
| **No playbooks/SOPs** | When an alert fires, the analyst needs step-by-step instructions. Your rule YAML supports `playbook:` but it's not wired up | **MEDIUM — SOC realism** |
| **No SLA tracking** | SOC teams are measured on MTTA (Mean Time to Acknowledge) and MTTR (Mean Time to Respond). You calculate MTTR in dashboard but don't enforce SLA deadlines | **MEDIUM — operational metric** |
| **No shift handoff** | L1 analysts work 8-hour shifts. At handoff, they need: open alerts, escalated alerts, unresolved criticals | **MEDIUM — SOC process** |
| **No frequency/absence rules** | You can't detect "volume spike" or "host stopped reporting" — two common SOC scenarios | **MEDIUM — detection gaps** |
| **No correlation rules** | You can't correlate across rules (e.g., "brute force followed by successful login from same IP within 10 minutes") | **LOW for Phase 1 — HIGH for Phase 3** |
| **No Python service** | Sigma conversion, ML anomaly detection, and threat feed ingestion all need Python | **Phase 2 — not NOW** |

### 1.3 What Is Too Complex (Simplify)

| Area | Issue | Recommendation |
|------|-------|----------------|
| **Monorepo artifacts/ structure** | The `artifacts/`, `lib/api-spec/`, `lib/api-client-react/`, `lib/api-zod/`, `lib/db/` layers add complexity without value for your use case | **Ignore these entirely.** Your actual code lives in `secops-backend/` + `secops-frontend/`. The monorepo scaffolding is overhead. If you want shared types later, just copy the interfaces. |
| **Docker Compose** | Fine for deployment demo, but don't spend time optimizing Docker configs. Your local dev setup (PostgreSQL + Redis via WSL) works fine. | **Keep docker-compose.yml for README screenshots, don't invest more time.** |
| **Full Sigma compatibility** | Sigma's condition language (`selection | count() > N`, boolean expressions) is complex. Don't try to parse it in Node.js. | **Use pySigma in Python to convert community Sigma rules → your YAML format. Don't build a Sigma parser.** |
| **SOAR workflow engine** | Building a drag-and-drop workflow builder is a separate product. | **Build simple webhook notifications (Slack/Teams). That's the 80/20 automation.** |

### 1.4 What Should Be Simplified

| Current State | Simplification |
|--------------|----------------|
| Mock data generator in frontend (`mockGenerator.ts`) | Remove or clearly label as "demo mode". In interviews, say "I built a demo mode for when no backend is running" — but make sure the real backend data path is the default. |
| 62+ UI components in `components/ui/` | These are Radix UI wrappers. Don't touch them. They work. Don't mention them in interviews as "things I built." |
| API keys table | Exists but scopes aren't enforced. Either enforce or remove. Half-implemented features look worse than missing features. |

---

## 2. Architecture Direction

### 2.1 What Stays in Node.js (and why)

| Component | Why Node.js |
|-----------|------------|
| **API server** | Express 5 handles HTTP routing, JWT auth, RBAC. Standard choice. No reason to change. |
| **Real-time event bus** | Node.js excels at async I/O. Your Redis Streams consumer, WebSocket broadcast, and event loop are idiomatic Node. |
| **Log parsing** | Your 7 parsers are TypeScript. Regex parsing is fast enough in V8. Moving to Python gains nothing — it would be slower. |
| **Detection engine** | Your sliding window logic, pre-filter index, and modifier system are well-implemented in TS. This is your core IP — keep it in the language you know best. |
| **Enrichment** | GeoIP is a lookup table. Asset cache is a Redis call. Both are I/O operations where Node.js shines. |
| **Scheduler** | node-cron works. Moving to Python gains nothing. |
| **Webhook notifications** | HTTP POST to Slack/Teams. One function, no dependency on Python. |

### 2.2 What Moves to Python (and why)

| Component | Why Python |
|-----------|-----------|
| **Sigma rule conversion** | `pySigma` is the **official** Sigma SDK. It converts 5000+ community detection rules to any backend format. There is no equivalent in Node.js. This is the single strongest reason to add Python. |
| **Threat intelligence feed ingestion** | `pyTAXII` + `stix2` handle the STIX/TAXII protocol (the standard for threat intel sharing). The protocol is complex — using the Python libraries saves weeks. |
| **ML anomaly detection** | `scikit-learn`'s Isolation Forest and `PyOD` are the standard tools. No ML library in Node.js comes close. |
| **UEBA baseline builder** | Statistical modeling (histograms, z-scores, standard deviation) is native to NumPy/Pandas. Doing this in Node is painful. |
| **YARA scanning** | `yara-python` wraps the YARA C engine. No Node binding exists at the same quality level. |

### 2.3 What You Build From Scratch (and why)

| Thing | Why Build It |
|-------|-------------|
| **Detection engine** | Already built. This teaches you how SIEM correlation works at the rule level. |
| **Log parsers** | Already built. Regex-based field extraction teaches you log format internals. |
| **Parser registry / plugin system** | Already built. Teaches plugin architecture patterns. |
| **Alert triage workflow** | Already built. Teaches SOC analyst daily operations. |
| **Rule condition DSL** | Already built (modifiers system). Teaches how Sigma/YARA condition languages work. |
| **SLA tracking** | Simple timer math. Build it — teaches SOC operational metrics. |
| **Shift handoff report** | SQL aggregation over time ranges. Build it — teaches SOC operational processes. |
| **Bloom filter wrapper for IOC lookup** | Wrap the `bloom-filters` npm package. Teaches probabilistic data structures in security. |
| **Playbook renderer** | Parse `playbook:` from rule YAML, display steps in frontend. Build it — teaches alert response procedures. |

### 2.4 What Uses Libraries (and why)

| Thing | Library | Why Not Build |
|-------|---------|---------------|
| Sigma rule parsing | `pySigma` (Python) | Official SDK with 5000+ community rules. Writing your own parser is a rabbit hole. |
| YARA scanning | `yara-python` | C-based engine. Regex at scale is its specialty. |
| Threat intel feeds | `pyTAXII` + `stix2` | STIX/TAXII is a complex protocol. Don't implement it. |
| ML anomaly detection | `scikit-learn` / `PyOD` | Battle-tested statistical models. |
| GeoIP | `geoip-lite` (already using) | Database-backed IP lookup. Reimplementing gains nothing. |
| Bloom filter | `bloom-filters` (npm) | Bit manipulation. Using a tested implementation avoids false negative bugs. |
| PDF reports | `puppeteer` or `pdfkit` | Don't hand-craft PDF bytes. |
| Slack notifications | `@slack/web-api` or raw `axios` POST | Tested API client. |
| Rate limiting | `express-rate-limit` (already using) | Battle-tested middleware. |
| JWT auth | `jsonwebtoken` (already using) | Crypto must never be hand-rolled. |

---

## 3. System Architecture

### 3.1 Current Architecture (What You Have Now)

```
┌─────────────────────────────────────────────────────────────────────┐
│                        FRONTEND (React 19 + Vite 7)                 │
│  Dashboard │ AlertQueue │ LogExplorer │ RuleBuilder │ MITRE │ Audit │
│  14 pages  │ Zustand state │ React Query caching │ WebSocket hooks  │
│  WebSocket ────────────────────────────┐                            │
└─────────────────────────┬──────────────┘                            │
                          │ HTTP (axios)                              │
                          ▼                                           │
┌───────────────────────────────────────────────────────┐             │
│              API SERVER (Express 5 + TypeScript)      │             │
│                                                       │◄──── ws://  │
│  Auth (JWT + bcrypt) → RBAC (6 roles) → Routes       │   /alerts   │
│                                                       │   /events   │
│  ┌────────────┐  ┌───────────┐  ┌──────────────┐     │             │
│  │ Parsers    │→ │ Enrichment│→ │ Detection    │     │             │
│  │ (registry) │  │ GeoIP     │  │ Engine       │     │             │
│  │ 7 formats: │  │ Asset     │  │ - simple     │     │             │
│  │ syslog     │  │ cache     │  │ - threshold  │     │             │
│  │ winlog     │  │           │  │ - sequence   │     │             │
│  │ firewall   │  │           │  │ Modifiers:   │     │             │
│  │ cef        │  │           │  │ gt/lt/gte/lte│     │             │
│  │ ecs-json   │  │           │  │ cidr/exists  │     │             │
│  │ leef       │  │           │  │ not/contains │     │             │
│  │ cloudtrail │  │           │  │ Pre-filter   │     │             │
│  │ (generic)  │  │           │  │ index        │     │             │
│  └────────────┘  └───────────┘  └──────────────┘     │             │
│                                                       │             │
│  ┌───────────────────────────────────────────────┐    │             │
│  │ Pipeline Worker (Redis Streams consumer)      │    │             │
│  │ - Consumer group: secops-workers              │    │             │
│  │ - Batch: 10 messages, 2s block                │    │             │
│  │ - Dead letter queue on 3× retry fail          │    │             │
│  └───────────────────────────────────────────────┘    │             │
│                                                       │             │
│  ┌───────────────────────────────────────────────┐    │             │
│  │ Scheduler (node-cron)                         │    │             │
│  │ - Rule reload: every 60s                      │    │             │
│  │ - Asset cache refresh: every 5min             │    │             │
│  │ - Dashboard stats cache: every 60s            │    │             │
│  │ - Stream cleanup: daily 2 AM                  │    │             │
│  │ - Data retention: daily 3 AM                  │    │             │
│  └───────────────────────────────────────────────┘    │             │
│                                                       │             │
│  ┌───────────────────────────────────────────────┐    │             │
│  │ 9 API Module Routes                           │    │             │
│  │ Auth · Me · Users · Alerts · Rules            │    │             │
│  │ Dashboard · Audit · Ingest · Assets           │    │             │
│  └───────────────────────────────────────────────┘    │             │
└────────────────┬───────────────┬──────────────────────┘             │
                 │               │                                    │
         ┌───────▼──────┐   ┌───▼─────────┐                          │
         │ PostgreSQL 18│   │ Redis 7.0   │                          │
         │ 9 tables     │   │ - Cache     │                          │
         │ Drizzle ORM  │   │ - Streams   │                          │
         └──────────────┘   │ - Pub/Sub   │                          │
                            │ - EPS track │                          │
         ┌─────────────┐    └─────────────┘
         │ Syslog Recv │
         │ UDP + TCP   │
         │ port 1514   │
         └─────────────┘
```

### 3.2 Target Architecture (with Python Analytics)

```
                       ┌──────────────────────────────────────┐
                       │  FRONTEND (React 19)                 │
                       │  + Live Event Stream (WS)            │
                       │  + Playbook Panel                    │
                       │  + SLA Countdown Timers              │
                       └──────────────┬───────────────────────┘
                                      │
                       ┌──────────────▼───────────────────────┐
                       │     NODE.JS API + EVENT BUS          │
                       │  ┌──────────────────────────────┐    │
                       │  │ Ingest → Parse → Enrich      │    │
                       │  │   → IOC Check (bloom filter) │    │
                       │  │   → Detect → Alert           │    │
                       │  └──────────────────────────────┘    │
                       │  ┌──────────────────────────────┐    │
                       │  │ Redis Streams (event bus)    │    │
                       │  │ secops:log_queue             │    │
                       │  │ secops:python_queue          │◄──── NEW
                       │  │ secops:enrichment_results    │◄──── NEW
                       │  └──────────────────────────────┘    │
                       └──────────────┬───────────────────────┘
                                      │
                         ┌────────────▼─────────────┐
                         │  PYTHON ANALYTICS SVC    │◄──── NEW
                         │  (FastAPI + Redis)       │
                         │                          │
                         │  - Sigma converter       │ (pySigma)
                         │  - Threat intel feeds    │ (AbuseIPDB, OTX)
                         │  - Anomaly detection     │ (Isolation Forest)
                         │  - UEBA baselines        │ (NumPy)
                         │  - YARA scanning         │ (yara-python)
                         └──────────────────────────┘
```

### 3.3 Communication Patterns

| Pattern | What It Connects | Protocol | When Used |
|---------|-----------------|----------|-----------|
| REST API | Frontend → Backend | HTTP/JSON | All CRUD operations, queries |
| WebSocket | Backend → Frontend | ws:// | Real-time alert + event streaming |
| Redis Streams | Ingest → Worker | XADD/XREADGROUP | Async log processing pipeline |
| Redis Pub/Sub | Backend → Frontend relay | PUBLISH/SUBSCRIBE | Cross-process alert broadcast |
| Redis Streams (planned) | Node.js → Python | XADD/XREADGROUP | Enqueue events for ML analysis |
| HTTP (planned) | Node.js → Python | HTTP/JSON | Sigma conversion, IOC lookup |

---

## 4. SOC L1 Workflow

This is the complete SOC Level-1 analyst workflow your project supports. **Every step here should map to a feature in your app.** This is what interviewers expect you to explain.

### 4.1 The Complete SOC L1 Pipeline

```
LOG SOURCES           YOUR APP              SOC ANALYST ACTION
─────────────        ──────────            ────────────────────

Syslog (1514) ──┐
HTTP ingest   ──┤    ┌─────────────┐
Bulk upload   ──┤───►│ 1. INGEST   │       Not analyst-facing
                │    └──────┬──────┘       (automated)
                │           │
                │    ┌──────▼──────┐
                ├───►│ 2. PARSE    │       Parser registry selects
                │    │    (7 fmt)  │       correct parser by sourceType
                │    └──────┬──────┘       or auto-detects format
                │           │
                │    ┌──────▼──────┐
                ├───►│ 3. NORMALIZE│       All fields mapped to
                │    │  ParsedEvent│       common schema
                │    └──────┬──────┘       (srcIp, dstIp, action, etc.)
                │           │
                │    ┌──────▼──────┐
                └───►│ 4. ENRICH   │       GeoIP country/city,
                     │  GeoIP +   │       asset criticality,
                     │  Asset     │       hostname → IP lookup
                     └──────┬──────┘
                            │
                     ┌──────▼──────┐
                     │ 5. DETECT   │       Rules fire, threshold
                     │  Engine    │       windows checked, dedup
                     │  (evaluate)│       applied, rate limit enforced
                     └──────┬──────┘
                            │
                     ┌──────▼──────┐
                     │ 6. ALERT    │       Insert alert to DB,
                     │  Create    │       broadcast via WebSocket,
                     │  + Notify  │       add to timeline
                     └──────┬──────┘
                            │
                     ┌──────▼──────┐       ┌───────────────────────┐
                     │ 7. TRIAGE   │◄─────►│ ANALYST: Opens alert   │
                     │  Queue     │       │ Reads playbook steps  │
                     │  (frontend)│       │ Checks enrichment     │
                     └──────┬──────┘       │ Views related events  │
                            │              │ Adds timeline notes   │
                     ┌──────▼──────┐       │ Sets status:          │
                     │ 8. RESPOND  │       │ → investigating       │
                     │  Decision  │       │ → resolved            │
                     └──────┬──────┘       │ → false_positive      │
                            │              │ OR escalates to L2    │
                     ┌──────▼──────┐       └───────────────────────┘
                     │ 9. INCIDENT │
                     │  (if L2+)  │       Group related alerts
                     └──────┬──────┘       into an incident/case
                            │
                     ┌──────▼──────┐
                     │ 10. AUDIT   │       All actions logged
                     │  + Report  │       Shift handoff generated
                     └─────────────┘       MTTA/MTTR tracked
```

### 4.2 Feature Support Status

| SOC L1 Step | Feature | Status | What You Show in Interview |
|-------------|---------|--------|---------------------------|
| **Ingest** | Syslog server (TCP/UDP 1514) | ✅ Done | "I built a syslog receiver that accepts RFC3164 from any security tool" |
| **Ingest** | HTTP bulk upload (10K batch) | ✅ Done | "Supports bulk log upload for batch forensic analysis" |
| **Ingest** | Redis Streams event queue | ✅ Done | "Async pipeline with consumer groups and dead letter queue" |
| **Parse** | 7 format parsers | ✅ Done | "I wrote parsers for syslog, Windows EventLog, firewall, CEF, ECS, LEEF, and CloudTrail" |
| **Parse** | Plugin registry with auto-detect | ✅ Done | "Parsers self-register with priority. If sourceType isn't known, it auto-detects by content sniffing" |
| **Normalize** | Common ParsedEvent schema (80+ fields) | ✅ Done | "All 7 formats normalize to one 80+ field schema — network, user, process, HTTP, DNS, file, registry, vendor, syslog sections" |
| **Enrich** | Dual GeoIP + Asset criticality + Risk scoring | ✅ Done | "Source and dest IPs both get GeoIP lookup, asset criticality from inventory, and a 6-factor risk score (0-100)" |
| **Enrich** | Threat intel IOC check | ❌ Not yet | "Planned: bloom filter for O(1) IOC lookup, confirmed hits query the DB" |
| **Detect** | Simple / threshold / sequence | ✅ Done | "Three rule types covering 90% of SOC detection scenarios" |
| **Detect** | 15 seeded detection rules | ✅ Done | "Covering brute-force, privilege escalation, lateral movement, exfiltration, and more — mapped to MITRE ATT&CK" |
| **Detect** | 10+ modifiers (cidr, gt, exists, not) | ✅ Done | "I extended the condition language to support CIDR matching, numeric comparison, and negation" |
| **Detect** | Pre-filter index | ✅ Done | "Rules are indexed by category and sourceType. Only candidate rules are evaluated per event" |
| **Search** | SPL-like search engine | ✅ Done | "50+ field aliases, 7 operators, boolean logic, free-text search across 6 columns" |
| **Alert** | Real-time WebSocket broadcast | ✅ Done | "Alerts appear in the analyst's queue instantly via WebSocket" |
| **Alert** | Dedup + rate limiting | ✅ Done | "Prevents alert fatigue — same alert won't fire repeatedly" |
| **Triage** | Status workflow (new → resolved) | ✅ Done | "Full triage workflow with assignment, timeline notes, and bulk actions" |
| **Triage** | Related events viewer | ✅ Done | "Analyst can see all events from the same source IP within the alert timeframe" |
| **Triage** | Playbook/SOP display | ❌ Not yet | "Rule YAML supports playbook steps — needs frontend rendering" |
| **Respond** | SLA countdown timer | ❌ Not yet | "Track MTTA/MTTR with severity-based deadlines" |
| **Incident** | Alert-to-incident grouping | ⚠️ Partial | "Incidents table exists but the workflow isn't wired to frontend" |
| **Audit** | Full audit trail | ✅ Done | "Every action logged with user, IP, timestamp. Compliance-ready." |
| **Report** | Shift handoff report | ❌ Not yet | "Printable summary of shift activity for SOC team handoff" |
| **Report** | MITRE coverage heatmap | ✅ Done | "Shows which MITRE ATT&CK techniques our rules cover" |

---

## 5. Log Parsing & Normalization

### 5.1 Parser Architecture ✅ Implemented (Production-Grade)

```
parsers/
  registry.ts  → Plugin registry: registerParser(), parseLogViaRegistry(), getRegisteredParsers()
  index.ts     → Imports all parsers (triggers self-registration), exports parseLog()
  types.ts     → ParsedEvent interface (80+ fields)
  syslog.ts    → 350+ lines. RFC3164+RFC5424, 20+ programs: sshd (6 patterns), sudo, su,
                 CRON, systemd, kernel (iptables/OOM/segfault), useradd/userdel/passwd/groupadd,
                 named/unbound, dhcpd, postfix/dovecot, auditd, PAM. Facility mapping,
                 timestamp parsing, fallback IP extraction.
  windows-eventlog.ts → 40+ EventIDs: Sysmon 1/3/5/7/8/10/11/12/13/15/22, account mgmt
                        4720-4756, PowerShell 4103/4104, scheduled tasks, firewall, Kerberos,
                        NTLM. LOGON_TYPE_MAP, XML attribute extraction, tags.
  firewall.ts  → iptables, nftables, BSD pf. Direction, networkInterface, bytesIn,
                 vendorName/vendorProduct, deviceAction, tags.
  cef.ts       → ArcSight CEF with parseCefTimestamp() (epoch-ms/ISO8601/text dates),
                 vendorName/vendorProduct, deviceEventClassId, bytesIn/Out, HTTP/file/user fields.
  ecs-json.ts  → Full ECS namespaces: http.*, dns.*, file.*, url.*, registry.*, observer.*.
                 Tags from event.category + event.type arrays. bytesIn/Out, direction.
  leef.ts      → IBM QRadar LEEF 1.0/2.0 with parseLeefTimestamp(), HTTP/DNS/file fields,
                 vendorName/vendorProduct, targetUserName, userId, direction.
  cloudtrail.ts → AWS CloudTrail with improved categorizeAction. parsedTimestamp, tags
                  (cloudtrail, aws, aws-service, error, read-only, root-user),
                  resourceArn extraction, vendorName/vendorProduct/deviceEventClassId.
```

**Parse flow:** `parseLog(raw, sourceType, sourceHost)` →
1. Try exact sourceType match in registry
2. Try `canParse()` auto-detection (content sniffing)
3. Fall back to generic JSON parser

### 5.2 How the Registry Works

```typescript
// parsers/registry.ts
interface ParserPlugin {
  name: string;
  sourceTypes: string[];   // what sourceType values this handles
  priority: number;        // lower = checked first (for auto-detection)
  canParse(raw: string): boolean;   // content sniffing
  parse(raw: string, sourceHost: string): ParsedEvent | null;
}

// Each parser self-registers on import:
// parsers/cef.ts
registerParser({
  name: "cef",
  sourceTypes: ["cef"],
  priority: 5,
  canParse: (raw) => /CEF:\d+\|/.test(raw),
  parse(raw, sourceHost) { /* ... */ },
});
```

### 5.3 Normalized Event Schema (80+ Fields)

All parsers output the same `ParsedEvent` interface:

```typescript
interface ParsedEvent {
  // --- Core identification ---
  sourceType: string;           // "syslog" | "windows_eventlog" | "firewall" | "cef" | "ecs" | "leef" | "cloudtrail"
  sourceHost: string;           // hostname or IP of log source
  category: string;             // "authentication" | "network" | "process" | "file" | "system" | "dns"
  action: string;               // "login_failure" | "connection_blocked" | "process_created"
  outcome?: string;             // "success" | "failure"
  severity: string;             // "critical" | "high" | "medium" | "low" | "info"
  eventType?: string;           // readable event label (e.g. "EventID-4625", "sshd_auth_failure")
  message?: string;
  rawLog?: string;

  // --- Timestamp ---
  parsedTimestamp?: Date;       // timestamp extracted from the log itself (not ingest time)

  // --- Syslog / facility ---
  facility?: number;            // RFC3164 facility code (0-23)
  facilityName?: string;        // "auth" | "kern" | "daemon" | "local0" etc.
  severityCode?: number;        // RFC3164 severity code (0-7)

  // --- User context ---
  userName?: string;
  userDomain?: string;
  userId?: string;
  targetUserName?: string;      // su/sudo target, RDP target, etc.
  logonType?: number;           // Windows logon type (2=interactive, 3=network, 10=RDP)

  // --- Process context ---
  processName?: string;
  processId?: number;
  processCommandLine?: string;
  parentProcessName?: string;
  parentProcessId?: number;

  // --- Network context ---
  srcIp?: string;
  srcPort?: number;
  dstIp?: string;
  dstPort?: number;
  protocol?: string;
  bytesIn?: number;
  bytesOut?: number;
  packetCount?: number;
  direction?: string;           // "inbound" | "outbound" | "internal"
  networkInterface?: string;

  // --- HTTP context ---
  httpMethod?: string;
  httpUrl?: string;
  httpStatusCode?: number;
  httpUserAgent?: string;
  httpReferrer?: string;

  // --- DNS context ---
  dnsQuery?: string;
  dnsResponseCode?: string;
  dnsRecordType?: string;

  // --- File context ---
  fileName?: string;
  filePath?: string;
  fileHash?: string;            // SHA256 or MD5

  // --- Registry context (Windows) ---
  registryKey?: string;
  registryValue?: string;

  // --- Vendor / device context ---
  vendorName?: string;          // "Microsoft" | "Palo Alto" | "AWS" | "IBM"
  vendorProduct?: string;       // "Windows" | "PAN-OS" | "CloudTrail" | "QRadar"
  deviceAction?: string;        // "block" | "allow" | "deny"
  deviceEventClassId?: string;  // vendor-specific event class ID

  // --- Tags ---
  tags?: string[];              // e.g. ["brute-force", "ssh", "external", "sysmon"]
}
```

### 5.4 What Was Built & What's Next for Parsing

#### ✅ Completed

| Task | Details |
|------|---------|
| **Extract timestamps from log content** | All 7 parsers now extract `parsedTimestamp` from log headers (syslog RFC3164/5424, Windows `@timestamp`, CEF epoch/ISO/text, ECS `@timestamp`, LEEF `devTime`, CloudTrail `eventTime`). Pipeline uses parsed timestamp for DB insertion instead of `new Date()`. |
| **80+ field extraction** | Every parser extracts vendor, network, user, process, HTTP, DNS, file, registry, and tag fields — not just core IP/port/user. |
| **Syslog program-specific parsing** | 20+ programs: sshd (accepted/failed/disconnect/invalid/pubkey/conn-closed), sudo (cmd+fail), su (session+fail), CRON, systemd, kernel (iptables/OOM/segfault), useradd/userdel/passwd/groupadd, named/unbound, dhcpd, postfix/dovecot, auditd, PAM. |
| **Windows Sysmon support** | EventIDs 1/3/5/7/8/10/11/12/13/15/22 (process create, network connect, process terminate, image load, create remote thread, process access, file create, registry events, DNS query). |
| **Facility mapping (syslog)** | RFC3164 facility code → human-readable name (kern, user, mail, daemon, auth, syslog, lpr, news, uucp, cron, local0-7). |
| **Tag generation** | All parsers emit descriptive tags (e.g. `["sysmon", "process-create"]`, `["cloudtrail", "aws", "root-user"]`, `["brute-force", "ssh"]`). |

#### ⬜ Still To Build

| Task | Details | Why |
|------|---------|-----|
| **Multi-line log buffering** | TCP syslog splits on `\n`. Java stack traces and Windows XML events span multiple lines. Buffer lines until next log header regex. | Without this, multi-line logs produce garbage parses. |
| **Parser metrics** | Track `parsedCount`, `failedCount`, `avgParseTime` per parser. Expose via `GET /api/admin/parsers/stats`. | Interview talking point: "I monitor parser health." |

---

## 6. Detection Engine

### 6.1 Engine Assessment

| Feature | Implementation | Assessment |
|---------|---------------|------------|
| **Simple match** | `matches()` with 10+ field modifiers | **Solid.** Covers ~90% of Sigma modifiers |
| **Threshold** | Sliding window buckets per `(ruleId, groupKey)` | **Good.** Correct sliding window approach |
| **Sequence** | Multi-step with `byField` grouping | **Good.** Proper ordered sequence correlation |
| **Dedup** | `dedupWindow` with `computeDedupKey()` | **Good.** Prevents alert storms |
| **Rate limit** | `maxAlertsPerHour` per rule | **Good.** Prevents rule saturation |
| **Numeric comparison** | `gt`, `gte`, `lt`, `lte` modifiers | ✅ Enables threshold-on-field rules |
| **CIDR matching** | `cidr` modifier with `isIpInCidr()` + `ipToInt()` | ✅ Network-scoped rules |
| **Existence check** | `exists` modifier (true/false) | ✅ Detect presence/absence of fields |
| **Negation** | `not` meta-modifier (combinable: `field\|not\|contains`) | ✅ Exclusion logic |
| **Pre-filter index** | `rulesByCategory`, `rulesBySourceType`, `universalRules` maps | ✅ O(1) rule candidate lookup |

### 6.2 Seeded Detection Rules (15 Production Rules)

All 15 rules are seeded via `scripts/seed-detection-rules.ts`:

| # | Rule Name | Type | Severity | MITRE Technique |
|---|-----------|------|----------|-----------------|
| 1 | Brute Force Login Attempt | threshold | high | T1110.001 — Brute Force |
| 2 | Suspicious PowerShell Execution | simple | high | T1059.001 — PowerShell |
| 3 | PsExec-style Lateral Movement | simple | critical | T1570 — Lateral Tool Transfer |
| 4 | SSH Brute Force | threshold | high | T1110.001 — Brute Force |
| 5 | Firewall Connection Blocked — Repeated | threshold | medium | T1071 — Application Layer Protocol |
| 6 | DNS Query to Known C2 Domain | simple | critical | T1071.004 — DNS |
| 7 | RDP Logon from External IP | simple | high | T1021.001 — Remote Desktop Protocol |
| 8 | New User Account Created | simple | medium | T1136.001 — Local Account |
| 9 | Suspicious HTTP POST to External IP | simple | high | T1041 — Exfiltration Over C2 Channel |
| 10 | Windows Registry Run Key Modification | simple | high | T1547.001 — Registry Run Keys |
| 11 | Kerberoasting — SPN Request Spike | threshold | high | T1558.003 — Kerberoasting |
| 12 | CloudTrail — Root Account Usage | simple | critical | T1078.004 — Cloud Accounts |
| 13 | Credential Dumping Tool Detected | simple | critical | T1003 — OS Credential Dumping |
| 14 | Login After Account Creation | sequence | high | T1136 → T1078 — Create Account → Valid Accounts |
| 15 | Excessive DNS Queries — Possible Tunneling | threshold | high | T1048.001 — DNS Exfiltration |

**Coverage:** 3 simple rules, 4 threshold rules, 1 sequence rule. Covers MITRE tactics: Initial Access, Execution, Persistence, Privilege Escalation, Credential Access, Lateral Movement, Exfiltration.

### 6.3 Condition Language Reference

```yaml
# ─── EXACT MATCH ───
action: login_failure

# ─── LIST MATCH (OR) ───
action: [login_failure, login_success]

# ─── STRING MODIFIERS ───
message|contains: "denied"
hostname|startswith: "prod-"
filePath|endswith: ".exe"
command|re: "powershell.*-enc.*"
message|contains|any: ["error", "fail", "denied"]

# ─── NUMERIC COMPARISON ───
severityScore|gt: 80
failedAttempts|gte: 5
bytesOut|lt: 1000

# ─── NETWORK ───
srcIp|cidr: "10.0.0.0/8"
dstIp|cidr: "192.168.0.0/16"

# ─── FIELD EXISTENCE ───
processName|exists: true
geoCountry|exists: false

# ─── NEGATION (combinable) ───
action|not: login_success
srcIp|not|cidr: "10.0.0.0/8"
message|not|contains: "heartbeat"
```

### 6.4 Rule Types to Add Next

#### 6.4.1 Frequency Rule (volume spike detection)

Threshold says "5 SSH failures from one IP." Frequency says "50 events of ANY kind from one host in 1 minute" — detecting abnormal volume.

```yaml
name: "Unusual Log Volume Spike"
type: frequency
severity: medium
match:
  sourceType|contains|any: [syslog, windows_eventlog]
frequency:
  groupBy: sourceHost
  count: 50
  timeframe: 1m
  baselineMultiplier: 3    # alert if 3× above rolling baseline
```

**Implementation:** Same sliding window as threshold, but grouped by `sourceHost` instead of a specific match field. Optionally compare against a stored baseline.

#### 6.4.2 Absence Rule (missing heartbeat)

```yaml
name: "Host Stopped Sending Logs"
type: absence
severity: high
match:
  assetCriticality: high
absence:
  groupBy: sourceHost
  expectedInterval: 5m
```

**Implementation:** Scheduler checks every 60s. For each high-criticality asset, query `MAX(created_at) FROM raw_logs WHERE source_host = X`. If older than `expectedInterval`, fire alert.

#### 6.4.3 Composite/Correlation Rule

```yaml
name: "Lateral Movement Detected"
type: composite
severity: critical
correlate:
  - ruleRef: ssh-brute-force
    withinLast: 10m
  - ruleRef: new-service-installed
    withinLast: 10m
  groupBy: srcIp
```

**Implementation:** When evaluating, query recent alerts from referenced rules within the time window, grouped by the field. If all component rules triggered for the same group key, fire composite alert.

---

## 7. Database Design

### 7.1 Current Schema (9 tables)

| Table | Purpose | Key Columns |
|-------|---------|------------|
| **users** | User accounts + RBAC | role (6 roles), status, failedLoginAttempts, settings (JSONB) |
| **alerts** | Detection alerts | severity, status workflow, MITRE mapping, dedupKey, context (JSONB) |
| **alert_timeline** | Analyst notes + actions | alertId FK, type, content, authorId |
| **rules** | Detection rules | yamlContent, enabled, mitreIds, triggerCount, falsePositiveRate |
| **incidents** | Grouped investigation cases | alertIds (array), severity, status |
| **raw_logs** | Normalized + enriched events (50+ columns) | All ParsedEvent fields, GeoIP (src+dst), asset criticality, risk score, tags (JSONB), parsed timestamp, 11 indexes |
| **assets** | Host/IP inventory | hostname, ip, criticality, tags, owner |
| **api_keys** | External API auth | keyHash, scopes, lastUsedAt |
| **audit_logs** | Compliance trail | action, resource, metadata, ipAddress, success |

### 7.2 raw_logs Table — Full Column Reference ✅ Implemented

The `raw_logs` table stores 50+ columns covering all parsed, enriched, and vendor fields:

```
Core:            id, source, severity, eventType, category, action, outcome, message, rawData
Network:         sourceIp, destIp, srcPort, dstPort, protocol, bytesIn, bytesOut, direction
Host:            hostname, sourceHost
User:            username, targetUsername, logonType, userId, userDomain
Process:         processName, processId, processCommandLine, parentProcessName, parentProcessId
HTTP:            httpMethod, httpUrl, httpStatusCode, httpUserAgent
DNS:             dnsQuery, dnsResponseCode, dnsRecordType
File:            fileName, filePath, fileHash
Registry:        registryKey, registryValue
Vendor/Device:   vendorName, vendorProduct, deviceAction, deviceEventClassId
Syslog:          facility, facilityName, severityCode
Enrichment:      geoCountry, geoCity, geoCountryDst, geoCityDst, assetCriticality, riskScore (real)
Tags:            tags (jsonb string[])
Timestamps:      parsedTimestamp, createdAt, detectionRunAt
Processing:      processed
```

**11 Indexes (all applied to DB):**
```sql
idx_raw_logs_created_at   ON (created_at)
idx_raw_logs_severity     ON (severity)
idx_raw_logs_category     ON (category)
idx_raw_logs_source       ON (source)
idx_raw_logs_source_ip    ON (source_ip)
idx_raw_logs_dest_ip      ON (dest_ip)
idx_raw_logs_hostname     ON (hostname)
idx_raw_logs_username     ON (username)
idx_raw_logs_event_type   ON (event_type)
idx_raw_logs_action       ON (action)
idx_raw_logs_processed    ON (processed)
```

### 7.3 Missing Indexes — ✅ DONE (raw_logs), Still Needed for Other Tables

The raw_logs indexes are applied. These additional indexes are still recommended:

```sql
-- Alerts: Most common queries
CREATE INDEX idx_alerts_status ON alerts(status) WHERE status IN ('new', 'investigating');
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_source_ip ON alerts(source_ip) WHERE source_ip IS NOT NULL;
CREATE INDEX idx_alerts_created_at ON alerts(created_at DESC);
CREATE INDEX idx_alerts_rule_name ON alerts(rule_name);
CREATE INDEX idx_alerts_assigned_to ON alerts(assigned_to) WHERE assigned_to IS NOT NULL;

-- Rules: Enabled rules query (used every 60s by detection engine)
CREATE INDEX idx_rules_enabled ON rules(enabled) WHERE enabled = true;

-- Audit logs
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at DESC);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);

-- Assets: Enrichment lookups
CREATE INDEX idx_assets_hostname ON assets(hostname);
CREATE INDEX idx_assets_ip ON assets(ip) WHERE ip IS NOT NULL;
```

### 7.3 New Tables for Phase 2+

#### IOC Indicators (Threat Intelligence)

```sql
CREATE TABLE ioc_indicators (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  type TEXT NOT NULL,             -- 'ip' | 'domain' | 'hash_md5' | 'hash_sha256' | 'url'
  value TEXT NOT NULL,
  source TEXT NOT NULL,           -- 'abuseipdb' | 'virustotal' | 'otx' | 'manual'
  confidence INTEGER DEFAULT 50,  -- 0-100
  severity TEXT DEFAULT 'medium',
  tags TEXT[] DEFAULT '{}',
  first_seen TIMESTAMP DEFAULT NOW(),
  last_seen TIMESTAMP DEFAULT NOW(),
  expires_at TIMESTAMP,
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(type, value, source)
);
CREATE INDEX idx_ioc_type_value ON ioc_indicators(type, value);
```

#### UEBA Baselines (Phase 4)

```sql
CREATE TABLE ueba_baselines (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  entity_type TEXT NOT NULL,      -- 'user' | 'host' | 'ip'
  entity_id TEXT NOT NULL,
  metric TEXT NOT NULL,           -- 'login_hours' | 'event_volume' | 'failed_auth_rate'
  baseline_value JSONB NOT NULL,  -- { mean, stddev, histogram }
  sample_count INTEGER DEFAULT 0,
  last_updated TIMESTAMP DEFAULT NOW(),
  UNIQUE(entity_type, entity_id, metric)
);
```

### 7.4 Data Retention ✅ Implemented

Daily at 3 AM:
- Delete `raw_logs` older than 90 days (where `processed != 'false'`)
- Delete `alerts` older than 180 days (where `status IN ('resolved', 'false_positive')`)

### 7.5 Partitioning Strategy (when raw_logs > 5M rows)

```sql
CREATE TABLE raw_logs_partitioned (
  LIKE raw_logs INCLUDING ALL
) PARTITION BY RANGE (created_at);

CREATE TABLE raw_logs_y2026m03 PARTITION OF raw_logs_partitioned
  FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');
```

**When:** Only if log search queries start taking > 500ms. Not needed yet.

---

## 8. SPL-like Search Engine ✅ Implemented

### 8.1 Overview

A custom Splunk-style search parser (`lib/search/spl-parser.ts`) translates user queries into Drizzle ORM `WHERE` clauses. This gives SOC analysts a familiar search syntax for exploring logs without writing SQL.

**Entry point:** `GET /api/logs?q=<query>` — the `q` parameter is parsed by `parseSPLQuery()` which returns an array of Drizzle conditions that are ANDed into the database query.

### 8.2 Field Alias Map (50+ entries)

The parser maps human-readable field names to database columns via `FIELD_COLUMN_MAP`:

```
src, src_ip, source_ip   → rawLogs.sourceIp
dst, dst_ip, dest_ip     → rawLogs.destIp
src_port, sport           → rawLogs.srcPort
dst_port, dport           → rawLogs.dstPort
host, hostname            → rawLogs.hostname
user, username            → rawLogs.username
target_user               → rawLogs.targetUsername
process, proc             → rawLogs.processName
pid, process_id           → rawLogs.processId
cmd, command_line         → rawLogs.processCommandLine
severity, level           → rawLogs.severity
category, cat             → rawLogs.category
event_type, type          → rawLogs.eventType
action                    → rawLogs.action
outcome, result           → rawLogs.outcome
protocol, proto           → rawLogs.protocol
direction, dir            → rawLogs.direction
method, http_method       → rawLogs.httpMethod
url, http_url             → rawLogs.httpUrl
status_code               → rawLogs.httpStatusCode
dns_query, query          → rawLogs.dnsQuery
vendor                    → rawLogs.vendorName
product                   → rawLogs.vendorProduct
risk, risk_score          → rawLogs.riskScore
country, geo_country      → rawLogs.geoCountry
...and more
```

### 8.3 Supported Operators

| Operator | Example | SQL Equivalent |
|----------|---------|----------------|
| `=` | `src_ip=10.0.0.1` | `source_ip = '10.0.0.1'` |
| `!=` | `severity!=info` | `severity != 'info'` |
| `>` | `risk_score>50` | `risk_score > 50` |
| `>=` | `risk_score>=75` | `risk_score >= 75` |
| `<` | `src_port<1024` | `src_port < 1024` |
| `<=` | `bytes_in<=100` | `bytes_in <= 100` |
| `=*` (wildcard) | `user=admin*` | `username ILIKE 'admin%'` |

### 8.4 Boolean Logic & Free-Text Search

**Boolean operators:**
- `AND` (explicit) — `src_ip=10.0.0.1 AND severity=high`
- `OR` — `severity=high OR severity=critical`  
- `NOT` — `NOT severity=info`
- Implicit AND between space-separated terms

**Free-text keyword search:**
Bare words (not `field=value`) search across 6 text columns simultaneously:
`message`, `rawData`, `hostname`, `username`, `processName`, `sourceIp`

Example: `failed login` → searches all 6 columns for "failed" AND "login" (ILIKE).

### 8.5 Architecture

```
User types: src_ip=10.0.0.1 AND severity=high
        │
        ▼
  ┌─────────────┐
  │  Tokenizer   │ ← Splits into tokens: {field,op,value}, {keyword}, {boolean}
  └─────┬───────┘
        ▼
  ┌─────────────┐
  │  Parser      │ ← Builds condition tree with AND/OR/NOT logic
  └─────┬───────┘
        ▼
  ┌─────────────┐
  │  SQL Builder │ ← Maps fields via FIELD_COLUMN_MAP → Drizzle conditions
  └─────┬───────┘
        ▼
  Array<SQL> conditions → ANDed into Drizzle query
```

---

## 9. Risk Scoring & Enrichment ✅ Implemented

### 9.1 Overview

Every ingested log event passes through `enrichEvent()` in `lib/enrichment.ts` which adds:
1. **Dual GeoIP lookups** (source IP + destination IP)
2. **Asset criticality** from the `assets` table
3. **Computed risk score** (0-100 integer)

### 9.2 GeoIP Enrichment

```
Source IP  → geoCountry, geoCity       (MaxMind GeoLite2-City)
Dest IP    → geoCountryDst, geoCityDst (MaxMind GeoLite2-City)
```

Private/reserved IPs (`10.x`, `172.16-31.x`, `192.168.x`, `127.x`, `169.254.x`) are detected via `isPrivateIp()` and skip GeoIP lookup.

### 9.3 Asset Criticality

The `assets` table stores hostname/IP → criticality mappings (`low`, `medium`, `high`, `critical`). During enrichment, if the source hostname or IP matches an asset, the `assetCriticality` field is populated.

### 9.4 Risk Score Computation

`computeRiskScore()` calculates a 0-100 integer risk score using 6 weighted factors:

| Factor | Condition | Points |
|--------|-----------|--------|
| **Severity base** | `info`=0, `low`=10, `medium`=25, `high`=50, `critical`=75 | 0-75 |
| **Failure outcome** | outcome = `failure` / `error` | +15 |
| **Admin/privileged user** | username contains `admin`, `root`, `system`, `service` | +10 |
| **Asset criticality** | `high` = +10, `critical` = +15 | +10/+15 |
| **External → Internal traffic** | direction = `inbound` AND sourceIp is not private | +10 |
| **High-risk country** | geoCountry ∈ {CN, RU, KP, IR} | +15 |

**Final score:** `min(sum, 100)` — capped at 100.

### 9.5 Integration

```
Ingest endpoint → parse(rawLog) → enrichEvent(parsed) → INSERT raw_logs
                                        │
                                        ├─ GeoIP lookup (src + dst)
                                        ├─ Asset DB lookup
                                        └─ computeRiskScore() → riskScore column
```

The risk score is stored in `raw_logs.risk_score` (PostgreSQL `real` type) and is:
- Displayed in the Log Explorer table's "Risk" column with color-coded badges
- Filterable via SPL search: `risk_score>75`
- Used by detection rules for risk-based alerting

---

## 10. Python Integration Plan

### 10.1 Architecture Decision

**Keep Node.js as the real-time event bus.** Python runs as a separate HTTP service (FastAPI) for batch/analytics workloads. Communication via:
- **HTTP:** Node.js calls Python endpoints for Sigma conversion, IOC checks
- **Redis Streams:** Node.js enqueues events for async Python processing; Python publishes results back

### 10.2 Python Service Structure

```
secops-python/
├── pyproject.toml
├── requirements.txt
├── main.py                 # FastAPI app entry
├── routers/
│   ├── sigma.py           # POST /sigma/convert
│   ├── ioc.py             # POST /ioc/check, GET /ioc/feeds/refresh
│   └── analyze.py         # POST /analyze (full event analysis)
├── analyzers/
│   ├── anomaly.py         # Isolation Forest anomaly scoring
│   └── ueba.py            # Baseline builder + deviation scorer
├── feeds/
│   ├── abuseipdb.py       # AbuseIPDB API client
│   ├── otx.py             # AlienVault OTX client
│   └── __init__.py        # check_all_feeds()
├── workers/
│   └── stream_consumer.py # Redis Streams consumer for async analysis
└── models/
    └── schemas.py         # Pydantic models
```

### 10.3 FastAPI Endpoints

```python
# POST /sigma/convert
# Input: { sigma_yaml: "..." }
# Output: { converted: "..." }  ← your YAML format

# POST /ioc/check
# Input: { indicators: ["1.2.3.4", "evil.com"], types: ["ip", "domain"] }
# Output: { hits: [{ value: "1.2.3.4", source: "abuseipdb", confidence: 85, ... }] }

# POST /analyze
# Input: { event: { srcIp: "...", ... }, checks: ["ioc", "anomaly"] }
# Output: { iocHits: [...], anomalyScore: 0.87, anomalyReasons: ["..."] }
```

### 10.4 Node.js → Python Client

```typescript
// lib/python-client.ts
import axios from "axios";

const PYTHON_URL = process.env["PYTHON_ANALYTICS_URL"] ?? "http://localhost:9000";
const client = axios.create({ baseURL: PYTHON_URL, timeout: 5000 });

export async function convertSigmaRule(sigmaYaml: string): Promise<string | null> {
  try {
    const { data } = await client.post("/sigma/convert", { sigma_yaml: sigmaYaml });
    return data.converted;
  } catch { return null; }  // graceful degradation — Python down doesn't break Node
}

export async function checkIocs(indicators: string[]): Promise<any> {
  try {
    const { data } = await client.post("/ioc/check", { indicators, types: ["ip", "hash", "domain"] });
    return data;
  } catch { return null; }
}
```

---

## 11. Next Tasks — Exact Build Plan

These are ordered by **impact** and **interview value**. Do them in this order.

### Task 1: Database Indexes (CRITICAL — Do First)

**Why it matters:** Without indexes, your log search and alert filtering will be noticeably slow at 5K+ rows. Every interviewer who looks at your schema will ask about indexing.

**Files:** New Drizzle migration file

**What to do:**
1. Create migration SQL with indexes from Section 7.2
2. Run migration against your local PostgreSQL
3. Verify with `EXPLAIN ANALYZE` on a sample query

**Input:** SQL from Section 7.2  
**Output:** Migration file applied, queries using index scans  
**Test:** Seed 10K logs via bulk ingest, run `EXPLAIN ANALYZE SELECT * FROM raw_logs WHERE created_at > NOW() - INTERVAL '1 hour' ORDER BY created_at DESC LIMIT 50` — should show "Index Scan" not "Seq Scan"  
**Show in GitHub:** Screenshot of EXPLAIN ANALYZE output showing Index Scan in README

---

### Task 2: Extract Log Timestamps

**Why it matters:** Currently all events show `created_at = NOW()`. In a real SIEM, the event timestamp comes from the log itself. A 2-hour-old log shouldn't show as "just now".

**Files:** `parsers/syslog.ts`, `parsers/windows-eventlog.ts`, `parsers/types.ts`

**What to do:**
1. Add `parsedTimestamp?: Date` to `ParsedEvent` interface
2. In syslog parser: the regex already captures `(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})` — parse it with `date-fns`
3. In Windows parser: extract timestamp from XML `<TimeCreated SystemTime="...">` or JSON `@timestamp`
4. In pipeline: use `parsedTimestamp` instead of `new Date()` when inserting to `raw_logs.created_at`

**Input:** Raw log string containing timestamp  
**Output:** `parsedTimestamp` field on ParsedEvent  
**Test:** Ingest a log with yesterday's date. Verify `created_at` in raw_logs shows yesterday, not now.  
**Show in GitHub:** Code diff showing timestamp extraction logic

---

### Task 3: Playbook Rendering in Alert Detail

**Why it matters:** This is a key SOC L1 feature. When an alert fires, the analyst needs guided response steps. In interviews, say: "Each detection rule includes a playbook with step-by-step triage instructions."

**Files:** `AlertDetailPage.tsx`, rule YAML schema

**What to do:**
1. Parse `playbook:` section from rule YAML when loading alert detail
2. Display playbook steps as a checklist in the AlertDetailPage sidebar
3. Let analyst check off steps they've completed
4. Store completion state in alert timeline (type: "playbook_step", content: "Checked: Step 2")

**Input:** Rule YAML with `playbook.steps[]` array  
**Output:** Checklist UI in AlertDetailPage, completion logged to timeline  
**Test:** Create a rule with playbook steps. Trigger an alert. Verify playbook appears in detail view.  
**Show in GitHub/LinkedIn:** Screenshot of playbook panel with checklist steps

---

### Task 4: SLA Tracking

**Why it matters:** SOC teams are measured on MTTA (Mean Time to Acknowledge) and MTTR (Mean Time to Respond). Showing SLA timers proves you understand operational metrics.

**Files:** `alerts.service.ts`, `AlertQueuePage.tsx`, `AlertDetailPage.tsx`

**What to do:**
1. Define SLA config: `{ critical: { ack: 15m, resolve: 4h }, high: { ack: 30m, resolve: 8h }, medium: { ack: 2h, resolve: 24h } }`
2. When alert is created, compute `slaAckDeadline = createdAt + SLA[severity].ack`
3. When alert status changes to investigating, record `acknowledgedAt`
4. Frontend: show countdown timer. Turn red when SLA breached.
5. Dashboard: add MTTA/MTTR averages (you already have MTTR — add MTTA)

**Input:** Alert severity + creation timestamp  
**Output:** SLA deadline timestamps, breach status, MTTA metric  
**Test:** Create a critical alert. Wait 16 minutes. Verify SLA shows as breached in red.  
**Show in GitHub/LinkedIn:** Screenshot of alert queue with SLA countdown timers

---

### Task 5: Shift Handoff Report

**Why it matters:** L1 analysts work 8-hour shifts. At handoff, the outgoing analyst needs to brief the incoming analyst. This is a standard SOC process.

**Files:** New `reports.routes.ts`, new `ShiftHandoffPage.tsx`

**What to do:**
1. `GET /api/reports/shift-handoff?from=2026-03-29T06:00&to=2026-03-29T14:00`
2. Query: open alerts created/modified in range, group by status + severity
3. Include: new alerts, alerts still investigating, escalated alerts, resolved count
4. Frontend: printable summary page with tables

**Input:** Time range (shift start/end)  
**Output:** JSON report with alert summaries grouped by status  
**Test:** Create alerts across a time range. Call the endpoint. Verify counts match.  
**Show in GitHub/LinkedIn:** "Built SOC shift handoff reporting — a real operational tool used in production SOCs"

---

### Task 6: Slack Webhook Notifications

**Why it matters:** The #1 automation real SOC teams use. Critical alerts → Slack channel → analyst responds faster. Interviewers love seeing notification integration.

**Files:** New `lib/notifications.ts`, update `detection/pipeline.ts`

**What to do:**
1. Add `SLACK_WEBHOOK_URL` env var
2. On critical/high alert creation, POST to Slack webhook:
   ```json
   {
     "text": "🚨 *{severity}* alert: {title}",
     "blocks": [{ "type": "section", "text": { "type": "mrkdwn", "text": "Source: {srcIp} ({geoCountry})\nRule: {ruleName}\nMITRE: {mitreTactic}" }}]
   }
   ```
3. Make severity threshold configurable (`NOTIFY_MIN_SEVERITY=high`)

**Input:** Alert object  
**Output:** Slack message posted  
**Test:** Set up a free Slack workspace. Configure webhook. Trigger a critical alert. Verify Slack message.  
**Show in GitHub/LinkedIn:** Screenshot of Slack notification with alert details

---

### Task 7: Incident Workflow (Wire Up Existing Table)

**Why it matters:** Your `incidents` table exists but isn't connected to the frontend. Grouping related alerts into incidents is a core L2 feature that L1 analysts initiate.

**Files:** `incidents.routes.ts` (update), new `IncidentDetailPage.tsx`, `AlertDetailPage.tsx` (add "Create Incident" button)

**What to do:**
1. "Create Incident from Alert" button on AlertDetailPage
2. "Add Alert to Incident" on AlertQueuePage (select alerts → create incident)
3. Incident detail page shows all linked alerts, timeline, severity
4. Closing an incident closes all linked alerts

**Input:** Array of alert IDs  
**Output:** Incident record linking alerts  
**Test:** Select 3 related alerts. Create incident. Verify all appear on incident page.

---

## 12. Scripts & Modules to Build

### 12.1 Threat Intelligence Module (Node.js)

**Language:** TypeScript (Node.js)  
**Why Node.js:** The bloom filter IOC lookup runs in the hot path (every event). It must be in-process. The Python side handles feed ingestion.

```
secops-backend/src/lib/
  threat-intel.ts       → Bloom filter management + IOC DB queries
  threat-intel-feeds.ts → (later) OR call Python service
```

```typescript
// lib/threat-intel.ts
import { BloomFilter } from "bloom-filters";

let ipBloom = new BloomFilter(100000, 7);

export async function refreshIocBloomFilters(): Promise<void> {
  const iocs = await db.select().from(iocIndicatorsTable);
  ipBloom = new BloomFilter(Math.max(iocs.length * 2, 100000), 7);
  for (const ioc of iocs) {
    if (ioc.type === "ip") ipBloom.add(ioc.value);
  }
}

export function quickIocCheck(event: NormalizedEvent): string[] {
  const hits: string[] = [];
  if (event.srcIp && ipBloom.has(event.srcIp)) hits.push(`ip:${event.srcIp}`);
  if (event.dstIp && ipBloom.has(event.dstIp)) hits.push(`ip:${event.dstIp}`);
  return hits;
}
```

**Fits in SIEM flow:** Between enrichment and detection. If bloom filter hit, add `threatIntelHits` to event context. Boost alert severity.

### 12.2 Notification Service (Node.js)

**Language:** TypeScript  
**Folder:** `secops-backend/src/lib/notifications.ts`

```typescript
interface NotificationChannel {
  type: "slack" | "webhook" | "email";
  config: Record<string, string>;
}

export async function notifyAlert(alert: Alert, channels: NotificationChannel[]): Promise<void> {
  for (const channel of channels) {
    switch (channel.type) {
      case "slack":
        await axios.post(channel.config.webhookUrl, formatSlackMessage(alert));
        break;
      case "webhook":
        await axios.post(channel.config.url, alert, { headers: { "Content-Type": "application/json" } });
        break;
    }
  }
}
```

### 12.3 Sigma Converter (Python)

**Language:** Python  
**Folder:** `secops-python/routers/sigma.py`

```python
from sigma.rule import SigmaRule
from sigma.backends.generic import GenericTextBackend

@router.post("/sigma/convert")
async def convert_sigma(body: SigmaConvertRequest):
    rule = SigmaRule.from_yaml(body.sigma_yaml)
    # Convert to your custom YAML format
    converted = {
        "name": rule.title,
        "severity": rule.level.name.lower(),
        "type": "simple",  # or threshold based on condition
        "match": extract_conditions(rule),
        "mitre": extract_mitre(rule),
    }
    return {"converted": yaml.dump(converted)}
```

### 12.4 Report Generator (Node.js)

**Language:** TypeScript  
**Folder:** `secops-backend/src/modules/reports/`

```typescript
// reports.service.ts
export async function generateShiftHandoff(from: Date, to: Date) {
  const newAlerts = await db.select().from(alertsTable)
    .where(and(gte(alertsTable.createdAt, from), lte(alertsTable.createdAt, to)));
  
  const bySeverity = groupBy(newAlerts, "severity");
  const byStatus = groupBy(newAlerts, "status");
  const unresolved = newAlerts.filter(a => a.status !== "resolved" && a.status !== "false_positive");
  
  return {
    period: { from, to },
    summary: {
      total: newAlerts.length,
      byStatus,
      bySeverity,
      unresolvedCount: unresolved.length,
      criticalUnresolved: unresolved.filter(a => a.severity === "critical"),
    },
    topRules: getTopTriggeredRules(newAlerts),
    escalated: newAlerts.filter(a => /* check timeline for escalation notes */),
  };
}
```

---

## 13. Advanced Enhancements

These make the project look professional and differentiate it from typical tutorials.

### 13.1 Threat Intelligence Integration

```
┌─────────────────────────────────────────────────────┐
│                THREAT INTEL SUBSYSTEM                 │
│                                                       │
│  ┌─ Feed Ingestion (Python, every 4h) ───────────┐   │
│  │  AbuseIPDB (free tier, 1000 checks/day)       │   │
│  │  AlienVault OTX (free, unlimited)              │   │
│  │  → Normalize → ioc_indicators table            │   │
│  └────────────────────────────────────────────────┘   │
│                                                       │
│  ┌─ Real-time Matching (Node.js, in hot path) ───┐   │
│  │  1. Extract IPs, hashes, domains from event    │   │
│  │  2. Check bloom filter (O(1), ~1% false pos)   │   │
│  │  3. If hit → query ioc_indicators table        │   │
│  │  4. If confirmed → add threatIntelHits to event│   │
│  │  5. Boost alert severity if IOC match          │   │
│  └────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────┘
```

### 13.2 UEBA (User & Entity Behavior Analytics)

Build in Python. The core idea:
1. **Build baselines** from historical data (login hours, event volume, source IPs per user)
2. **Score deviations** when new events arrive (login at 3 AM? +40 points. New country? +50 points.)
3. **Generate anomaly alerts** when score exceeds threshold

```python
def score_event(event, baseline):
    score = 0
    reasons = []
    if event["hour"] not in baseline["normal_hours"]:
        score += 40; reasons.append(f"Unusual login hour: {event['hour']}")
    if event["srcIp"] not in baseline["known_ips"]:
        score += 25; reasons.append(f"New source IP: {event['srcIp']}")
    if event["geoCountry"] not in baseline["known_countries"]:
        score += 50; reasons.append(f"New country: {event['geoCountry']}")
    return score, reasons
```

### 13.3 MITRE ATT&CK Coverage Enhancement

You already have a heatmap. Enhance it:
1. **Coverage score:** Count techniques covered / total techniques (201 in Enterprise ATT&CK v14)
2. **Gap analysis:** Show uncovered tactics (e.g., "No rules for Lateral Movement")
3. **Navigator export:** Generate JSON compatible with MITRE ATT&CK Navigator tool

### 13.4 Real-time Event Filtering (WebSocket)

Add server-side filtering. Client sends filter after connecting:
```json
{ "subscribe": { "severity": ["high", "critical"], "srcIpCidr": "10.0.0.0/8" } }
```
Server only forwards matching events. Reduces client-side processing load.

### 13.5 Webhook Response Actions

Start with notifications. Don't build a full SOAR:

```yaml
# In rule YAML:
response:
  actions:
    - type: notify
      channel: slack
      template: "🚨 {{severity}} alert: {{title}} from {{srcIp}}"
```

Phase 1: `notify` (Slack/Teams webhook)  
Phase 2: `block_ip` (write to firewall rules table)  
Phase 3: `create_ticket` (Jira/ServiceNow API)

---

## 14. Development Roadmap

### Phase 1: Foundation Hardening ✅ Mostly Complete

| # | Task | Priority | Status |
|---|------|----------|--------|
| ~~1~~ | ~~Add database indexes (Section 7.2)~~ | ~~CRITICAL~~ | ✅ Done — 11 indexes on raw_logs |
| ~~2~~ | ~~Extract log timestamps from content~~ | ~~HIGH~~ | ✅ Done — all 7 parsers extract parsedTimestamp |
| 3 | Playbook rendering in AlertDetailPage | HIGH | ⬜ TODO |
| 4 | SLA tracking (countdown timers, breach alerts) | HIGH | ⬜ TODO |
| 5 | Shift handoff report endpoint + page | MEDIUM | ⬜ TODO |
| 6 | Slack webhook notifications | MEDIUM | ⬜ TODO |
| 7 | Wire up incidents workflow to frontend | MEDIUM | ⬜ TODO |
| ~~8~~ | ~~Parser registry pattern~~ | ~~—~~ | ✅ Done |
| ~~9~~ | ~~CEF parser~~ | ~~—~~ | ✅ Done |
| ~~10~~ | ~~ECS JSON parser~~ | ~~—~~ | ✅ Done |
| ~~11~~ | ~~LEEF parser~~ | ~~—~~ | ✅ Done |
| ~~12~~ | ~~CloudTrail parser~~ | ~~—~~ | ✅ Done |
| ~~13~~ | ~~gt/lt/gte/lte/cidr/exists/not modifiers~~ | ~~—~~ | ✅ Done |
| ~~14~~ | ~~Rule evaluation pre-filter index~~ | ~~—~~ | ✅ Done |
| ~~15~~ | ~~Data retention scheduler~~ | ~~—~~ | ✅ Done |
| ~~16~~ | ~~80+ field ParsedEvent schema~~ | ~~—~~ | ✅ Done — expanded from 21 fields |
| ~~17~~ | ~~50+ column DB schema~~ | ~~—~~ | ✅ Done — network, user, process, HTTP, DNS, file, registry, vendor, syslog fields |
| ~~18~~ | ~~SPL-like search engine~~ | ~~—~~ | ✅ Done — 50+ field aliases, 7 operators, boolean logic, free-text |
| ~~19~~ | ~~Risk scoring (0-100)~~ | ~~—~~ | ✅ Done — 6-factor weighted scoring |
| ~~20~~ | ~~Dual GeoIP enrichment~~ | ~~—~~ | ✅ Done — src + dst IP lookup |
| ~~21~~ | ~~15 seeded detection rules~~ | ~~—~~ | ✅ Done — covering 9 MITRE techniques |
| ~~22~~ | ~~Syslog parser upgrade (350+ lines)~~ | ~~—~~ | ✅ Done — 20+ program patterns, RFC3164+5424 |
| ~~23~~ | ~~Frontend Log Explorer upgrade~~ | ~~—~~ | ✅ Done — SPL search, dynamic filters, Splunk-style detail panel |
| ~~24~~ | ~~MITRE ATT&CK dedup fix~~ | ~~HIGH~~ | ✅ Done — composite key deduplication in heatmap widget |
| ~~25~~ | ~~Dashboard time-range selector~~ | ~~HIGH~~ | ✅ Done — 1h/6h/24h/7d/30d with backend range param |
| ~~26~~ | ~~Dashboard drill-through stat cards~~ | ~~MEDIUM~~ | ✅ Done — click stat card → navigate to filtered page |
| ~~27~~ | ~~Dashboard MITRE coverage ring widget~~ | ~~MEDIUM~~ | ✅ Done — radial chart showing covered vs total techniques |
| ~~28~~ | ~~Alert Queue date range + group-by~~ | ~~HIGH~~ | ✅ Done — TIME_RANGES filter + group by rule/MITRE toggle |
| ~~29~~ | ~~Alert Detail investigation checklist~~ | ~~HIGH~~ | ✅ Done — persistent via localStorage per alert |
| ~~30~~ | ~~Alert Detail IOC extraction panel~~ | ~~HIGH~~ | ✅ Done — auto-extract IPs, domains, hashes from alert data |
| ~~31~~ | ~~Detection Rules full MITRE taxonomy picker~~ | ~~HIGH~~ | ✅ Done — ~60 techniques across 14 tactics, grouped + searchable |
| ~~32~~ | ~~Detection Rules severity filter~~ | ~~MEDIUM~~ | ✅ Done — dropdown filter by severity level |
| ~~33~~ | ~~Log Explorer column picker~~ | ~~HIGH~~ | ✅ Done — customizable columns with localStorage persistence |
| ~~34~~ | ~~Log Explorer CSV export~~ | ~~MEDIUM~~ | ✅ Done — export filtered results to CSV |
| ~~35~~ | ~~Audit Log React Query migration~~ | ~~HIGH~~ | ✅ Done — replaced useState/useEffect with useQuery |
| ~~36~~ | ~~Audit Log filter bar + CSV export~~ | ~~HIGH~~ | ✅ Done — user/action/status/date filters + CSV download |
| ~~37~~ | ~~Assets CSV export~~ | ~~MEDIUM~~ | ✅ Done — download asset inventory as CSV |
| ~~38~~ | ~~Settings password strength meter~~ | ~~MEDIUM~~ | ✅ Done — 5-bar visual indicator (Weak→Very Strong) |
| ~~39~~ | ~~Accessibility aria-labels~~ | ~~LOW~~ | ✅ Done — select elements, widget containers |
| ~~40~~ | ~~Logs Explorer blank page fix~~ | ~~CRITICAL~~ | ✅ Done — 4 root causes identified and fixed (see §14.1.1) |
| ~~41~~ | ~~WebSocket auth guard~~ | ~~HIGH~~ | ✅ Done — both hooks check for token before connecting |
| ~~42~~ | ~~React ErrorBoundary~~ | ~~HIGH~~ | ✅ Done — wraps all route content in MainLayout |
| ~~43~~ | ~~Safe date formatting (all pages)~~ | ~~HIGH~~ | ✅ Done — `safeFormat()` on every page with date rendering |
| ~~44~~ | ~~Real-time WebSocket on Dashboard + AlertQueue~~ | ~~HIGH~~ | ✅ Done — `useWebSocket()` auto-invalidates React Query caches |
| ~~45~~ | ~~Time-range-aware histogram~~ | ~~MEDIUM~~ | ✅ Done — frontend sends `hours` param, backend respects it |
| ~~46~~ | ~~Backend `from` relative time filter for logs~~ | ~~MEDIUM~~ | ✅ Done — `GET /api/logs?from=15m` parses relative time strings |
| ~~47~~ | ~~Histogram response shape fix~~ | ~~HIGH~~ | ✅ Done — backend returns `{ bucket }` matching frontend `dataKey` |

#### §14.1.1 Logs Explorer Blank Page — Root Cause Analysis & Fix

The Logs Explorer page was crashing with a blank screen due to 4 independent root causes:

| # | Root Cause | Fix Applied | Files Modified |
|---|-----------|-------------|----------------|
| **RC1** | WebSocket hooks attempted connection before auth token existed, causing silent 401 failures and reconnect loops | Added `if (!localStorage.getItem("access_token")) return;` guard before `new WebSocket()` | `useWebSocket.ts`, `useEventStream.ts` |
| **RC2** | `date-fns/format()` throws "Invalid time value" on null/undefined/malformed dates from API responses | Created `safeFormat()` wrappers using `isValid()` + try/catch on every page; added null guards in API normalizers (`normalizeLog`, `normalizeAlert`, `normalizeRule`) | `api.ts`, all 6 page files with date rendering |
| **RC3** | Recharts crashed because histogram backend returned `{ time: bucket }` but frontend used `dataKey="bucket"` | Changed backend histogram response from `{ time: r.bucket }` → `{ bucket: r.bucket }` | `ingest.routes.ts` |
| **RC4** | No React ErrorBoundary — any component crash propagated upward and blanked the entire page | Created `ErrorBoundary` class component with styled fallback UI and "Try Again" button; wrapped all MainLayout routes | `ErrorBoundary.tsx` (new), `App.tsx` |

#### §14.1.2 WebSocket Failure — Root Cause Analysis & Fix

WebSocket connections to `/ws/alerts` and `/ws/events/live` were failing silently:

- **Root Cause:** Hooks fired during initial render before login completed. The backend's `requireAuth` on WebSocket upgrade rejected unauthenticated connections.
- **Fix:** Both `useWebSocket.ts` and `useEventStream.ts` now check `localStorage.getItem("access_token")` before attempting connection. The `useEffect` dependency array already includes the token, so hooks reconnect automatically after login.

#### §14.1.3 Advanced SIEM Stability Upgrades

| Upgrade | Description | Impact |
|---------|-------------|--------|
| **ErrorBoundary** | React class component wrapping all route content. Catches render errors, shows styled fallback with "Try Again" button. | Prevents single component crashes from blanking the entire app |
| **Safe date formatting** | `safeFormat()` utility on every page using `date-fns`. Uses `isValid()` check + try/catch, returns `'—'` fallback. | Eliminates "Invalid time value" crashes across the entire frontend |
| **Real-time Dashboard** | `useWebSocket()` hook on DashboardPage auto-invalidates `dashboard-stats` and `alerts` React Query caches when new alerts arrive | Dashboard stats and alert tables update in real-time without manual refresh |
| **Real-time AlertQueue** | `useWebSocket()` hook on AlertQueuePage auto-invalidates alert caches | New alerts appear instantly in the SOC analyst's queue |
| **Time-range histogram** | Frontend computes `hours` from selected time range (`15m`→0.25, `1h`→1, `7d`→168) and sends to `POST /events/histogram`. Backend uses `hours` for query window. | Histogram chart always matches the selected time filter |
| **Relative time log filtering** | `GET /api/logs?from=15m` parses relative time strings (`15m`, `1h`, `6h`, `24h`, `7d`, `30d`) via regex `/^(\d+)([mhd])$/` | Log Explorer filter dropdown values correctly translate to time-windowed queries |

### Phase 2: Python Analytics Service (3-4 weeks)

| # | Task | Details |
|---|------|---------|
| 1 | Scaffold `secops-python/` | FastAPI + Redis client + PostgreSQL |
| 2 | Sigma converter | pySigma integration. Import community rules. |
| 3 | IOC table + bloom filter | Node.js bloom filter in hot path. |
| 4 | Threat intel feeds | AbuseIPDB (free) + AlienVault OTX (free) |
| 5 | Redis Streams bridge | Node.js enqueues, Python consumes |
| 6 | `/analyze` endpoint | Full event analysis (IOC + anomaly) |
| 7 | Node.js → Python HTTP client | `lib/python-client.ts` |
| 8 | Frequency + absence rules | Detection engine expansion |

### Phase 3: SOC Operations (2-3 weeks)

| # | Task | Details |
|---|------|---------|
| 1 | Alert enrichment panel | One-click context sidebar: GeoIP, asset, threat intel, related events |
| 2 | MITRE coverage report | Gap analysis + Navigator layer export |
| 3 | Entity profile page | Show user/host behavioral timeline |
| 4 | Composite/correlation rules | Cross-rule correlation |

### Phase 4: Behavioral Analytics (3-4 weeks)

| # | Task | Details |
|---|------|---------|
| 1 | UEBA baselines table | Statistical norms per entity |
| 2 | Baseline builder (Python) | Login hours, event volume, source IPs |
| 3 | Anomaly scorer + alerts | Score events against baselines |
| 4 | Entity profile page | Frontend behavioral timeline |

### What NOT to Waste Time On

| Don't Build | Why |
|------------|-----|
| ~~Custom query language~~ | ✅ Built — SPL-like search engine (Section 8) |
| Full SOAR workflow designer | Drag-and-drop workflow builder is a separate product. |
| Multi-tenancy | Single-org tool. Tenant isolation adds complexity everywhere. |
| Custom charting library | Recharts is already working. |
| SSO/SAML | Use `passport-saml` if needed later. Don't build SAML parsing. |
| Log shipping agent | Use Filebeat/Fluentd. Don't build a log collector. |
| Full Sigma parser in Node.js | Use pySigma in Python. Native Sigma parsing is a rabbit hole. |

---

## 15. Build vs. Use Libraries

### 15.1 Build It Yourself

| Component | Why Build | What You Learn |
|-----------|-----------|----------------|
| Log parsers (7 formats) | ✅ Built | Log format internals, field extraction, severity mapping |
| Detection engine (3 rule types) | ✅ Built | How SIEM correlation works at rule level |
| Parser registry / plugin system | ✅ Built | Plugin architecture patterns |
| Rule condition DSL (10+ modifiers) | ✅ Built | How Sigma/YARA condition languages work |
| Alert triage workflow | ✅ Built | SOC analyst daily operations |
| Enrichment pipeline | ✅ Built | How context gets added to raw events |
| RBAC system | ✅ Built | Access control in security tools |
| Normalized event schema | ✅ Built | Why field consistency matters |
| Bloom filter wrapper | Build next | Probabilistic data structures in security |
| SLA tracking | Build next | SOC operational metrics |
| Shift handoff reports | Build next | SOC operational processes |
| Playbook renderer | Build next | Alert response procedures |

### 15.2 Use a Library

| Component | Library | Why Not Build |
|-----------|---------|---------------|
| Sigma rule parsing | `pySigma` (Python) | Official SDK. 5000+ community rules. |
| YARA scanning | `yara-python` | C-based engine. Don't rewrite regex matching. |
| Threat intel feeds | `pyTAXII` + `stix2` | Complex protocol. Don't implement it. |
| ML anomaly detection | `scikit-learn` / `PyOD` | Tested statistical models. |
| GeoIP | `geoip-lite` (already using) | Database-backed lookup. |
| Bloom filter | `bloom-filters` (npm) | Tested bit manipulation. |
| PDF reports | `puppeteer` or `pdfkit` | Don't hand-craft PDF bytes. |
| Slack notifications | `@slack/web-api` or raw `axios` POST | Tested API client. |

### 15.3 Don't Build At All

| Component | Why Skip |
|-----------|----------|
| ~~Custom query language~~ | ✅ Built — SPL-like search parser (Section 8) |
| Full SOAR engine with workflow designer | Webhook notifications are the 80/20 solution |
| Multi-tenancy | You're building a single-org tool |
| Custom charting library | Use Recharts (already have it) |
| SSO/SAML provider | Use `passport-saml` when needed |
| Log shipping agent | Use Filebeat/Fluentd/rsyslog |

---

## 16. Interview Guidance

### 16.1 What Interviewers Will Ask

| Question | Your Answer |
|----------|------------|
| "Walk me through your architecture" | "Three-tier: React frontend, Node.js API with real-time detection engine, PostgreSQL + Redis. Logs come in via syslog or HTTP, get parsed by one of 7 format parsers, enriched with GeoIP and asset data, evaluated against detection rules, and surface as alerts to the SOC analyst's queue via WebSocket." |
| "How does your detection engine work?" | "I built three rule types: simple match, threshold (N events per field in timeframe), and sequence (ordered multi-step). Rules are Sigma-inspired YAML with 10+ modifiers including CIDR matching and negation. I added a pre-filter index so only candidate rules are evaluated per event — otherwise it's O(rules × events) which doesn't scale." |
| "How do you handle alert fatigue?" | "Three mechanisms: deduplication windows prevent the same alert from firing repeatedly, rate limiting caps alerts per hour per rule, and pre-filter indexing reduces unnecessary rule evaluations." |
| "What's your enrichment pipeline?" | "Dual GeoIP lookup on both source and destination IPs, asset criticality from inventory cache, and a 6-factor risk score (0-100) computed per event — factoring severity, outcome, privileged user, asset criticality, external-to-internal direction, and high-risk geo countries." |
| "How do you handle log parsing at scale?" | "Plugin registry pattern. Each parser self-registers with sourceType mappings and a priority-ordered canParse() function for auto-detection. The registry tries exact match first, then content sniffing, then falls back to a generic parser." |
| "What would you do differently?" | "I'd add Sigma rule conversion via pySigma to import community detection content. I'd also add table partitioning for raw_logs when we hit millions of rows, and I'd move anomaly detection to a Python sidecar with scikit-learn." |
| "How do analysts search logs?" | "I built an SPL-like search engine with 50+ field aliases, 7 comparison operators including wildcard matching, boolean logic (AND/OR/NOT), and free-text keyword search across 6 columns. Analysts type queries like `src_ip=10.0.0.1 AND severity=high` in a search bar — it compiles to Drizzle ORM conditions." |
| "What SOC workflow does this support?" | "Full L1 workflow: ingest → parse → normalize → enrich → detect → alert → triage → respond. Analysts get real-time alerts, playbook instructions, timeline annotations, bulk actions, SLA tracking, and shift handoff reports." |

### 16.2 What To Claim As Your Own Work

**Claim confidently:**
- Detection engine (3 rule types, modifiers, pre-filter index) — you wrote every line
- 7 log parsers with plugin registry — you wrote every line
- SPL-like search engine with 50+ field aliases — you wrote every line
- Risk scoring engine (6-factor, 0-100) — you wrote every line
- 80+ field normalized event schema — you designed the field taxonomy
- Alert triage workflow (status machine, timeline, assignment) — you designed it
- RBAC system with 6 roles — you designed the permission matrix
- Real-time WebSocket streaming — you implemented it
- Dual GeoIP enrichment (src + dst) — you implemented it
- Splunk-style log detail panel with 10 sections — you built the frontend
- Redis Streams pipeline with dead letter queue — you built it
- Data retention and scheduling — you implemented it
- Frontend: Dashboard, AlertQueue, AlertDetail, RuleBuilder, MITRE heatmap — you built them

**Claim with nuance:**
- "I used Radix UI for the base component library and customized the design with Tailwind"
- "I used Drizzle ORM for type-safe database queries"
- "I used geoip-lite for the GeoIP enrichment"
- "The React frontend uses Zustand for state and React Query for server cache"

**Do NOT claim:**
- That you wrote the 62 Radix UI wrapper components — they're standard shadcn/ui boilerplate
- That you built a "production-ready SIEM" — say "production-grade architecture for a portfolio project"
- That it handles "millions of events per second" — say "tested with bulk ingestion of 10K events"
- That it has ML anomaly detection — until you build it

### 16.3 What Not To Exaggerate

- Don't say "I built a SIEM from scratch" — say "I built a SIEM pipeline (ingest, parse, detect, alert, triage) from scratch to learn SOC operations"
- Don't claim "battle-tested at scale" — say "designed for horizontal scaling via Redis Streams consumer groups"
- Don't say "compatible with Sigma" — say "Sigma-inspired rule format with plans to add pySigma conversion"
- Don't mention Docker unless asked — focus on the engineering, not deployment config
- Don't overclaim the frontend — say "I built 14 functional pages including a detection rule builder with live YAML preview"

---

## 17. GitHub & LinkedIn Guidance

### 17.1 README Structure

```markdown
# SecOps Console — Mini-SIEM with Detection Engine

> A full-stack Security Operations Center platform built from scratch to demonstrate
> SOC L1 engineering: log parsing, real-time detection, alert triage, and incident response.

## Architecture
[Insert architecture diagram from Section 3.1]

## Features
- **7 Log Format Parsers** — Syslog, Windows EventLog, Firewall, CEF, ECS/JSON, LEEF, CloudTrail
- **Real-time Detection Engine** — Simple, threshold, and sequence rules with 10+ condition modifiers
- **SOC L1 Workflow** — Alert queue, playbooks, SLA tracking, timeline annotations, shift handoff
- **6-Role RBAC** — Admin, SOC Manager, Detection Engineer, L2, L1, Viewer
- **MITRE ATT&CK Mapping** — Heatmap showing detection coverage across ATT&CK techniques
- **Event Pipeline** — Redis Streams consumer groups, dead letter queue, data retention
- **Asset Inventory** — Hosts, criticality levels, used for alert enrichment

## Tech Stack
| Layer | Technology |
|-------|-----------|
| Frontend | React 19, TypeScript, Tailwind CSS, Radix UI, Recharts |
| Backend | Node.js, Express 5, TypeScript |
| Database | PostgreSQL 18, Drizzle ORM |
| Cache/Streams | Redis 7 (cache, pub/sub, streams, EPS tracking) |
| Auth | JWT + bcrypt, 6-role RBAC |
| Analytics (planned) | Python, FastAPI, pySigma, scikit-learn |

## Screenshots
[Dashboard] [Alert Queue] [Rule Builder] [MITRE Heatmap] [Alert Detail with Timeline]

## What I Built vs. What I Used
- **Built from scratch:** Detection engine, log parsers, parser registry, alert triage workflow, RBAC, WebSocket streaming, enrichment pipeline
- **Libraries used:** Express, Drizzle ORM, Radix UI, geoip-lite, jsonwebtoken, ioredis

## SOC L1 Workflow
[Paste simplified version of Section 4.1 pipeline diagram]

## Running Locally
\```bash
# Prerequisites: Node.js 22+, PostgreSQL 18, Redis 7
cd secops-backend && npm install && npm run build
cd secops-frontend && npm install && npm run dev
\```

## Roadmap
- [x] Phase 1: Parser registry, 7 parsers, detection modifiers, data retention
- [x] Phase 1.5: Advanced UI enhancements — time-range selectors, drill-through navigation, MITRE coverage widget, alert grouping, IOC extraction, investigation checklists, full MITRE taxonomy picker, column pickers, CSV exports, password strength meter, audit log filters, accessibility
- [ ] Phase 2: Python analytics (Sigma conversion, threat intel, anomaly detection)
- [ ] Phase 3: SOC operations (SLA, shift handoff, alert enrichment panel)
```

### 17.2 Screenshots to Include

1. **Dashboard** — Show stat cards with drill-through, alert trend chart, severity pie chart, time-range selector, MITRE coverage ring widget
2. **Alert Queue** — Show alerts with severity badges, status, assigned analyst, date range filter, group-by toggle (rule/MITRE)
3. **Alert Detail** — Show timeline, related events, IOC extraction panel, persistent investigation checklist, status machine
4. **Rule Builder** — Show YAML preview, full MITRE taxonomy picker (grouped by tactic), test button
5. **MITRE ATT&CK Heatmap** — Show deduplicated covered techniques in color
6. **Log Explorer** — Show filtered logs with column picker, time range filter, CSV export button
7. **Audit Log** — Show filter bar (action, user, status, date range), CSV export
8. **Settings** — Show password strength meter (5-bar visual)
9. **Architecture Diagram** — ASCII or Mermaid diagram from Section 3.1

### 17.3 LinkedIn Project Description

> **SecOps Console — Mini-SIEM with Real-time Detection Engine**
>
> I built a full-stack Security Operations Center platform from scratch to deeply learn SOC L1 engineering. The system ingests logs from 7 formats (syslog, Windows EventLog, CEF, ECS, LEEF, CloudTrail, firewall), parses and normalizes them through a plugin-based parser registry, enriches events with GeoIP and asset context, and evaluates them against a custom detection engine supporting simple, threshold, and sequence rules with 10+ condition modifiers including CIDR matching and field negation. Alerts surface in real-time via WebSocket to a SOC analyst queue with full triage workflow: assignment, timeline annotations, playbook-guided response, SLA tracking, and MITRE ATT&CK mapping. Built with React 19, Node.js/Express 5, PostgreSQL, and Redis Streams.

### 17.4 What NOT to Write

- ❌ "Built an enterprise-grade SIEM" — sounds fake
- ❌ "Handles millions of events" — unverifiable
- ❌ "Production-ready security platform" — a recruiters will test this claim
- ❌ "AI-powered detection" — unless you actually ship ML
- ❌ Listing every library as a feature ("Features: Express, React, Redis...")

---

## Appendix A: File Reference

| Purpose | File |
|---------|------|
| **Backend Core** | |
| Express app setup | `secops-backend/src/app.ts` |
| Server entry point | `secops-backend/src/index.ts` |
| Build config | `secops-backend/build.mjs` |
| **Database** | |
| Drizzle ORM connection | `secops-backend/src/db/index.ts` |
| Schema exports | `secops-backend/src/db/schema/index.ts` |
| Users table | `secops-backend/src/db/schema/users.ts` |
| Alerts + timeline tables | `secops-backend/src/db/schema/alerts.ts` |
| Rules table | `secops-backend/src/db/schema/rules.ts` |
| Raw logs table (50+ columns, 11 indexes) | `secops-backend/src/db/schema/logs.ts` |
| Assets table | `secops-backend/src/db/schema/assets.ts` |
| Incidents table | `secops-backend/src/db/schema/incidents.ts` |
| API keys table | `secops-backend/src/db/schema/api-keys.ts` |
| Audit logs table | `secops-backend/src/db/schema/audit-logs.ts` |
| **Parsers** | |
| Parser plugin registry | `secops-backend/src/lib/parsers/registry.ts` |
| Parser router + exports | `secops-backend/src/lib/parsers/index.ts` |
| ParsedEvent interface (80+ fields) | `secops-backend/src/lib/parsers/types.ts` |
| Syslog (RFC3164+5424, 350+ lines, 20+ programs) | `secops-backend/src/lib/parsers/syslog.ts` |
| Windows EventLog (Sysmon 1/3/7/11/13, 4624/4625/4688/4720/4732) | `secops-backend/src/lib/parsers/windows-eventlog.ts` |
| Firewall (iptables) | `secops-backend/src/lib/parsers/firewall.ts` |
| CEF (ArcSight) | `secops-backend/src/lib/parsers/cef.ts` |
| ECS JSON (Elastic) | `secops-backend/src/lib/parsers/ecs-json.ts` |
| LEEF (IBM QRadar) | `secops-backend/src/lib/parsers/leef.ts` |
| CloudTrail (AWS) | `secops-backend/src/lib/parsers/cloudtrail.ts` |
| **Detection** | |
| Detection engine (core) | `secops-backend/src/lib/detection/engine.ts` |
| Detection types | `secops-backend/src/lib/detection/types.ts` |
| Processing pipeline | `secops-backend/src/lib/detection/pipeline.ts` |
| **Libraries** | |
| Enrichment (dual GeoIP + risk scoring) | `secops-backend/src/lib/enrichment.ts` |
| SPL-like search parser (50+ field aliases) | `secops-backend/src/lib/search/spl-parser.ts` |
| Redis client + streams | `secops-backend/src/lib/redis.ts` |
| WebSocket server | `secops-backend/src/lib/websocket.ts` |
| Scheduler (cron jobs) | `secops-backend/src/lib/scheduler.ts` |
| JWT utilities | `secops-backend/src/lib/jwt.ts` |
| Audit logger | `secops-backend/src/lib/audit.ts` |
| Pino logger | `secops-backend/src/lib/logger.ts` |
| **Middleware** | |
| JWT auth | `secops-backend/src/middlewares/auth.middleware.ts` |
| RBAC enforcement | `secops-backend/src/middlewares/rbac.middleware.ts` |
| **API Modules** | |
| Auth (login, refresh, logout) | `secops-backend/src/modules/auth/` |
| Me (profile, settings, API keys) | `secops-backend/src/modules/me/` |
| Users (CRUD, role management) | `secops-backend/src/modules/users/` |
| Alerts (queue, triage, timeline) | `secops-backend/src/modules/alerts/` |
| Rules (CRUD, test, stats) | `secops-backend/src/modules/rules/` |
| Dashboard (stats, metrics) | `secops-backend/src/modules/dashboard/` |
| Audit (compliance log) | `secops-backend/src/modules/audit/` |
| Ingest (single, bulk, pending) | `secops-backend/src/modules/ingest/` |
| Assets (inventory) | `secops-backend/src/modules/assets/` |
| **Workers** | |
| Pipeline worker | `secops-backend/src/workers/pipeline-worker.ts` |
| **Frontend** | |
| App router | `secops-frontend/src/App.tsx` |
| Auth store (Zustand) | `secops-frontend/src/store/authStore.ts` |
| API client (axios) | `secops-frontend/src/lib/api.ts` |
| Type definitions | `secops-frontend/src/lib/types.ts` |
| WebSocket hook (alerts) | `secops-frontend/src/hooks/useWebSocket.ts` |
| WebSocket hook (events) | `secops-frontend/src/hooks/useEventStream.ts` |
| **Frontend Pages** | |
| Login | `secops-frontend/src/pages/LoginPage.tsx` |
| Dashboard | `secops-frontend/src/pages/DashboardPage.tsx` |
| Alert Queue | `secops-frontend/src/pages/AlertQueuePage.tsx` |
| Alert Detail | `secops-frontend/src/pages/AlertDetailPage.tsx` |
| Log Explorer | `secops-frontend/src/pages/LogsExplorerPage.tsx` |
| Detection Rules | `secops-frontend/src/pages/DetectionRulesPage.tsx` |
| Rule Builder | `secops-frontend/src/pages/RuleBuilderPage.tsx` |
| MITRE ATT&CK | `secops-frontend/src/pages/MitreAttackPage.tsx` |
| Log Ingestion | `secops-frontend/src/pages/LogIngestionPage.tsx` |
| Assets | `secops-frontend/src/pages/AssetsPage.tsx` |
| Audit Log | `secops-frontend/src/pages/AuditLogPage.tsx` |
| User Management | `secops-frontend/src/pages/UserManagementPage.tsx` |
| Settings | `secops-frontend/src/pages/SettingsPage.tsx` |
| **Frontend Components** | |
| Error boundary (crash resilience) | `secops-frontend/src/components/ErrorBoundary.tsx` |
| **Frontend Libraries** | |
| RBAC constants (ROLE_COLORS, ROLE_LABELS, ROLE_HIERARCHY) | `secops-frontend/src/lib/constants.ts` |
| MITRE ATT&CK taxonomy (14 tactics, ~60 techniques) | `secops-frontend/src/lib/mitre-taxonomy.ts` |

---

## Appendix B: Rule YAML Format

```yaml
# ─── CURRENT FORMAT (all features working) ───
name: "SSH Brute Force Detection"
description: "Detects multiple SSH login failures from the same IP"
severity: high
type: threshold                # simple | threshold | sequence

match:
  action: login_failure
  sourceType: syslog
  processName: sshd

filter:                        # events matching filter are EXCLUDED
  userName: root

threshold:
  field: srcIp
  count: 5
  timeframe: 5m

dedup_window: 1h
max_alerts_per_hour: 10

mitre:
  tactic: Credential Access
  technique_id: T1110.001
  technique_name: Brute Force - Password Guessing

alert:
  title_template: "SSH Brute Force: {count} failures from {srcIp}"
  context_fields: [srcIp, userName, sourceHost, geoCountry]

tags: [brute_force, ssh, external]

# ─── EXTENSIONS (building in Phase 1-3) ───

playbook:
  title: "SSH Brute Force Response"
  steps:
    - "Check source IP reputation in Threat Intel panel"
    - "Verify if target host is internet-facing"
    - "Search for login_success from same srcIp after failures"
    - "If success found → Escalate to L2"
    - "If no success + external IP → Block at firewall"
  escalation:
    condition: "login_success after brute force"
    to: soc_l2
    sla: 15m

response:
  actions:
    - type: notify
      channel: slack
      template: "🚨 SSH Brute Force: {count} failures from {srcIp} → {sourceHost}"
    - type: block_ip
      target: "{srcIp}"
      duration: 24h
      condition: "geoCountry NOT IN ['IN', 'US']"
```

---

## Appendix C: API Endpoint Reference

### Auth
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/login` | Authenticate (username/email + password) |
| POST | `/api/auth/refresh` | Refresh access token |
| POST | `/api/auth/logout` | Invalidate session |
| GET | `/api/auth/me` | Get current user profile |

### Me (Self-Service)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/me` | Get my profile |
| PATCH | `/api/me` | Update displayName, jobTitle |
| POST | `/api/me/password` | Change password |
| GET | `/api/me/settings` | Get user settings |
| PATCH | `/api/me/settings` | Update settings |
| GET | `/api/me/api-keys` | List my API keys |
| POST | `/api/me/api-keys` | Create API key |
| DELETE | `/api/me/api-keys/:id` | Delete API key |

### Users (Admin/SOC Manager)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/users` | List all users |
| GET | `/api/users/:id` | Get user details |
| POST | `/api/users` | Create user |
| PATCH | `/api/users/:id` | Update user |
| POST | `/api/users/:id/reset-password` | Admin password reset |

### Alerts
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/alerts` | List alerts (filter: status, severity, search) |
| GET | `/api/alerts/:id` | Get alert detail + timeline |
| PATCH | `/api/alerts/:id/status` | Update alert status |
| PATCH | `/api/alerts/:id/assign` | Assign alert to analyst |
| POST | `/api/alerts/:id/timeline` | Add timeline entry |
| POST | `/api/alerts/bulk-update` | Bulk status update |
| GET | `/api/alerts/:id/related-events` | Related raw logs |

### Rules
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/rules` | List detection rules |
| GET | `/api/rules/:id` | Get rule detail |
| POST | `/api/rules` | Create rule |
| PATCH | `/api/rules/:id` | Update rule |
| DELETE | `/api/rules/:id` | Delete rule |
| PATCH | `/api/rules/:id/toggle` | Enable/disable |
| POST | `/api/rules/:id/test` | Test rule |
| GET | `/api/rules/:id/stats` | Rule stats |

### Dashboard
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/dashboard/stats` | All dashboard metrics |

### Ingest & Logs
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/ingest-log` | Ingest single log |
| POST | `/api/ingest/bulk` | Bulk ingest (up to 10K) |
| GET | `/api/ingest/pending` | List unprocessed logs |
| POST | `/api/ingest/detections` | Bulk create alerts |
| GET | `/api/logs` | Search logs (supports `q` param with SPL-like syntax) |
| GET | `/api/logs/filters` | Dynamic distinct values for source, severity, category dropdowns |

### Assets
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/assets` | List assets |
| POST | `/api/assets` | Create asset |
| PATCH | `/api/assets/:id` | Update asset |

### Audit
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/audit` | List audit logs |

### Health
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Service health check |

### WebSocket
| Endpoint | Description |
|----------|-------------|
| `ws://host/ws/alerts` | Real-time alert stream |
| `ws://host/ws/events/live` | Real-time raw event stream |

---

*This document is a living reference. Update it as you build each phase.*
