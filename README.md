<div align="center">

# SecOps Console

<img src="https://img.shields.io/badge/version-1.0.0-0f172a?style=for-the-badge" alt="Version"/>
&nbsp;
<img src="https://img.shields.io/badge/TypeScript-5.x-3178c6?style=for-the-badge&logo=typescript&logoColor=white" alt="TypeScript"/>
&nbsp;
<img src="https://img.shields.io/badge/React-19-61dafb?style=for-the-badge&logo=react&logoColor=black" alt="React"/>
&nbsp;
<img src="https://img.shields.io/badge/Node.js-22-339933?style=for-the-badge&logo=nodedotjs&logoColor=white" alt="Node.js"/>
&nbsp;
<img src="https://img.shields.io/badge/PostgreSQL-15+-336791?style=for-the-badge&logo=postgresql&logoColor=white" alt="PostgreSQL"/>
&nbsp;
<img src="https://img.shields.io/badge/Redis-7-dc382d?style=for-the-badge&logo=redis&logoColor=white" alt="Redis"/>

**A production-grade mini-SIEM and SOC analyst workspace.**  
Real-time log ingestion · MITRE-mapped detection · Full SOC triage workflow · Built-in threat enrichment.

[Quick Start](#-quick-start) · [Features](#-features) · [Architecture](ARCHITECTURE.md) · [Detection Rules](Guide.md) · [API Reference](#-api-reference)

</div>

---

## 📖 Overview

SecOps Console is a self-hosted Security Information and Event Management (SIEM) platform designed for detection engineers and SOC analysts. It ingests raw logs from any source, normalises and enriches them, runs them through a detection engine with 15 pre-built MITRE ATT&CK-mapped rules, and surfaces actionable alerts in a real-time analyst UI.

```
Raw Logs  →  Parser Registry  →  Enrichment  →  Detection Engine  →  Alert Queue
(syslog / Windows / CEF /        (GeoIP + Asset     (simple / threshold /     (WebSocket
 CloudTrail / DNS / …)            + Risk Score)       sequence rules)           live push)
```

Everything runs as a single cohesive application with no external services beyond PostgreSQL and Redis.

---

## ✨ Features

<table>
<tr><th width="200">Area</th><th>What's Included</th></tr>
<tr>
<td><strong>Log Ingestion</strong></td>
<td>HTTP single/bulk/raw endpoints + UDP/TCP syslog receiver (port 1514). Ingest from any source.</td>
</tr>
<tr>
<td><strong>Parser Registry</strong></td>
<td>9 parsers covering Syslog (20+ programs), Windows EventLog (40+ EventIDs + Sysmon), CEF, ECS JSON, LEEF, CloudTrail, DNS, Firewall, and Generic — each extracting 50+ normalised fields.</td>
</tr>
<tr>
<td><strong>Detection Engine</strong></td>
<td><code>simple</code>, <code>threshold</code>, and <code>sequence</code> rule types. 12 field modifiers. Pre-filter index for fast evaluation. Alert deduplication and per-rule rate limiting.</td>
</tr>
<tr>
<td><strong>Seeded Rules</strong></td>
<td>15 production-ready rules covering brute force, PowerShell abuse, Kerberoasting, LSASS dumping, DNS tunnelling, CloudTrail root usage, lateral movement, and more.</td>
</tr>
<tr>
<td><strong>SPL Search</strong></td>
<td>Splunk-style query language: field equality, comparison operators, wildcards, boolean logic, pipe commands (<code>stats</code>, <code>sort</code>, <code>head</code>), and free-text search.</td>
</tr>
<tr>
<td><strong>Threat Enrichment</strong></td>
<td>Dual GeoIP (src + dst), asset criticality lookup, 0–100 risk scoring across 6 factors, IOC extraction, ThreatLens enrichment pipeline.</td>
</tr>
<tr>
<td><strong>SOC Workflow</strong></td>
<td>Alert queue → investigate → assign → escalate → resolve. Timeline notes, bulk actions, related events, investigation checklist.</td>
</tr>
<tr>
<td><strong>RBAC</strong></td>
<td>6 roles (admin, soc_manager, detection_engineer, soc_l2, soc_l1, viewer). Database-driven permission matrix. Redis-cached auth. Full audit log.</td>
</tr>
<tr>
<td><strong>Real-time UI</strong></td>
<td>WebSocket push for alerts, live log tail, and notifications. Redis Pub/Sub for cross-process broadcast.</td>
</tr>
<tr>
<td><strong>Rule Builder</strong></td>
<td>Visual condition editor with live Sigma YAML preview, MITRE ATT&CK picker (~200 techniques), and a test-against-real-logs endpoint.</td>
</tr>
<tr>
<td><strong>Dashboard</strong></td>
<td>Alert trends, EPS gauge, MITRE coverage ring, MTTR, top targeted hosts, time-range selector, drill-through stat cards.</td>
</tr>
<tr>
<td><strong>Notifications</strong></td>
<td>Email (SMTP) and Slack (incoming webhook) for high/critical alerts. Configurable from the Settings UI.</td>
</tr>
</table>

---

## 🗂 Repository Structure

```
secops/
├── start.sh                      # Full-stack start script (installs deps + runs everything)
├── README.md                     # This file
├── ARCHITECTURE.md               # Deep-dive: detection engine, schema, Redis pipeline, RBAC
├── Guide.md                      # SPL syntax + detection rule authoring reference
├── sample-logs/                  # 15 log files, each triggering one detection rule
│
├── secops-backend/               # Node.js/Express API server
│   ├── start.sh                  # Backend-only start script
│   ├── README.md                 # Backend documentation
│   ├── src/
│   │   ├── index.ts              # Server entry point
│   │   ├── app.ts                # Express app + route mounting
│   │   ├── db/schema/            # Drizzle ORM table definitions (15 tables)
│   │   ├── lib/
│   │   │   ├── detection/        # Rule engine + 15 seeded rules
│   │   │   ├── parsers/          # 9 log format parsers
│   │   │   ├── search/           # SPL parser + query executor
│   │   │   ├── notification-service.ts  # Email + Slack delivery
│   │   │   ├── enrichment.ts     # GeoIP, asset lookup, risk scoring
│   │   │   └── scheduler.ts      # node-cron task runner
│   │   ├── modules/              # Feature modules (auth, alerts, rules, logs …)
│   │   ├── receivers/            # UDP + TCP syslog listener
│   │   └── workers/              # Redis Streams consumer group
│   └── scripts/                  # DB setup + seeding utilities
│
├── secops-frontend/              # React 19 + Vite SPA
│   ├── start.sh                  # Frontend-only start script
│   ├── README.md                 # Frontend documentation
│   └── src/
│       ├── pages/                # 15 application views
│       ├── components/           # UI components (Radix UI + Tailwind)
│       ├── lib/                  # API client, SPL helpers, MITRE taxonomy
│       └── store/                # Zustand auth + UI state
│
└── secops-forwarder/             # CLI log forwarder (Splunk UF–style)
    ├── start.sh                  # Forwarder start script
    ├── README.md                 # Forwarder documentation
    ├── conf/                     # inputs.conf, outputs.conf, props.conf
    └── src/                      # TypeScript CLI source
```

---

## 🚀 Quick Start

### Option A — Run Everything (recommended)

```bash
bash start.sh
```

The script automatically:
1. Checks for Node.js, Redis, and PostgreSQL
2. Installs npm dependencies for the backend and frontend
3. Applies the Drizzle database schema
4. Builds the backend
5. Starts the backend API on `:8080`
6. Starts the Vite dev server on `:5000`
7. Seeds 6 demo users and 15 detection rules on first run

Open **http://localhost:5000** and log in with `admin` / `Admin@SecOps1!`

---

### Option B — Run Components Independently

```bash
# Backend only
bash secops-backend/start.sh

# Frontend only (in a separate terminal)
bash secops-frontend/start.sh

# Log forwarder
bash secops-forwarder/start.sh
```

---

### Prerequisites

> **On Replit** — PostgreSQL and Redis are already provisioned. Just run `bash start.sh`.

For local development, install these first:

**Node.js 22**
```bash
# Ubuntu/Debian
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs

# macOS
brew install node@22
```

**PostgreSQL 15+**
```bash
# Ubuntu/Debian
sudo apt-get install -y postgresql
sudo systemctl start postgresql
sudo -u postgres psql -c "CREATE USER secops WITH PASSWORD 'secops_pass';"
sudo -u postgres psql -c "CREATE DATABASE secops OWNER secops;"

# macOS
brew install postgresql@15 && brew services start postgresql@15
psql postgres -c "CREATE USER secops WITH PASSWORD 'secops_pass'; CREATE DATABASE secops OWNER secops;"
```

**Redis 7**
```bash
# Ubuntu/Debian
sudo apt-get install -y redis-server

# macOS
brew install redis
```

---

## 🔑 Demo Credentials

Seeded automatically on first run — no SQL required.

| Username | Password | Role | Access Level |
|---|---|---|---|
| `admin` | `Admin@SecOps1!` | Administrator | Full access — users, roles, rules, settings |
| `morgan` | `Manager@1234!` | SOC Manager | Alert management, rule oversight, team coordination |
| `elena` | `Engineer@1234!` | Detection Engineer | Rule creation, threat hunting, log analysis |
| `alice` | `Analyst@1234!` | SOC L2 Analyst | Alert triage, investigation, escalation |
| `bob` | `Analyst@1234!` | SOC L1 Analyst | Alert view, basic triage, note-taking |
| `viewer` | `Viewer@1234!` | Read-Only Viewer | View all resources, no mutations |

---

## ⚙️ Configuration

The backend reads configuration from environment variables (or `secops-backend/.env` for local development). The start script creates `.env` automatically on first run.

| Variable | Required | Default | Description |
|---|---|---|---|
| `PORT` | Yes | `8080` | Backend HTTP port |
| `DATABASE_URL` | Yes | — | PostgreSQL connection string |
| `REDIS_URL` | No | `redis://localhost:6379` | Redis connection string |
| `JWT_SECRET` | Yes | — | Access token signing key (change before production) |
| `JWT_REFRESH_SECRET` | Yes | — | Refresh token signing key |
| `NODE_ENV` | No | `development` | `development` or `production` |
| `ENABLE_WORKER` | No | `false` | Enable inline Redis Streams worker |
| `ENABLE_SYSLOG` | No | `false` | Enable UDP/TCP syslog receiver |
| `SYSLOG_UDP_PORT` | No | `1514` | UDP syslog listen port |
| `SYSLOG_TCP_PORT` | No | `1514` | TCP syslog listen port |
| `LOG_LEVEL` | No | `info` | Pino log level (`debug`, `info`, `warn`, `error`) |
| `SMTP_PASSWORD` | No | — | SMTP password for email alerts (Replit Secret) |
| `SLACK_WEBHOOK_URL` | No | — | Slack incoming webhook URL (Replit Secret) |
| `THREATLENS_API_KEY` | No | — | ThreatLens enrichment API key (Replit Secret) |

---

## 📥 Ingest Sample Logs

The `sample-logs/` directory contains 15 files, each crafted to trigger one seeded detection rule.

```bash
# 1. Get an auth token
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"identifier":"admin","password":"Admin@SecOps1!"}' \
  | grep -o '"accessToken":"[^"]*' | cut -d'"' -f4)

# 2. Ingest a Windows EventLog sample (triggers PowerShell detection)
while IFS= read -r line; do
  curl -s -X POST http://localhost:8080/api/ingest-log \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"source\":\"windows_eventlog\",\"message\":$( \
        python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))' <<< "$line")}"
done < sample-logs/02-powershell-execution.jsonl

# 3. Ingest a syslog sample (triggers SSH brute-force detection)
curl -s -X POST "http://localhost:8080/api/ingest/raw?source=syslog" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{\"text\":\"$(cat sample-logs/04-ssh-brute-force.txt)\"}"
```

See [sample-logs/README.md](sample-logs/README.md) for the full ingest guide and rule-to-file mapping.

---

## 🔍 SPL Search Examples

Run these queries in the **Log Explorer** tab.

```spl
# All failed logins in the last hour
action=login_failure earliest=-1h

# PowerShell with suspicious encoding flags
process=powershell* AND (cmd=-enc OR cmd=-nop OR cmd=hidden)

# High-risk events from non-RFC-1918 sources
risk_score>=80 AND NOT src_ip=10.0.0.0/8

# DNS queries to suspicious TLDs
dns_query=*.xyz OR dns_query=*.tk OR dns_query=*.onion

# Count login failures by source IP
action=login_failure | stats count by src_ip | sort -count

# External successful logins
action=login_success AND NOT src_ip=10.0.0.0/8 AND NOT src_ip=192.168.0.0/16
```

See [Guide.md](Guide.md) for the complete SPL and detection rule authoring reference.

---

## 🌐 API Reference

All endpoints are mounted under `/api`. Authentication uses `Authorization: Bearer <token>`.

| Area | Key Endpoints |
|---|---|
| **Health** | `GET /healthz` |
| **Auth** | `POST /auth/login` · `POST /auth/refresh` · `POST /auth/logout` · `GET /auth/me` |
| **Profile** | `GET/PATCH /me` · `POST /me/password` · API key CRUD |
| **Alerts** | List · detail · investigate · assign · escalate · resolve · timeline · related events · bulk update |
| **Rules** | List · detail · create · update · delete · toggle · test · stats |
| **Logs** | Search (SPL) · filter metadata · facets · histogram · host context |
| **Ingest** | `POST /ingest-log` · `/ingest/bulk` · `/ingest/raw` · pending · reprocess |
| **Enrichment** | `GET /enrichment/ip/:ip` · `/enrichment/domain/:domain` · ThreatLens report |
| **Dashboard** | `GET /dashboard/stats` |
| **Assets** | Asset CRUD + hostname/IP lookup |
| **Settings** | `GET/PATCH /settings/system` · test-email · test-slack · ThreatLens connectivity |
| **Audit** | `GET /audit` — full activity log |
| **Notifications** | List · mark read · delete |

**WebSocket channels:** `ws://host/ws/alerts` · `ws://host/ws/events/live` · `ws://host/ws/notifications`

---

## 🏗 Tech Stack

| Layer | Technology |
|---|---|
| **Frontend** | React 19, TypeScript 5, Vite 7, TanStack React Query v5, Zustand, Radix UI, Recharts, Tailwind CSS v4 |
| **Backend** | Node.js 22, Express 5, TypeScript 5, Drizzle ORM, esbuild, Zod, Pino |
| **Database** | PostgreSQL 15+ |
| **Cache / Streams** | Redis 7 (Streams, Pub/Sub, auth cache, dashboard cache) |
| **Real-time** | WebSocket (`ws`), Redis Pub/Sub |
| **Auth** | JWT (access 15 min + refresh 7 days), bcrypt, express-rate-limit |
| **Email / Slack** | Nodemailer (SMTP), Slack Incoming Webhooks |

---

## 📚 Documentation

| Document | Description |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Detection engine internals, database schema, Redis pipeline, RBAC model, real-time streaming |
| [Guide.md](Guide.md) | SPL query syntax reference, detection rule YAML format, field modifier reference, examples |
| [secops-backend/README.md](secops-backend/README.md) | Backend setup, module map, API details, scripts reference |
| [secops-frontend/README.md](secops-frontend/README.md) | Frontend setup, page inventory, component guide, state management |
| [secops-forwarder/README.md](secops-forwarder/README.md) | Forwarder setup, configuration files, deployment guide |

---

## 📄 License

MIT — free to use, modify, and distribute.
