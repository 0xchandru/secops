# SecOps Console

<div align="center">

![SecOps Console](https://img.shields.io/badge/SecOps-Console-0f172a?style=for-the-badge&logo=shield&logoColor=22d3ee)
&nbsp;
![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178c6?style=for-the-badge&logo=typescript&logoColor=white)
&nbsp;
![React](https://img.shields.io/badge/React-19-61dafb?style=for-the-badge&logo=react&logoColor=black)
&nbsp;
![Node.js](https://img.shields.io/badge/Node.js-22-339933?style=for-the-badge&logo=nodedotjs&logoColor=white)
&nbsp;
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15+-336791?style=for-the-badge&logo=postgresql&logoColor=white)
&nbsp;
![Redis](https://img.shields.io/badge/Redis-7-dc382d?style=for-the-badge&logo=redis&logoColor=white)

**A production-grade mini-SIEM and SOC analyst workspace built for detection engineering, real-time triage, and security operations workflows.**

[Setup Guide](#local-setup) · [Architecture](ARCHITECTURE.md) · [SPL & Rule Guide](Guide.md) · [Sample Logs](sample-logs/)

</div>

---

## What Is SecOps Console?

SecOps Console ingests raw security logs from any source, normalises them through a pluggable parser registry, enriches events with GeoIP and asset context, evaluates 15 pre-built MITRE-mapped detection rules through a custom correlation engine, and streams alerts into a real-time analyst UI — all in one cohesive, self-hosted application.

```
Raw Logs (syslog / Windows / CEF / CloudTrail / DNS …)
        │
        ▼
  Parser Registry  ──►  Normalised Event  ──►  Enrichment (GeoIP + Asset + Risk Score)
        │                                                │
        ▼                                                ▼
  Redis Streams ──►  Detection Engine  ──►  Alert  ──►  WebSocket ──►  Analyst UI
```

---

## Feature Highlights

| Area | What's Built |
|---|---|
| **Log Ingestion** | HTTP single / bulk / raw-text endpoints + optional UDP/TCP syslog receiver on port 1514 |
| **Parser Registry** | 9 formats: Syslog (20+ programs), Windows EventLog (40+ EventIDs + Sysmon), Firewall, CEF, ECS JSON, LEEF, CloudTrail, DNS, generic — each extracting 50+ normalised fields |
| **Detection Engine** | `simple`, `threshold`, and `sequence` rule types; 12 field modifiers (`contains`, `any`, `gt`, `lt`, `cidr`, `exists`, `not`, `re`, `startswith`, `endswith`, `gte`, `lte`); pre-filter index; alert dedup; rule-level rate limiting |
| **Seeded Rules** | 15 production rules covering brute force, PowerShell abuse, lateral movement, Kerberoasting, credential dumping, DNS tunnelling, CloudTrail root usage, and more |
| **SPL Search** | Splunk-style query language with field aliases, comparison operators, wildcard matching, boolean logic, pipe operators, and free-text search |
| **Threat Enrichment** | Dual GeoIP (src + dst IP), asset criticality lookup, 0–100 risk scoring across 6 factors, IOC extraction, ThreatLens enrichment pipeline |
| **SOC Workflow** | Alert queue → investigate → assign → escalate → resolve; timeline notes; bulk actions; related events; investigation checklist |
| **RBAC** | 6 roles (admin, senior analyst, analyst, tier1, read-only, auditor); database-driven permission matrix; Redis-cached auth context; audit log on every action |
| **Real-time** | WebSocket streams for alerts, live events, and notifications; Redis Pub/Sub for cross-process broadcast |
| **Rule Builder** | Visual condition editor with live Sigma YAML preview, MITRE ATT&CK picker (~200 techniques), test endpoint |
| **Dashboard** | Alert trends, EPS gauge, MITRE coverage ring, MTTR, top targeted hosts, time-range selector, drill-through stat cards |
| **Scheduled SPL Alerts** | Save any SPL query as a recurring alert rule; scheduler evaluates every minute and fires when threshold is crossed |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React 19, TypeScript 5, Vite 7, TanStack React Query v5, Zustand, Radix UI, Recharts, Tailwind CSS v4 |
| Backend | Node.js 22, Express 5, TypeScript, Drizzle ORM, esbuild, Zod |
| Database | PostgreSQL 15+ |
| Cache / Streams | Redis 7 (Streams, Pub/Sub, cache) |
| Real-time | WebSocket (ws), Redis Pub/Sub |
| Auth | JWT access + refresh tokens, bcrypt, express-rate-limit |

---

## Repository Layout

```
secops/
├── start.sh                    # Unified start script (Replit + local)
├── Guide.md                    # SPL and Detection Rule authoring guide
├── README.md
├── ARCHITECTURE.md
├── sample-logs/                # 15 alert-triggering sample log files
├── secops-backend/
│   ├── src/
│   │   ├── db/schema/          # Drizzle ORM schema (15 tables)
│   │   ├── lib/
│   │   │   ├── parsers/        # 9 log format parsers
│   │   │   ├── detection/      # Engine + 15 seeded rules
│   │   │   ├── search/         # SPL parser + executor
│   │   │   ├── enrichment.ts   # GeoIP, asset, risk scoring
│   │   │   ├── scheduler.ts    # node-cron task runner
│   │   │   └── redis.ts        # Streams + Pub/Sub helpers
│   │   ├── modules/            # Express route modules (auth, alerts, rules …)
│   │   ├── receivers/          # UDP + TCP syslog receiver
│   │   └── workers/            # Redis Streams consumer group
│   └── scripts/                # DB setup + user seed scripts
└── secops-frontend/
    ├── src/
    │   ├── pages/              # 15 application views
    │   ├── components/         # Layout, widgets, Radix UI wrappers
    │   ├── lib/                # API client, SPL helpers, MITRE taxonomy
    │   └── store/              # Zustand auth + UI state
```

---

## Demo Credentials

> Seeded automatically on first startup — no manual SQL required.

| Username | Password | Role | Access |
|---|---|---|---|
| `admin` | `Admin@123` | Administrator | Full access — users, roles, rules, settings |
| `senior_analyst` | `Analyst@123` | Senior Analyst | Alerts, rules, escalation, user management |
| `analyst` | `Analyst@123` | Analyst | Alerts, rules, logs, enrichment |
| `tier1` (bob) | `Tier1@123` | Tier-1 SOC | Alert triage, view-only for rules |
| `readonly` | `Readonly@123` | Read-Only | View everything, change nothing |
| `auditor` | `Auditor@123` | Auditor | Alerts + audit logs read |

---

## Local Setup

### Prerequisites

Install these natively before running the start script:

**Node.js 22**
```bash
# Ubuntu / Debian
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs

# macOS (Homebrew)
brew install node@22

# Windows — download from https://nodejs.org
```

**PostgreSQL 15+**
```bash
# Ubuntu / Debian
sudo apt-get install -y postgresql
sudo systemctl start postgresql
sudo -u postgres psql -c "CREATE USER secops WITH PASSWORD 'secops_pass';"
sudo -u postgres psql -c "CREATE DATABASE secops OWNER secops;"

# macOS (Homebrew)
brew install postgresql@15
brew services start postgresql@15
psql postgres -c "CREATE USER secops WITH PASSWORD 'secops_pass'; CREATE DATABASE secops OWNER secops;"
```

**Redis 7**
```bash
# Ubuntu / Debian
sudo apt-get install -y redis-server

# macOS (Homebrew)
brew install redis
```

> **On Replit** — PostgreSQL and Redis are already provisioned. No setup required; just run `start.sh`.

---

### Run the application

```bash
# Clone / open the project, then:
bash start.sh
```

The script automatically:
1. Starts Redis (if not already running)
2. Creates `secops-backend/.env` with defaults if it doesn't exist
3. Installs npm dependencies (backend + frontend) if missing
4. Pushes the Drizzle schema to your database
5. Builds and starts the backend on `:8080`
6. Starts the Vite dev server (frontend) on `:5000`
7. Seeds 6 demo users and 15 detection rules on first run

Open `http://localhost:5000` and log in with `admin` / `Admin@123`.

---

### Configure the backend

`secops-backend/.env` is created automatically on first run. Edit it to change defaults:

```env
PORT=8080
NODE_ENV=development
DATABASE_URL=postgresql://secops:secops_pass@localhost:5432/secops
REDIS_URL=redis://localhost:6379
JWT_SECRET=replace-with-a-long-random-string
JWT_REFRESH_SECRET=replace-with-a-different-long-random-string
ENABLE_WORKER=true
ENABLE_SYSLOG=false
SYSLOG_UDP_PORT=1514
SYSLOG_TCP_PORT=1514
LOG_LEVEL=info
```

---

## Ingest Sample Logs

The `sample-logs/` directory contains 15 files, each crafted to trigger one of the seeded detection rules.

```bash
# Get a token
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin@123"}' \
  | grep -o '"accessToken":"[^"]*' | cut -d'"' -f4)

# Ingest a Windows EventLog sample (triggers PowerShell detection)
while IFS= read -r line; do
  curl -s -X POST http://localhost:8080/api/ingest-log \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"source\":\"windows_eventlog\",\"message\":$(python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))' <<< "$line")}"
done < sample-logs/02-powershell-execution.jsonl

# Ingest a syslog sample (triggers SSH brute-force detection)
curl -s -X POST "http://localhost:8080/api/ingest/raw?source=syslog" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{\"text\":\"$(cat sample-logs/04-ssh-brute-force.txt)\"}"
```

See [sample-logs/README.md](sample-logs/README.md) for the full ingest guide and rule-to-file mapping.

---

## SPL Search Examples

See [Guide.md](Guide.md) for the complete SPL and detection rule authoring reference.

```
# Failed logins from external IPs
action=login_failure AND NOT src_ip=10.0.0.0/8

# PowerShell with suspicious flags
process=powershell* AND cmd=-enc

# High-risk events
risk_score>=80

# DNS queries to suspicious TLDs
dns_query=*.xyz OR dns_query=*.tk

# Count login failures by source IP
action=login_failure | stats count by src_ip | sort -count
```

---

## API Surface

All endpoints are mounted under `/api`.

| Area | Endpoints |
|---|---|
| Health | `GET /healthz` |
| Auth | `POST /auth/login` · `POST /auth/refresh` · `POST /auth/logout` · `GET /auth/me` |
| Profile | `GET/PATCH /me` · `POST /me/password` · API key CRUD |
| Alerts | List · detail · investigate · assign · escalate · resolve · timeline notes · related events · bulk update |
| Rules | List · detail · create · update · delete · toggle · test · stats |
| Logs | Search · filter metadata · facets · histogram · host context |
| Ingest | `POST /ingest-log` · `/ingest/bulk` · `/ingest/raw` · pending · reprocess |
| Enrichment | `GET /enrichment/ip/:ip` · `/enrichment/domain/:domain` · ThreatLens report |
| Dashboard | `GET /dashboard/stats` |
| Assets | Asset CRUD + hostname/IP lookup |
| Audit | `GET /audit` |
| Notifications | List · mark read · delete |

WebSocket channels: `/ws/alerts` · `/ws/events/live` · `/ws/notifications`

---

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `PORT` | Yes | `8080` | Backend HTTP port |
| `DATABASE_URL` | Yes | — | PostgreSQL connection string |
| `REDIS_URL` | No | `redis://localhost:6379` | Redis connection string |
| `JWT_SECRET` | Yes | — | Access token signing key |
| `JWT_REFRESH_SECRET` | Yes | — | Refresh token signing key |
| `NODE_ENV` | No | `development` | `development` or `production` |
| `ENABLE_WORKER` | No | `false` | Start inline Redis Streams worker |
| `ENABLE_SYSLOG` | No | `false` | Start UDP/TCP syslog receiver |
| `SYSLOG_UDP_PORT` | No | `1514` | UDP syslog port |
| `SYSLOG_TCP_PORT` | No | `1514` | TCP syslog port |
| `LOG_LEVEL` | No | `info` | Pino log level |

---

## Useful Commands

```bash
# Start everything (first time or after changes)
bash start.sh

# Backend only
cd secops-backend
npm run dev          # ts-node-dev hot-reload
npm run build        # production esbuild bundle
npm run typecheck    # tsc --noEmit
npm run db:push      # apply schema changes

# Frontend only
cd secops-frontend
npm run dev          # Vite dev server
npm run build        # production bundle
npm run typecheck    # tsc --noEmit
```

---

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for a comprehensive breakdown of the detection engine internals, log parser registry, database schema, SOC workflow state machine, Redis pipeline design, RBAC model, and enrichment pipeline.

---

## Learning Resources

See [Guide.md](Guide.md) for:
- Complete SPL query syntax reference with copy-paste examples
- Detection rule YAML format and all supported options
- Rule type walkthroughs (simple / threshold / sequence / SPL)
- Field modifier reference
- 6 detection rule examples from basic to advanced
- Full normalised field reference for building conditions

---

## License

MIT
