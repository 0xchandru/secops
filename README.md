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

[Live Demo](#local-development) · [Architecture](ARCHITECTURE.md) · [API Reference](#api-surface) · [Detection Rules](#detection-engine)

</div>

---

## What Is SecOps Console?

SecOps Console ingests raw security logs from any source, normalises them through a pluggable parser registry, enriches events with GeoIP and asset context, evaluates 15 pre-built MITRE-mapped detection rules through a custom correlation engine, and streams alerts into a real-time analyst UI — all in one cohesive, self-hosted application.

```
Raw Logs (syslog / Windows / CEF / CloudTrail…)
        │
        ▼
  Parser Registry  ──►  Normalised Event  ──►  Enrichment (GeoIP + Asset)
        │                                              │
        ▼                                              ▼
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
| **SPL-like Search** | Splunk-style query language with field aliases, comparison operators, wildcard matching, boolean logic, pipe operators, and free-text search |
| **Threat Enrichment** | Dual GeoIP (src + dst IP), asset criticality lookup, 0–100 risk scoring across 6 factors, IOC extraction, ThreatLens enrichment pipeline |
| **SOC Workflow** | Alert queue → investigate → assign → escalate → resolve; timeline notes; bulk actions; related events; investigation checklist |
| **RBAC** | 6 roles (admin, senior analyst, analyst, tier1, read-only viewer, auditor); database-driven permission matrix; Redis-cached auth context; audit log on every action |
| **Real-time** | WebSocket streams for alerts, live events, and notifications; Redis Pub/Sub for cross-process broadcast |
| **Rule Builder** | Visual condition editor with live Sigma YAML preview, MITRE ATT&CK picker (~200 techniques across 14 tactics), test endpoint |
| **Dashboard** | Alert trends, EPS gauge, MITRE coverage ring, MTTR, top targeted hosts, time-range selector, drill-through stat cards |
| **Scheduled SPL Alerts** | Save any SPL query as a recurring alert rule; scheduler runs every minute and fires alerts when threshold is crossed |

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
| Infra | Docker + Docker Compose, node-cron scheduler, optional syslog receiver |

---

## Repository Layout

```
secops/
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
│   │   ├── modules/            # Express route modules (auth, alerts, rules, …)
│   │   ├── receivers/          # UDP + TCP syslog receiver
│   │   └── workers/            # Redis Streams consumer group
│   └── scripts/                # DB setup + user seed scripts
├── secops-frontend/
│   ├── src/
│   │   ├── pages/              # 15 application views
│   │   ├── components/         # Layout, widgets, Radix UI wrappers
│   │   ├── lib/                # API client, SPL helpers, MITRE taxonomy
│   │   └── store/              # Zustand auth + UI state
├── sample-logs/                # Alert-triggering sample log files
├── docker-compose.yml
└── README.md
```

---

## Demo Credentials

> Seeded automatically on first startup — no manual SQL required.

| Username | Password | Role | Access |
|---|---|---|---|
| `admin` | `Admin@123` | Administrator | Full access — users, roles, rules, settings |
| `senior_analyst` | `Analyst@123` | Senior Analyst | Alerts, rules, escalation, user management |
| `analyst` | `Analyst@123` | Analyst | Alerts, rules, logs, enrichment |
| `tier1` | `Tier1@123` | Tier-1 SOC | Alert triage, view only for rules |
| `readonly` | `Readonly@123` | Read-Only | View everything, change nothing |
| `auditor` | `Auditor@123` | Auditor | Alerts + audit logs read |

---

## Local Development

### Prerequisites

- Node.js 22+
- PostgreSQL 15+
- Redis 7+
- (Optional) Docker + Docker Compose for infra

### 1 — Start infrastructure

```bash
docker compose up -d postgres redis
```

Exposes PostgreSQL on `localhost:5432` and Redis on `localhost:6379`.

### 2 — Configure the backend

```bash
cp secops-backend/.env.example secops-backend/.env
# Edit secops-backend/.env if needed (defaults work with docker compose)
```

Key variables:

```env
PORT=8080
DATABASE_URL=postgresql://secops:secops_pass@localhost:5432/secops
REDIS_URL=redis://localhost:6379
JWT_SECRET=replace-me
JWT_REFRESH_SECRET=replace-me-too
ENABLE_WORKER=true
ENABLE_SYSLOG=false
```

### 3 — Build and start the backend

```bash
cd secops-backend
npm install
npm run db:push        # applies schema via drizzle-kit
npm run build
npm run dev            # auto-seeds demo users on first start
```

Backend listens on `http://localhost:8080`.

### 4 — Start the frontend

```bash
cd secops-frontend
npm install
npm run dev            # Vite dev server on http://localhost:5173
```

The Vite proxy forwards `/api` and `/ws` to the backend automatically.

### 5 — Ingest sample logs

```bash
# Ingest a full syslog sample (triggers brute-force + lateral movement rules)
curl -X POST http://localhost:8080/api/ingest/raw?source=syslog \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <your_access_token>" \
  -d '{"text":"<paste contents of sample-logs/syslog-sample.txt>"}'
```

See [sample-logs/README.md](sample-logs/README.md) for the rule-to-file mapping.

---

## SPL Search Examples

The log explorer accepts plain text and SPL-style queries:

```
failed login
severity=critical OR severity=high
src_ip=10.0.0.5 AND action=login_failure
risk_score>=75
process=powershell* AND NOT user=svc*
dns_query=*malware*
src_country=RU AND action=login_success
```

Common field aliases: `src`, `src_ip`, `dst`, `dst_ip`, `host`, `user`, `process`, `cmd`, `risk`, `country`, `status_code`, `dns_query`.

---

## Detection Engine

Rules are stored as Sigma-compatible YAML. The engine evaluates every ingested event against enabled rules in real time.

```yaml
name: Suspicious PowerShell Execution
description: 'PowerShell with suspicious download or obfuscation patterns'
severity: high
type: simple
logsource:
  category: windows
  product: '*'
detection:
  selection:
    processCommandLine|contains|any:
      - "DownloadString"
      - "IEX"
      - "-EncodedCommand"
  condition: selection
mitre:
  tactic: Execution
  technique_id: T1059.001
```

### Rule Types

| Type | How It Works |
|---|---|
| `simple` | Single-event field match with modifiers |
| `threshold` | N events matching a field within a time window |
| `sequence` | Ordered multi-step correlation across events |
| `spl_saved_search` | Scheduled SPL query; fires when result count ≥ threshold |

### Field Modifiers

`contains` · `any` · `re` (regex) · `gt` · `gte` · `lt` · `lte` · `cidr` · `exists` · `not` · `startswith` · `endswith`

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

## Docker Deployment

```bash
docker compose up -d
```

`docker-compose.yml` runs: PostgreSQL · Redis · API server · Pipeline worker · Syslog receiver · Nginx-served frontend.

---

## Useful Commands

```bash
# Backend
cd secops-backend
npm run dev            # development with ts-node-dev
npm run build          # esbuild production bundle
npm run typecheck      # tsc --noEmit
npm run db:push        # push schema via drizzle-kit

# Frontend
cd secops-frontend
npm run dev            # Vite dev server
npm run build          # production bundle
npm run typecheck      # tsc --noEmit
```

---

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for a comprehensive breakdown of the detection engine internals, log parser registry, database schema, SOC workflow state machine, Redis pipeline design, RBAC model, and enrichment pipeline.

---

## License

MIT — see [LICENSE](LICENSE) for details.
