# SecOps Console

SecOps Console is a full-stack mini-SIEM and SOC analyst workspace. It ingests security logs, normalizes them through a parser registry, enriches events with asset and GeoIP context, evaluates custom detection rules, and streams alerts into a real-time triage UI.

The project is designed as a production-grade security engineering portfolio: it demonstrates log ingestion, detection engineering, alert lifecycle management, RBAC, auditability, and analyst-facing investigation workflows in one cohesive application.

## Highlights

- Real-time log ingestion through HTTP endpoints and optional syslog receiver
- Parser registry for Syslog, Windows EventLog, Firewall, CEF, ECS JSON, LEEF, CloudTrail, DNS, VPC Flow, and Apache/Nginx-style web logs
- Custom detection engine with simple, threshold, and sequence rules
- 15 seeded MITRE-mapped detection rules for brute force, PowerShell abuse, PsExec-style lateral movement, Kerberoasting, credential dumping, suspicious DNS, CloudTrail root usage, and related scenarios
- Redis Streams pipeline with consumer groups, batch processing, retries, and dead-letter handling
- Event enrichment with source/destination GeoIP, asset criticality, and 0-100 risk scoring
- SPL-like log search with field aliases, comparison operators, wildcard matching, boolean logic, and free-text search
- SOC workflow for alert queueing, assignment, investigation, escalation, resolution, related events, timeline notes, and bulk updates
- Database-backed RBAC model with roles, permissions, user-role assignments, effective priority, and cached authorization context
- Audit logging for security-relevant actions
- React analyst console with dashboard, alerts, log explorer, rule builder, MITRE view, assets, audit logs, users, settings, and notifications

## Tech Stack

| Layer | Technology |
| --- | --- |
| Frontend | React 19, TypeScript, Vite 7, TanStack React Query, Zustand, Radix UI, Recharts, Tailwind CSS |
| Backend | Node.js 22, Express 5, TypeScript, Drizzle ORM, esbuild, Zod |
| Data | PostgreSQL, Redis 7 |
| Realtime | WebSocket, Redis Pub/Sub |
| Pipeline | Redis Streams, background worker, syslog receiver |
| Security | JWT access/refresh tokens, bcrypt, RBAC middleware, audit log |
| Packaging | Dockerfiles and Docker Compose topology |

## Architecture

```text
React/Vite Analyst Console
  | HTTP /api
  | WebSocket /ws/alerts, /ws/events/live, /ws/notifications
  v
Express API Server
  | Auth, RBAC, routes, audit logging
  | Parser registry
  | Enrichment
  | Detection engine
  v
PostgreSQL
  | users, roles, permissions, rules, raw_logs, alerts, assets, audit_logs, notifications

Redis
  | Streams: async log pipeline
  | Pub/Sub: cross-process alert and event broadcast
  | Cache: permissions, assets, dashboard data

Optional Runtime Processes
  | Pipeline worker
  | UDP/TCP syslog receiver on 1514
```

The deeper design notes, rule DSL, parser internals, database model, SOC workflow, and roadmap are documented in [ARCHITECTURE.md](ARCHITECTURE.md).

## Repository Structure

```text
.
|-- ARCHITECTURE.md              # Detailed architecture and roadmap
|-- README.md                    # Project overview and setup
|-- docker-compose.yml           # Production-style service topology
|-- sample-logs/                 # Alert-generating sample logs
|-- secops-backend/              # Express API, pipeline, parsers, detection engine
|   |-- src/db/schema/           # Drizzle schema
|   |-- src/lib/parsers/         # Log parser plugins
|   |-- src/lib/detection/       # Detection engine and seed rules
|   |-- src/modules/             # API modules
|   |-- src/receivers/           # Syslog receiver
|   `-- src/workers/             # Redis Streams worker
`-- secops-frontend/             # React analyst console
    |-- src/pages/               # Application views
    |-- src/components/          # Layout, widgets, UI components
    |-- src/hooks/               # WebSocket and UI hooks
    |-- src/lib/                 # API client, types, utilities
    `-- src/store/               # Client state
```

## Core Capabilities

### Log Ingestion and Normalization

The backend accepts logs through:

- `POST /api/ingest-log` for a single structured/raw event
- `POST /api/ingest/bulk` for batch ingestion
- `POST /api/ingest/raw` for pasted or piped raw text
- Optional UDP/TCP syslog receiver on port `1514`

Logs are normalized into a broad event model covering network, host, user, process, HTTP, DNS, file, registry, vendor, syslog, enrichment, and timestamp fields.

### Detection Engine

Rules support:

- `simple` one-event matching
- `threshold` sliding-window counts by a chosen field
- `sequence` ordered multi-step correlation
- Field modifiers such as `contains`, `any`, `re`, `gt`, `gte`, `lt`, `lte`, `cidr`, `exists`, and `not`
- Alert deduplication and rule-level rate limiting
- MITRE ATT&CK mapping and alert context templates

Example rule shape:

```yaml
name: Suspicious PowerShell Execution
description: PowerShell with suspicious download or obfuscation patterns
severity: high
type: simple
match:
  processCommandLine|contains|any:
    - "DownloadString"
    - "IEX"
    - "-EncodedCommand"
mitre:
  tactic: Execution
  technique_id: T1059.001
  technique_name: "Command and Scripting Interpreter: PowerShell"
alert:
  title_template: "Suspicious PowerShell on {sourceHost} by {userName}"
  context_fields: [processCommandLine, userName, sourceHost]
tags: [powershell, execution]
```

### Analyst Workflow

The frontend provides:

- Dashboard with alert counts, trends, EPS, MITRE coverage, MTTR, and top targeted hosts
- Alert queue with filtering, grouping, assignment, bulk actions, and live updates
- Alert detail with timeline, status transitions, escalation, related events, IOC extraction, and investigation checklist
- Log explorer with SPL-like search, filters, facets, histogram, customizable columns, CSV export, and live tail
- Detection rules and rule builder with YAML preview, MITRE picker, test endpoint, and enable/disable flow
- MITRE ATT&CK heatmap for rule coverage
- Assets, audit logs, users, roles, settings, notifications, and API key screens

### Security and Governance

- JWT access tokens and refresh tokens
- Password hashing with bcrypt
- Login rate limiting and failed-attempt lockout
- Legacy role checks plus database-driven permissions
- Multi-role assignment with effective priority
- Redis-cached authorization context
- Alert state transition history and escalation tracking
- Audit logs for auth, alert, rule, user, role, settings, and API key activity

## Prerequisites

- Node.js 22+
- npm 10+
- PostgreSQL 15+ recommended
- Redis 7+
- Docker and Docker Compose, optional but useful for local infrastructure

There is no root package manifest. Install backend and frontend dependencies separately.

## Local Development

### 1. Start PostgreSQL and Redis

You can use the Compose file for infrastructure only:

```bash
docker compose up -d postgres redis
```

This exposes PostgreSQL on `localhost:5432` and Redis on `localhost:6379` using the defaults from `.env.example`.

### 2. Configure the backend

Create `secops-backend/.env`:

```bash
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
```

Install dependencies, create/update the schema, build, and start:

```bash
cd secops-backend
npm install
DATABASE_URL=postgresql://secops:secops_pass@localhost:5432/secops npm run db:push
npm run build
npm run dev
```

The backend listens on `http://localhost:8080`.

### 3. Start the frontend

In a second terminal:

```bash
cd secops-frontend
npm install
npm run dev
```

The frontend listens on `http://localhost:5173` and proxies `/api` plus `/ws` to the backend.

### 4. Create the first user

The API protects user creation behind admin authorization, so a fresh database needs an initial user seed before login. The backend `package.json` contains seed script names, but the corresponding `secops-backend/scripts/` directory is not present in this checkout.

Use your preferred database seed workflow to insert the first admin user, or restore the seed scripts before running:

```bash
npm run seed:roles
npm run seed:admin
```

After login, use the User Management and Roles screens to create additional users and assign permissions.

## Useful Commands

Backend:

```bash
cd secops-backend
npm run build
npm run dev
npm run start
npm run typecheck
npm run db:push
```

Frontend:

```bash
cd secops-frontend
npm run dev
npm run build
npm run preview
npm run typecheck
```

Infrastructure:

```bash
docker compose up -d postgres redis
docker compose logs -f postgres redis
docker compose down
```

## API Surface

All REST endpoints are mounted under `/api`.

| Area | Endpoints |
| --- | --- |
| Health | `GET /healthz` |
| Auth | `POST /auth/login`, `POST /auth/refresh`, `POST /auth/logout`, `GET /auth/me` |
| Profile | `GET/PATCH /me`, `POST /me/password`, `GET/PATCH /me/settings`, API key CRUD |
| Users | User CRUD, password reset, escalation targets, user-role assignment |
| Roles | Role CRUD, permission catalog, role permission assignment |
| Alerts | List/detail, investigate, status update, assign, escalate, timeline notes, related events, bulk update, action endpoints |
| Rules | List/detail, create, update, delete, toggle, test, stats |
| Logs | Search logs, filter metadata, facets, event histogram, host context |
| Ingest | Single, bulk, raw text, pending, stats, reprocess, manual detections |
| Dashboard | `GET /dashboard/stats` |
| Assets | Asset CRUD and hostname/IP lookup |
| Audit | `GET /audit` |
| Notifications | List, mark read, mark all read, delete |

WebSocket endpoints:

| Channel | Path |
| --- | --- |
| Alerts | `/ws/alerts` |
| Live events | `/ws/events/live` |
| Notifications | `/ws/notifications` |

## Sample Logs

The [sample-logs](sample-logs) directory contains raw events for exercising detections across Windows EventLog, syslog, firewall, DNS, VPC Flow, and CloudTrail formats.

Example raw ingest:

```bash
curl -X POST "http://localhost:8080/api/ingest/raw?source=syslog" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access_token>" \
  -d '{"text":"<paste log file contents here>"}'
```

Example bulk ingest:

```bash
curl -X POST "http://localhost:8080/api/ingest/bulk" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access_token>" \
  -d '{"logs":[{"source":"windows_eventlog","message":"<raw event>"}]}'
```

Threshold and sequence rules require enough events, in the right order, to cross the configured window. See [sample-logs/README.md](sample-logs/README.md) for the rule-to-file mapping.

## Search Examples

The log explorer accepts plain text and SPL-like queries:

```text
failed login
severity=critical OR severity=high
src_ip=10.0.0.5 AND action=login_failure
risk_score>=75
process=powershell* AND NOT user=svc*
dns_query=*malware*
```

Common aliases include `src`, `src_ip`, `dst`, `dst_ip`, `host`, `user`, `process`, `cmd`, `risk`, `country`, `status_code`, and `dns_query`.

## Environment Variables

| Variable | Required | Description |
| --- | --- | --- |
| `PORT` | Yes | Backend HTTP port |
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `REDIS_URL` | No | Redis connection string, defaults to `redis://localhost:6379` |
| `JWT_SECRET` | Yes | Access token signing secret |
| `JWT_REFRESH_SECRET` | Yes | Refresh token signing secret |
| `NODE_ENV` | No | `development` or `production` |
| `ENABLE_WORKER` | No | Start inline Redis Streams worker when `true` |
| `ENABLE_SYSLOG` | No | Start UDP/TCP syslog receiver when `true` |
| `SYSLOG_UDP_PORT` | No | UDP syslog port, defaults to `1514` |
| `SYSLOG_TCP_PORT` | No | TCP syslog port, defaults to `1514` |
| `LOG_LEVEL` | No | Pino log level |

The root `.env.example` is Docker-oriented. For local backend development, prefer `secops-backend/.env` with `localhost` database and Redis hosts.

## Docker Topology

`docker-compose.yml` defines:

- PostgreSQL
- Redis
- API server
- Pipeline worker
- Syslog receiver
- Nginx-served frontend

The Compose topology is useful as a deployment reference. In this checkout, the backend Dockerfile references a `scripts/` directory that is not committed, so validate the Docker build after restoring or removing that copy step.

## Database Overview

Primary tables:

- `users`, `roles`, `permissions`, `role_permissions`, `user_roles`
- `raw_logs`
- `rules`
- `alerts`, `alert_timeline`, `alert_state_transitions`, `escalation_history`
- `assets`
- `audit_logs`
- `notifications`
- `api_keys`
- `incidents`

`raw_logs` is the central event table and includes indexes on timestamp, severity, category, source, source/destination IP, hostname, username, event type, action, and processed state.

## Current Roadmap

Implemented foundation:

- Parser registry and normalized event model
- Detection engine with three rule types
- Seeded detection rules
- Enrichment and risk scoring
- SPL-like log search
- Alert lifecycle workflow
- RBAC, audit logging, notifications, assets, dashboard, and analyst UI

High-value next steps:

- Threat intelligence enrichment for IPs, domains, hashes, and URLs
- Playbook/SOP rendering from rule YAML
- SLA timers and shift handoff reports
- Incident workflow on top of grouped alerts
- Parser health metrics
- Sigma conversion service using Python and pySigma
- UEBA/anomaly detection service using Python analytics

## Project Status Notes

- `ARCHITECTURE.md` is both architecture documentation and roadmap. Some sections describe target-state features that are not yet implemented.
- The current backend seeds detection rules automatically on startup, but initial user/role seed scripts referenced by `package.json` are not present in this checkout.
- `sample-logs/README.md` mentions a few web log samples that are not currently present in the directory.
- API key storage exists and keys can be created from the profile area; scope enforcement should be completed before treating API keys as a production integration boundary.

## License

No license file is currently included. Add a license before publishing or accepting external contributions.
