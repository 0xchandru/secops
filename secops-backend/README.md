<div align="center">

# SecOps Console — Backend

<img src="https://img.shields.io/badge/Node.js-22-339933?style=for-the-badge&logo=nodedotjs&logoColor=white" alt="Node.js"/>
&nbsp;
<img src="https://img.shields.io/badge/Express-5-000000?style=for-the-badge&logo=express&logoColor=white" alt="Express"/>
&nbsp;
<img src="https://img.shields.io/badge/TypeScript-5.x-3178c6?style=for-the-badge&logo=typescript&logoColor=white" alt="TypeScript"/>
&nbsp;
<img src="https://img.shields.io/badge/PostgreSQL-15+-336791?style=for-the-badge&logo=postgresql&logoColor=white" alt="PostgreSQL"/>
&nbsp;
<img src="https://img.shields.io/badge/Redis-7-dc382d?style=for-the-badge&logo=redis&logoColor=white" alt="Redis"/>

**The API server powering SecOps Console.**  
Detection engine · Log ingestion · Real-time WebSocket · SPL search · RBAC

</div>

---

## Contents

- [Quick Start](#quick-start)
- [Project Structure](#project-structure)
- [Environment Variables](#environment-variables)
- [NPM Scripts](#npm-scripts)
- [Module Map](#module-map)
- [Database Schema](#database-schema)
- [Detection Engine](#detection-engine)
- [API Endpoints](#api-endpoints)

---

## Quick Start

### Using the start script (recommended)

```bash
bash secops-backend/start.sh
```

This installs dependencies, applies the database schema, builds the TypeScript bundle, and starts the server.

### Manual steps

```bash
cd secops-backend

# 1. Install dependencies
npm install

# 2. Create .env (first time only)
cp .env.example .env   # then edit DATABASE_URL and JWT secrets

# 3. Apply database schema
npm run db:push

# 4. Build
npm run build

# 5. Start
npm run start
```

The server starts on **http://localhost:8080**.

---

## Project Structure

```
secops-backend/
├── start.sh                    # Backend-only start script
├── build.mjs                   # esbuild bundle script
├── drizzle.config.ts           # Drizzle ORM config
├── tsconfig.json
├── package.json
├── scripts/                    # One-time database utilities
│   ├── db-setup.ts             # Create tables + seed roles/permissions
│   ├── seed-users.ts           # Seed demo user accounts
│   ├── seed-detection-rules.ts # Seed the 15 production detection rules
│   └── seed-admin.ts           # Seed/reset admin account
└── src/
    ├── index.ts                # Entry point: HTTP server + startup hooks
    ├── app.ts                  # Express app configuration + route mounting
    ├── db/
    │   ├── index.ts            # Drizzle client (exported as `db`)
    │   └── schema/             # One file per table (15 tables)
    ├── lib/
    │   ├── detection/          # Detection engine + pre-filter + seeded rules
    │   ├── parsers/            # 9 log format parsers
    │   ├── search/             # SPL parser (AST) + PostgreSQL executor
    │   ├── enrichment.ts       # GeoIP, asset lookup, risk scoring
    │   ├── notification-service.ts  # Email (nodemailer) + Slack webhooks
    │   ├── replit-secrets.ts   # Persistent secret store (Replit DB)
    │   ├── scheduler.ts        # node-cron task definitions
    │   ├── redis.ts            # Redis client + Streams + Pub/Sub helpers
    │   ├── websocket.ts        # WebSocket server + channel management
    │   ├── audit.ts            # Audit log writer
    │   └── logger.ts           # Pino logger instance
    ├── middlewares/
    │   ├── auth.middleware.ts  # JWT verification + user hydration
    │   └── rbac.middleware.ts  # Permission check (`can(resource, action)`)
    ├── modules/                # Feature-specific Express routers
    │   ├── auth/
    │   ├── alerts/
    │   ├── rules/
    │   ├── logs/
    │   ├── ingest/
    │   ├── enrichment/
    │   ├── dashboard/
    │   ├── assets/
    │   ├── users/
    │   ├── audit/
    │   ├── notifications/
    │   └── settings/
    ├── receivers/
    │   └── syslog-server.ts    # UDP + TCP syslog listener (port 1514)
    └── workers/
        └── pipeline-worker.ts  # Redis Streams consumer group
```

---

## Environment Variables

Create `secops-backend/.env` (the start script creates it automatically on first run):

```env
# Server
PORT=8080
NODE_ENV=development
LOG_LEVEL=info

# Database
DATABASE_URL=postgresql://secops:secops_pass@localhost:5432/secops

# Redis
REDIS_URL=redis://localhost:6379

# Auth (change before production)
JWT_SECRET=replace-with-a-long-random-string
JWT_REFRESH_SECRET=replace-with-a-different-long-random-string

# Workers
ENABLE_WORKER=true       # Start Redis Streams consumer inline
ENABLE_SYSLOG=false      # Start UDP/TCP syslog listener
SYSLOG_UDP_PORT=1514
SYSLOG_TCP_PORT=1514
```

**Secrets** (set via Replit Secrets or environment — never stored in `.env` plaintext):

| Secret | Description |
|---|---|
| `SMTP_PASSWORD` | SMTP password for email alert delivery |
| `SLACK_WEBHOOK_URL` | Slack incoming webhook URL |
| `THREATLENS_API_KEY` | ThreatLens enrichment service API key |

---

## NPM Scripts

| Script | Description |
|---|---|
| `npm run build` | Bundle TypeScript → `dist/index.mjs` with esbuild |
| `npm run start` | Start the compiled bundle (requires `.env`) |
| `npm run dev` | Start in dev mode (compiled bundle, no hot-reload) |
| `npm run typecheck` | Run `tsc --noEmit` type check |
| `npm run db:push` | Apply Drizzle schema to the database |
| `npm run db:push-force` | Force-push schema (drops conflicting columns) |
| `npm run seed:users` | Seed the 6 demo user accounts |
| `npm run seed:rules` | Seed the 15 detection rules |
| `npm run setup` | Run `db:setup` + `seed:users` in sequence |

---

## Module Map

| Module | Router prefix | Key responsibilities |
|---|---|---|
| `auth` | `/api/auth` | Login, refresh token, logout, `GET /me` |
| `me` | `/api/me` | Profile CRUD, password change, API key management |
| `alerts` | `/api/alerts` | Alert lifecycle, assignment, escalation, timeline |
| `rules` | `/api/rules` | Detection rule CRUD, toggle, test, stats |
| `logs` | `/api/logs` | SPL search, facets, histogram, host context |
| `ingest` | `/api/ingest` | Single/bulk/raw log ingestion endpoints |
| `enrichment` | `/api/enrichment` | IP/domain lookup, ThreatLens panel |
| `dashboard` | `/api/dashboard` | Pre-computed SOC stats aggregates |
| `assets` | `/api/assets` | Asset CRUD + criticality lookup |
| `users` | `/api/users` | User management (admin only) |
| `audit` | `/api/audit` | Audit log read (admin/auditor) |
| `notifications` | `/api/notifications` | In-app notification management |
| `settings` | `/api/settings` | System config: email, Slack, ThreatLens |

---

## Database Schema

The backend uses **Drizzle ORM** with PostgreSQL. Schemas live in `src/db/schema/`.

| Table | Purpose |
|---|---|
| `users` | User accounts + password hashes |
| `roles` | Role definitions (admin, soc_manager, …) |
| `permissions` | Permission records (resource + action pairs) |
| `role_permissions` | Many-to-many: roles ↔ permissions |
| `user_roles` | Many-to-many: users ↔ roles |
| `raw_logs` | All ingested log events (80+ normalised fields) |
| `rules` | Detection rules (YAML + metadata) |
| `alerts` | Generated alerts with status and assignments |
| `alert_timeline` | Timeline notes and state-change events |
| `alert_state_transitions` | Immutable audit trail for alert status changes |
| `escalation_history` | Escalation records with reason text |
| `assets` | Asset inventory with criticality levels |
| `audit_logs` | Full system audit trail (every action) |
| `notifications` | In-app notification messages |
| `api_keys` | Hashed API keys for programmatic access |
| `system_settings` | Key-value config store (non-sensitive values) |

---

## Detection Engine

Located in `src/lib/detection/`. The engine:

1. **Pre-filters** events against a hash index keyed by field names — rules that cannot possibly match are skipped.
2. **Routes** each event to applicable rules by type:
   - `simple` — evaluates field conditions with modifiers
   - `threshold` — maintains a sliding-window counter per group field
   - `sequence` — tracks ordered step completion within a time window
3. **Creates alerts** in PostgreSQL and broadcasts via Redis Pub/Sub → WebSocket.
4. **Deduplicates** using a per-rule Redis key with a configurable TTL.
5. **Rate-limits** using a per-rule counter capped per minute.

---

## API Endpoints

### Authentication

```
POST   /api/auth/login            Body: { identifier, password }
POST   /api/auth/refresh          Body: { refreshToken }
POST   /api/auth/logout
GET    /api/auth/me
```

### Alerts

```
GET    /api/alerts                 Query: status, severity, page, limit, search
GET    /api/alerts/:id
POST   /api/alerts/:id/status      Body: { status, resolutionNotes? }
POST   /api/alerts/:id/assign      Body: { assignedTo }
POST   /api/alerts/:id/escalate    Body: { escalateTo, reason }
GET    /api/alerts/:id/timeline
POST   /api/alerts/:id/notes       Body: { content, type? }
GET    /api/alerts/:id/related
POST   /api/alerts/bulk            Body: { ids, status }
```

### Log Ingestion

```
POST   /api/ingest-log             Body: { source, message, ... }
POST   /api/ingest/bulk            Body: { logs: [...] }
POST   /api/ingest/raw?source=X    Body: { text }
```

### SPL Search

```
GET    /api/logs/search?q=<spl>&from=<ts>&to=<ts>&limit=<n>
GET    /api/logs/facets
GET    /api/logs/histogram
GET    /api/logs/hosts/:hostname
```

### Rules

```
GET    /api/rules
GET    /api/rules/:id
POST   /api/rules
PUT    /api/rules/:id
DELETE /api/rules/:id
POST   /api/rules/:id/toggle
POST   /api/rules/:id/test
GET    /api/rules/:id/stats
```

### Settings

```
GET    /api/settings/system
PATCH  /api/settings/system
POST   /api/settings/notifications/test-email
POST   /api/settings/notifications/test-slack
GET    /api/settings/integrations/threatlens
POST   /api/settings/integrations/threatlens/test
```

### Other

```
GET    /healthz
GET    /api/dashboard/stats
GET    /api/enrichment/ip/:ip
GET    /api/enrichment/domain/:domain
GET    /api/assets
GET    /api/audit
GET    /api/notifications
```

### WebSocket Channels

```
ws://host/ws/alerts          → { type: "new_alert", data: AlertSummary }
ws://host/ws/events/live     → { type: "raw_log", data: ParsedEvent }
ws://host/ws/notifications   → { type: "notification", data: Notification }
```
