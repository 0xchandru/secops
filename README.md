# SecOps Console — Mini-SIEM with Detection Engine

> A full-stack Security Operations Center platform with real-time detection engine, built as a production-grade portfolio project.

## Stack

- **Frontend:** React 19 · TypeScript · Vite 7 · TanStack React Query · Zustand · Recharts · Radix UI
- **Backend:** Node.js 22 · Express 5 · TypeScript · Drizzle ORM · esbuild
- **Database:** PostgreSQL 18 · Redis 7 (Streams, Pub/Sub, Cache)

## Key Features

### Detection & Ingestion
- 7 production-grade log parsers (Syslog, Windows EventLog, CEF, ECS JSON, LEEF, CloudTrail, Firewall) with auto-detection registry
- Custom detection engine: simple, threshold, and sequence rule types with 12+ field modifiers
- 15 seeded detection rules covering 9 MITRE ATT&CK techniques
- Redis Streams pipeline with consumer groups, batch processing, and dead letter queue
- Dual GeoIP enrichment (src + dst), asset criticality cache, risk scoring (0–100, 6 factors)
- SPL-like search engine with 50+ field aliases and boolean logic

### SOC Analyst Workflow
- **Dashboard** — Time-range selector (1h/6h/24h/7d/30d), drill-through stat cards, MITRE ATT&CK coverage ring widget
- **Alert Queue** — Date range filter, group-by toggle (rule/MITRE), severity badges, bulk actions
- **Alert Detail** — Status machine (new → investigating → escalated → resolved/false_positive), persistent investigation checklist, IOC extraction panel (IP/Domain/Hash), timeline annotations, related events
- **Detection Rules** — Severity filter, searchable tactic-grouped MITRE technique picker, YAML preview, test endpoint
- **Rule Builder** — Full MITRE ATT&CK taxonomy (~60 techniques across 14 tactics), visual condition editor, edit mode
- **MITRE ATT&CK** — Heatmap with deduplicated rule coverage, tactic/technique drill-down
- **Log Explorer** — Time range filter, customizable column picker (localStorage), CSV export, histogram, live tail
- **Audit Logs** — React Query, action/user/status/date filters, CSV export
- **Assets** — CRUD inventory, criticality filter, CSV export, tag management
- **Settings** — Profile, notifications, security (password strength meter), API key management
- **User Management** — 6 RBAC roles (admin → viewer), 15 granular permissions, role assignment

### Infrastructure
- RBAC middleware with 6 roles and 15 permissions
- JWT auth with refresh tokens
- WebSocket real-time streaming (alerts + events) via Redis Pub/Sub
- Scheduled jobs: rule reload, asset cache, dashboard cache, stream cleanup, data retention
- Full audit logging on every system action

## Quick Start

```bash
# Install dependencies
pnpm install

# Frontend dev
cd secops-frontend && npx vite dev

# Backend build + run
cd secops-backend && node ./build.mjs
# Set environment variables then:
node --enable-source-maps dist/index.mjs
```

## Environment Variables

| Variable | Default |
|----------|---------|
| `DATABASE_URL` | `postgresql://secops:...@localhost:5432/secops` |
| `REDIS_URL` | `redis://localhost:6379` |
| `PORT` | `8080` |
| `JWT_SECRET` | — |
| `JWT_REFRESH_SECRET` | — |
| `NODE_ENV` | `development` |

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for full system design, database schema, detection engine internals, and development roadmap.