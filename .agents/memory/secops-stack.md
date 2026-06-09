---
name: SecOps Stack
description: Core tech stack and architecture for the SecOps Console SIEM/SOC platform
---

Frontend: React 19 + Vite 7 + Tailwind CSS v4 + Radix UI primitives, wouter routing, Zustand auth store, TanStack Query v5.
Backend: Express 5, Drizzle ORM, PostgreSQL via `DATABASE_URL`, Redis (optional, graceful fallback), Pino logger.
Start script: `bash start.sh` — starts Redis, builds backend with esbuild, starts backend on :8080, starts Vite frontend on :5000.
Key frontend paths: `secops-frontend/src/pages/`, `secops-frontend/src/components/layout/MainLayout.tsx`, `secops-frontend/src/lib/api.ts`.
Demo credentials: admin/Admin@SecOps1!, morgan/Manager@1234!, elena/Engineer@1234!, bob/Analyst@1234!, alice/Analyst@1234!, viewer/Viewer@1234!

**Why:** Replit environment with PostgreSQL provisioned, Redis via Nix. Vite config has `allowedHosts: true` for the proxied preview pane.
