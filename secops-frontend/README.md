<div align="center">

# SecOps Console — Frontend

<img src="https://img.shields.io/badge/React-19-61dafb?style=for-the-badge&logo=react&logoColor=black" alt="React"/>
&nbsp;
<img src="https://img.shields.io/badge/TypeScript-5.x-3178c6?style=for-the-badge&logo=typescript&logoColor=white" alt="TypeScript"/>
&nbsp;
<img src="https://img.shields.io/badge/Vite-7-646cff?style=for-the-badge&logo=vite&logoColor=white" alt="Vite"/>
&nbsp;
<img src="https://img.shields.io/badge/Tailwind_CSS-4-06b6d4?style=for-the-badge&logo=tailwindcss&logoColor=white" alt="Tailwind CSS"/>

**The analyst UI for SecOps Console.**  
Real-time alert queue · Log Explorer · Rule Builder · MITRE Heatmap · SOC dashboards

</div>

---

## Contents

- [Quick Start](#quick-start)
- [Project Structure](#project-structure)
- [Pages & Views](#pages--views)
- [State Management](#state-management)
- [API Client](#api-client)
- [Component Library](#component-library)
- [Development](#development)

---

## Quick Start

### Using the start script (recommended)

```bash
bash secops-frontend/start.sh
```

This installs all dependencies and starts the Vite dev server on `:5000`.

> **The backend must be running on `:8080`** for the UI to work.  
> Start the full stack with `bash start.sh` from the project root.

### Manual setup

```bash
cd secops-frontend
npm install
npm run dev
```

Open **http://localhost:5000**.

---

## Project Structure

```
secops-frontend/
├── start.sh                    # Frontend-only start script
├── README.md                   # This file
├── vite.config.ts              # Vite configuration (proxy to :8080, host binding)
├── tsconfig.json
├── package.json
├── components.json             # shadcn/ui registry config
└── src/
    ├── main.tsx                # React 19 entry point (createRoot)
    ├── App.tsx                 # Root component: router + query client + auth guard
    ├── index.css               # Tailwind CSS v4 entry + design tokens
    │
    ├── pages/                  # Full-page views (one file per route)
    │   ├── DashboardPage.tsx
    │   ├── AlertQueuePage.tsx
    │   ├── AlertDetailPage.tsx
    │   ├── LogExplorerPage.tsx
    │   ├── RuleBuilderPage.tsx
    │   ├── RuleDetailPage.tsx
    │   ├── MitreHeatmapPage.tsx
    │   ├── AssetsPage.tsx
    │   ├── UsersPage.tsx
    │   ├── AuditLogPage.tsx
    │   ├── SettingsPage.tsx
    │   ├── NotificationsPage.tsx
    │   ├── EnrichmentPage.tsx
    │   └── LoginPage.tsx
    │
    ├── components/             # Reusable UI components
    │   ├── layout/
    │   │   ├── AppLayout.tsx   # Sidebar + header shell
    │   │   ├── Sidebar.tsx     # Navigation sidebar
    │   │   └── TopBar.tsx      # Breadcrumbs + notification bell
    │   └── ui/                 # Radix UI + shadcn component wrappers
    │
    ├── lib/
    │   ├── api.ts              # Axios API client + typed endpoint wrappers
    │   ├── mitre.ts            # MITRE ATT&CK taxonomy (~200 techniques)
    │   └── utils.ts            # cn(), date formatting, severity helpers
    │
    └── store/
        └── authStore.ts        # Zustand: auth state, tokens, `can()` helper
```

---

## Pages & Views

| Page | Route | Description |
|---|---|---|
| **Login** | `/login` | JWT authentication form with demo credential buttons |
| **Dashboard** | `/` | Alert trends, EPS gauge, MITRE coverage, MTTR, top hosts |
| **Alert Queue** | `/alerts` | Filterable/sortable alert list with bulk actions and real-time push |
| **Alert Detail** | `/alerts/:id` | Full alert context, timeline, assignment, escalation, ThreatLens enrichment |
| **Log Explorer** | `/logs` | SPL search interface with faceted filters, histogram, live tail |
| **Rule Builder** | `/rules` | Visual detection rule editor with MITRE picker and live YAML preview |
| **Rule Detail** | `/rules/:id` | Rule statistics, trigger history, recent alerts |
| **MITRE Heatmap** | `/mitre` | ATT&CK matrix coloured by detection coverage and alert frequency |
| **Assets** | `/assets` | Asset inventory with criticality management |
| **Users** | `/users` | User management (admin only) |
| **Audit Log** | `/audit` | Full system activity log with actor/resource filtering |
| **Notifications** | `/notifications` | In-app notification centre with read/unread management |
| **Enrichment** | `/enrichment` | IP and domain threat intelligence lookup |
| **Settings** | `/settings` | Profile, notifications (Email/Slack config), security, API keys, integrations |

---

## State Management

The app uses **TanStack React Query v5** for all server state and **Zustand** for client-side UI state.

### TanStack Query

All API data is fetched and cached via React Query:

```tsx
const { data: alerts } = useQuery({
  queryKey: ['alerts', filters],
  queryFn: () => alertsApi.list(filters),
  refetchInterval: 30_000,
});
```

### Zustand Auth Store (`src/store/authStore.ts`)

```tsx
const { user, accessToken, isAuthenticated, can } = useAuthStore();

// Permission check
if (can('users:manage')) {
  // show admin controls
}
```

The `can(permission)` helper checks the user's role permissions against the permission string returned by the backend.

### WebSocket hooks

Real-time connections are managed via custom hooks:

- `useAlertStream()` — subscribes to `ws://host/ws/alerts` and invalidates the alert query on new events
- `useEventStream()` — subscribes to `ws://host/ws/events/live` for the Log Explorer live tail
- `useNotificationStream()` — subscribes to `ws://host/ws/notifications` for the bell indicator

---

## API Client

All backend communication goes through typed wrappers in `src/lib/api.ts`.

```typescript
import { alertsApi, rulesApi, logsApi, settingsApi } from '@/lib/api';

// Fetch alerts with filters
const response = await alertsApi.list({ status: 'new', severity: 'critical' });

// Run a SPL search
const results = await logsApi.search('action=login_failure | stats count by src_ip');

// Update a setting
await settingsApi.patchSystem({ 'notifications.email.enabled': 'true' });
```

The Vite dev server proxies `/api` and `/ws` to `http://localhost:8080`, so no CORS configuration is needed during development.

---

## Component Library

The UI is built on **Radix UI** primitives wrapped with **shadcn/ui** styling conventions and **Tailwind CSS v4** utility classes.

Key components:

| Component | Location | Description |
|---|---|---|
| `AppLayout` | `components/layout/AppLayout.tsx` | Page shell with sidebar and top bar |
| `AlertCard` | Used in AlertQueue | Compact alert summary card with severity badge |
| `SplSearch` | Used in LogExplorer | SPL input with syntax highlighting |
| `RuleEditor` | Used in RuleBuilder | Condition editor with MITRE picker |
| `TimelineView` | Used in AlertDetail | Chronological alert event timeline |
| All UI primitives | `components/ui/` | Button, Badge, Dialog, Select, Table, Tabs, … |

---

## Development

### Available scripts

```bash
npm run dev        # Start Vite dev server (hot module replacement)
npm run build      # Production bundle → dist/
npm run preview    # Preview production bundle locally
npm run typecheck  # tsc --noEmit type check
```

### Environment

The Vite dev server proxies API requests to the backend. The proxy target is configured in `vite.config.ts`:

```ts
server: {
  proxy: {
    '/api': 'http://localhost:8080',
    '/ws':  { target: 'ws://localhost:8080', ws: true },
  }
}
```

### Design tokens

The colour palette and spacing use CSS custom properties defined in `src/index.css`. The dark theme is the default and only theme. Primary accent colour: `hsl(217, 91%, 60%)` (blue).
