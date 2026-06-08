# SecOps × ThreatLens — Integration Architecture & Build Plan

> **Author:** Senior Security Architect Review  
> **Stack:** SecOps (React 19 + Express 5 + TypeScript + PostgreSQL + Redis) × ThreatLens (React + FastAPI + Python + PostgreSQL/SQLite)  
> **Goal:** Upgrade SecOps into a SOC-grade mini SIEM with deep ThreatLens enrichment on every alert  
> **Constraint:** Realistic student project, interview-worthy, security-first

---

## 1. ThreatLens — Architectural Analysis

### What ThreatLens Actually Is

ThreatLens is a stateful IOC enrichment microservice, not just a lookup tool. That distinction matters for how SecOps integrates with it. Key observations:

**What makes it useful as a backend service:**
- **Parallel aggregation engine** — fires 5 API calls simultaneously via `asyncio.gather`. End-to-end latency is ~800ms regardless of how many sources respond. This means SecOps should call it once and wait, not poll.
- **60-minute response cache** — ThreatLens already caches at the DB layer. SecOps should add its own persistence layer on top to avoid re-querying after cache expiry, especially for IOCs already seen in an investigation.
- **Stateful scoring** — scores are composite (breakdown by source: VT=32, AbuseIPDB=25, OTX=22, URLhaus=12, GreyNoise=9). The breakdown is more useful than the composite alone for analyst triage.
- **MITRE mapping is live** — `app/services/mitre.py` derives technique mappings from what the external APIs return. This means the MITRE data in ThreatLens is evidence-backed, not just tag-based. High interview value — say: "MITRE mappings are derived from threat intelligence source data, not hardcoded."
- **Analyst notes + tags are writable** — ThreatLens has `POST /ioc/{value}/notes` and `PUT /ioc/{value}/tags`. SecOps can write back to ThreatLens, creating bidirectional data flow — this is how real SOAR integrations work.
- **Background enrichment** — IPs get async ASN/country/rDNS enrichment via `BackgroundTasks`. The first SecOps call gets a fast response; richer geo data is available on subsequent calls.

### What ThreatLens Does NOT Do

Be clear about these gaps so you don't over-promise in interviews:
- **No bulk lookup endpoint** — only single-IOC POST. SecOps must call it N times for N IOCs, in parallel with `Promise.all()`.
- **No push notification** — ThreatLens is request/response only. SecOps cannot subscribe to new detections in ThreatLens.
- **No IOC-to-alert linking in ThreatLens** — it doesn't know which SecOps alert triggered the lookup. That relationship must be stored in SecOps.
- **No verdict field in the API contract** — the `risk_level` string (`clean`/`low`/`suspicious`/`malicious`/`critical`) is the verdict. "Recommended action" is derived by SecOps, not returned by ThreatLens.

### CORS Reality

ThreatLens runs FastAPI with configurable `CORS_ORIGINS`. The integration doc provides the exact config change needed. **Do not call ThreatLens directly from the SecOps React frontend** — always proxy through the SecOps Express backend. Reasons: API key management, caching, auto-tagging alerts, and you won't expose your ThreatLens URL in browser network tabs. More on this in Section 5.

---

## 2. SecOps → ThreatLens Integration Design

### Integration Pattern Decision

The ThreatLens doc describes four patterns. For your use case, combine **Pattern B + Pattern D**:

```
Pattern B: Auto-enrich on alert detail page open
Pattern D: Auto-tag alert when ThreatLens returns malicious/critical
```

Pattern A (click-to-enrich) is too passive for a "production-grade" demo. Pattern C (nightly batch) is fine for Phase 2 but adds complexity now. Pattern B+D gives you: enrichment fires automatically when an analyst opens an alert, and if ThreatLens returns a critical verdict the alert is immediately upgraded and tagged — without the analyst having to do anything.

### Communication Architecture

```
                    ┌────────────────────────────────────────────┐
                    │          SecOps React Frontend              │
                    │  AlertDetailPage                            │
                    │  Tab: "ThreatLens Report"                  │
                    │   └─► GET /api/enrichment/alert/:alertId   │
                    └───────────────────┬────────────────────────┘
                                        │ HTTP/JSON
                    ┌───────────────────▼────────────────────────┐
                    │      SecOps Express Backend                 │
                    │                                             │
                    │  ┌─────────────────────────────────────┐   │
                    │  │  enrichment.routes.ts                │   │
                    │  │  POST /api/enrichment/alert/:id      │   │
                    │  │  GET  /api/enrichment/alert/:id      │   │
                    │  │  POST /api/enrichment/ioc            │   │
                    │  └──────────────────┬──────────────────┘   │
                    │                     │                       │
                    │  ┌──────────────────▼──────────────────┐   │
                    │  │  threatlens-client.ts                │   │
                    │  │  enrichIOC(value)                    │   │
                    │  │  enrichMultiple(values[])            │   │
                    │  │  addNoteToThreatLens(value, note)    │   │
                    │  └──────────────────┬──────────────────┘   │
                    │                     │                       │
                    │  ┌──────────────────▼──────────────────┐   │
                    │  │  ioc_enrichment_cache table          │   │
                    │  │  alert_ioc_enrichments table         │   │
                    │  │  (PostgreSQL — SecOps DB)            │   │
                    │  └─────────────────────────────────────┘   │
                    └───────────────────┬────────────────────────┘
                                        │ HTTP POST
                                        │ (cross-origin, CORS enabled)
                    ┌───────────────────▼────────────────────────┐
                    │        ThreatLens FastAPI Backend           │
                    │  POST /api/v1/ioc/lookup                    │
                    │  GET  /api/v1/ioc/{value}                   │
                    │  POST /api/v1/ioc/{value}/notes             │
                    └────────────────────────────────────────────┘
```

### Three Trigger Points for Enrichment

**Trigger 1 — Alert creation (critical/high severity):**
In `detection/pipeline.ts`, after `createAlert()`, check severity. If `critical` or `high`, extract IOCs from the alert context and call `enrichAlertsIocs(alertId)` as a background task. Do not await it — don't block the detection pipeline.

```typescript
// In pipeline.ts, after createAlert():
if (['critical', 'high'].includes(alert.severity)) {
  setImmediate(() => enrichAlertsIocs(alert.id).catch(logger.error));
}
```

**Trigger 2 — Alert detail page open:**
`GET /api/alerts/:id` response includes an `enrichmentStatus` field. Frontend checks this and auto-calls `POST /api/enrichment/alert/:id` if status is `pending`. This is non-blocking — the tab renders immediately with a loading state.

**Trigger 3 — Analyst manually requests re-enrichment:**
A "Re-enrich" button in the ThreatLens Report tab. Useful when ThreatLens has updated data since the alert was created.

---

## 3. Advanced Mini SIEM Features to Add

These are ordered by security relevance and interview impact, not UI complexity.

### Priority 1 — ThreatLens Integration (this document's primary subject)

Full IOC enrichment pipeline. Covered in detail throughout this document.

**Interview value:** "When an alert fires, the system automatically extracts IOCs and queries ThreatLens across 5 threat intel sources in parallel. If the composite score exceeds 60, the alert is auto-tagged and severity is upgraded. The analyst sees the full breakdown — VirusTotal detection counts, AbuseIPDB confidence score, AlienVault pulse count, and MITRE technique mappings — in a dedicated tab without leaving the alert."

### Priority 2 — Playbook Rendering (already in YAML, zero backend work needed)

Your rule YAML already has the `playbook:` schema. This is the single highest-ROI feature you're not building yet — the backend supports it, you just need 30 lines of frontend code.

**What to show:** A checklist panel in the alert detail sidebar. Each step is a checkbox. State stored in `localStorage` keyed by `alertId`. When analyst checks a step, it auto-logs to the alert timeline: `"Playbook step completed: Check source IP reputation"`.

**Interview value:** "Detection rules include response playbooks. When an analyst opens an alert, they get step-by-step SOC procedures specific to that detection. Completed steps are logged to the audit trail."

### Priority 3 — SLA Countdown Timers

Define SLA tiers per severity. Track two timestamps: `acknowledgedAt` and `resolvedAt`. Display a countdown in the alert queue — green while healthy, amber at 75%, red when breached.

```typescript
const SLA_CONFIG = {
  critical: { ack: 15 * 60 * 1000,  resolve: 4 * 60 * 60 * 1000  },
  high:     { ack: 30 * 60 * 1000,  resolve: 8 * 60 * 60 * 1000  },
  medium:   { ack: 2 * 60 * 60 * 1000, resolve: 24 * 60 * 60 * 1000 },
  low:      { ack: 8 * 60 * 60 * 1000, resolve: 72 * 60 * 60 * 1000 },
};
```

**Interview value:** "SOC performance is measured by MTTA and MTTR. The platform enforces severity-based SLA deadlines and highlights breached alerts — this is a real operational KPI used in commercial SIEMs."

### Priority 4 — Slack Webhook Notifications

One env var, one `axios.post`, 30 lines of code. Enormous demo value.

Send to Slack when: alert severity is `critical` or `high` AND ThreatLens returns `malicious` or `critical`. This is a compound trigger — both the detection engine AND threat intel must agree before notifying. This reduces false positives in notifications.

```
🚨 *CRITICAL* — DNS Query to C2 Domain
Rule: DNS Query to Known C2 Domain (T1071.004)
Source IP: 203.0.113.45 (RU) → 192.168.1.24
ThreatLens: 87/100 · CRITICAL | malware, botnet, c2
MITRE: T1071.004 — Application Layer Protocol: DNS
→ View in SecOps: https://secops.app/alerts/uuid
```

### Priority 5 — Frequency / Absence Rules (Detection Engine Expansion)

You have `simple`, `threshold`, `sequence`. Add `frequency` (volume spike vs baseline) and `absence` (host stopped reporting). These cover two SOC scenarios your current engine cannot detect. See Section 6.4 of the SecOps doc for the exact YAML schema and implementation approach.

### Priority 6 — Shift Handoff Report

One SQL aggregation endpoint + one printable React page. No new dependencies. Strong interview story about understanding SOC operational processes.

### Priority 7 — Incident Workflow (wire up existing table)

Your `incidents` table exists. The frontend just needs a "Create Incident" button on AlertDetailPage that groups multiple alerts. This takes one afternoon to wire up and demonstrates you understand L1 → L2 escalation paths.

---

## 4. Alert Detail Page — Tab Layout

### Current State
Your `AlertDetailPage.tsx` has: overview info, timeline, related events, IOC extraction panel. It does not have tabs.

### Target State: 7-Tab Alert Investigation Page

```
┌─────────────────────────────────────────────────────────────────┐
│  🔴 CRITICAL  |  SSH Brute Force → 203.0.113.45  |  [Assign]  │
│  Rule: SSH Brute Force Detection  |  T1110.001  |  [Resolve ▼] │
├─────────────────────────────────────────────────────────────────┤
│  [Overview] [Raw Logs] [Detection Logic] [IOC Enrichment]      │
│  [ThreatLens Report ●] [Analyst Notes] [Timeline]             │
└─────────────────────────────────────────────────────────────────┘
```

The `●` dot on ThreatLens Report indicates active enrichment data. If risk_level is malicious/critical, color the tab label red.

### Tab 1 — Overview
**What goes here:** Alert summary card (rule name, severity, MITRE tactic/technique), source/dest IP with GeoIP flags, asset info (criticality, owner, hostname), risk score bar, SLA countdown, quick action buttons (Assign, Escalate, False Positive, Resolve).

**Existing code to reuse:** Your current AlertDetailPage header + enrichment sidebar.

### Tab 2 — Raw Logs
**What goes here:** Filtered view of `raw_logs` table for the alert's `sourceIp`, `destIp`, within `±5 minutes` of `alert.createdAt`. Reuse your `LogsExplorerPage` table component with pre-applied filters. Include a "Open in Log Explorer" link that passes the query string.

**Key detail:** Show `parsedTimestamp` not `createdAt`. Since you fixed timestamp extraction in all 7 parsers, this will show the actual event time from the log — a strong demo point.

### Tab 3 — Detection Logic
**What goes here:** The full rule YAML rendered as a code block. Show the specific condition that matched: which field, which value, what threshold count. If it's a threshold rule, show the sliding window: "5 failures in 5 minutes — triggered at count 7."

**New backend endpoint needed:** `GET /api/alerts/:id/detection-context` — returns the rule YAML + the matched event details + threshold window data.

### Tab 4 — IOC Enrichment
**What goes here:** Your existing IOC extraction panel, upgraded. Auto-extracted IOCs displayed as cards. Each card shows: IOC value, type badge (IP/domain/hash), copy button, and a ThreatBadge chip (score + risk level from ThreatLens). Clicking a card opens the ThreatLens Report tab filtered to that IOC.

**Reuse:** Your existing IOC extraction panel from `AlertDetailPage.tsx` + add ThreatBadge component.

### Tab 5 — ThreatLens Report (THE INTEGRATION SHOWCASE)

This is the main deliverable. Full layout:

```
┌── ThreatLens Report ──────────────────────────────────────────────┐
│                                                                    │
│  IOC: 203.0.113.45  [IP]    Queried: 2 min ago   [Re-enrich]    │
│                                                                    │
│  ┌─── VERDICT ────────────────────────────────────────────────┐  │
│  │         87.4 / 100          ●  CRITICAL                    │  │
│  │   ████████████████████░░░   High Confidence                │  │
│  │   Recommended Action: Block immediately. Escalate to L2.   │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                    │
│  ┌─── SCORE BREAKDOWN ────────────────────────────────────────┐  │
│  │  VirusTotal    ████████████░░░░░  28/32  (malicious: 14)   │  │
│  │  AbuseIPDB     ████████████████░  23/25  (score: 92%)      │  │
│  │  AlienVault    ██████████░░░░░░░  18/22  (pulses: 7)       │  │
│  │  URLhaus       ████░░░░░░░░░░░░░   8/12  (threat: malware) │  │
│  │  GreyNoise     █████░░░░░░░░░░░░   6/9   (classification:  │  │
│  │                                           malicious)       │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                    │
│  ┌─── SOURCE DETAILS ─────────────────────────────────────────┐  │
│  │  [VirusTotal ▼] Malicious: 14 · Suspicious: 3 · Total: 72  │  │
│  │  Tags: trojan, botnet, c2-server, ransomware               │  │
│  │  [AbuseIPDB ▼] Confidence: 92 · Reports: 847 · ISP: AS...  │  │
│  │  Country: RU · TOR: No · Distinct reporters: 312           │  │
│  │  [AlienVault ▼] Pulses: 7 · Malware: Emotet, TrickBot     │  │
│  │  Adversaries: TA505                                        │  │
│  │  [GreyNoise ▼] Classification: malicious · Noise: yes      │  │
│  │  Name: "Known Malicious Scanner"                           │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                    │
│  ┌─── MITRE ATT&CK (from ThreatLens) ────────────────────────┐  │
│  │  T1595 · Active Scanning · Reconnaissance · high           │  │
│  │  T1071.004 · DNS · Command & Control · medium              │  │
│  │  T1041 · Exfil Over C2 · Exfiltration · low                │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                    │
│  ┌─── GEO & ASN (background enrichment) ─────────────────────┐  │
│  │  🇷🇺 Russia · Moscow · ASN AS12389 · Rostelecom            │  │
│  │  rDNS: mail.evil-domain.ru                                 │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                    │
│  [Open full report in ThreatLens →]  [Add analyst note]          │
└────────────────────────────────────────────────────────────────────┘
```

**Multi-IOC support:** If the alert has multiple IOCs (source IP + dest domain + file hash), show a selector at the top of the tab:

```
IOC:  [203.0.113.45 ● 87]  [evil-domain.ru ● 72]  [hash:abc123 ● 45]
```

Each chip colored by risk level. Click to switch which IOC's report is shown.

### Tab 6 — Analyst Notes
Full markdown editor. Save to `alert_timeline` table (type: `analyst_note`, content: markdown). Display as a feed below the editor. Include: who wrote it, when, and allow editing within 5 minutes (graceful — not a hard requirement). Reuse your existing timeline write functionality; just add the markdown editor.

### Tab 7 — Timeline
Your existing alert timeline. Show all events: alert created, status changes, playbook steps completed, ThreatLens enrichment completed, analyst notes, related alerts if grouped into an incident. Sort descending. Each event shows actor (system/analyst name), action, and timestamp. This is the audit-friendly view.

---

## 5. Backend / API Design

### New Module: `secops-backend/src/modules/enrichment/`

```
enrichment/
  enrichment.routes.ts     ← Express router, mounts at /api/enrichment
  enrichment.service.ts    ← Business logic: orchestrates client + cache + alert tagging
  enrichment.types.ts      ← TypeScript interfaces matching ThreatLens response shape
```

### Endpoints

```
POST /api/enrichment/ioc
  Body:  { value: string }
  Logic: 1. Check ioc_enrichment_cache (< 4h old) → return cache hit
          2. If miss: call threatlens-client.enrichIOC(value)
          3. Persist to ioc_enrichment_cache
          4. Return enrichment result
  Auth:  requireAuth (any role)

GET  /api/enrichment/ioc/:value
  Logic: Return latest cache entry for this IOC value
  Auth:  requireAuth

POST /api/enrichment/alert/:alertId
  Logic: 1. Load alert + context fields
          2. Extract IOCs via extractIocsFromAlert(alert)
          3. Promise.all(iocs.map(ioc => enrichIOC(ioc.value)))
          4. If any result is malicious/critical:
              - Update alert.tags to include 'threat:malicious', 'auto-enriched'
              - If score > 80: upgrade severity if not already critical
          5. Link results to alert via alert_ioc_enrichments table
          6. WebSocket broadcast: { type: 'enrichment_complete', alertId, results }
  Auth:  requireAuth

GET  /api/enrichment/alert/:alertId
  Logic: JOIN ioc_enrichment_cache via alert_ioc_enrichments
  Returns: array of { iocValue, iocType, score, riskLevel, breakdown, mitre, sourceResults, ... }
  Auth:  requireAuth

DELETE /api/enrichment/alert/:alertId/cache
  Logic: Delete ioc_enrichment_cache entries for this alert's IOCs (force re-enrich)
  Auth:  requireRole('soc_analyst_l2', 'soc_manager', 'admin')
```

### New Library: `secops-backend/src/lib/threatlens-client.ts`

This is the HTTP client that talks to ThreatLens. Keep it thin — just fetch + error handling + timeout.

```typescript
import axios, { AxiosInstance } from "axios";
import { logger } from "./logger.js";
import type { ThreatLensLookupResponse } from "../modules/enrichment/enrichment.types.js";

const THREATLENS_BASE = process.env["THREATLENS_URL"] ?? "http://localhost:8000";
const THREATLENS_TIMEOUT_MS = parseInt(process.env["THREATLENS_TIMEOUT_MS"] ?? "35000");

const client: AxiosInstance = axios.create({
  baseURL: `${THREATLENS_BASE}/api/v1`,
  timeout: THREATLENS_TIMEOUT_MS,
  headers: { "Content-Type": "application/json" },
});

export async function enrichIOC(value: string): Promise<ThreatLensLookupResponse | null> {
  try {
    const { data } = await client.post<ThreatLensLookupResponse>("/ioc/lookup", { value });
    return data;
  } catch (err: any) {
    // ThreatLens being down should NEVER break SecOps
    logger.warn({ value, err: err.message }, "ThreatLens enrichment failed — degraded mode");
    return null;
  }
}

export async function enrichMultiple(values: string[]): Promise<Map<string, ThreatLensLookupResponse | null>> {
  // Fire all lookups in parallel — ThreatLens handles its own concurrency
  const results = await Promise.allSettled(values.map(v => enrichIOC(v)));
  const map = new Map<string, ThreatLensLookupResponse | null>();
  values.forEach((v, i) => {
    const r = results[i];
    map.set(v, r.status === "fulfilled" ? r.value : null);
  });
  return map;
}

export async function addNoteToThreatLens(iocValue: string, note: string, analyst: string): Promise<void> {
  try {
    await client.post(`/ioc/${encodeURIComponent(iocValue)}/notes`, { note, analyst });
  } catch (err: any) {
    logger.warn({ iocValue, err: err.message }, "Failed to write note to ThreatLens — continuing");
  }
}

export async function isThreatLensHealthy(): Promise<boolean> {
  try {
    await client.get("/health", { timeout: 3000 });
    return true;
  } catch { return false; }
}
```

**Critical design decision:** Every call to ThreatLens is wrapped in try/catch and returns `null` on failure. ThreatLens being offline should never crash SecOps, block alert creation, or break the analyst's workflow. This is non-negotiable for a production-grade design. Say this in interviews: "The enrichment layer is fully decoupled from the detection pipeline. ThreatLens being unreachable degrades gracefully — alerts still fire, just without enrichment context."

### Updated: `secops-backend/src/lib/ioc-extractor.ts`

Your AlertDetailPage already has an IOC extraction panel — this implies an extractor exists somewhere. Formalize it as a shared backend utility:

```typescript
interface ExtractedIOC {
  value: string;
  type: "ip" | "domain" | "url" | "md5" | "sha256";
  field: string;       // which field it came from ("srcIp", "dnsQuery", "fileHash")
  confidence: "high" | "medium";
}

export function extractIocsFromAlert(alert: Alert): ExtractedIOC[] {
  const iocs: ExtractedIOC[] = [];
  const context = alert.context as Record<string, any>;

  // From structured fields (high confidence)
  if (context?.srcIp && !isPrivateIp(context.srcIp))
    iocs.push({ value: context.srcIp, type: "ip", field: "srcIp", confidence: "high" });
  if (context?.dstIp && !isPrivateIp(context.dstIp))
    iocs.push({ value: context.dstIp, type: "ip", field: "dstIp", confidence: "high" });
  if (context?.dnsQuery)
    iocs.push({ value: context.dnsQuery, type: "domain", field: "dnsQuery", confidence: "high" });
  if (context?.fileHash)
    iocs.push({ value: context.fileHash, type: detectHashType(context.fileHash), field: "fileHash", confidence: "high" });

  // From raw message (medium confidence — regex extraction)
  const msg = alert.description ?? "";
  const ipPattern = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
  const domainPattern = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi;
  
  for (const ip of msg.matchAll(ipPattern)) {
    if (!isPrivateIp(ip[0]) && !iocs.find(i => i.value === ip[0]))
      iocs.push({ value: ip[0], type: "ip", field: "message", confidence: "medium" });
  }

  return deduplicateIocs(iocs);
}
```

### New Library: `secops-backend/src/lib/recommended-action.ts`

ThreatLens doesn't return a "recommended action" string — you derive it in SecOps. This is actually a strong feature to claim as yours:

```typescript
export function deriveRecommendedAction(score: number, riskLevel: string, context: {
  isTor: boolean; isNoise: boolean; malwareCount: number; country: string;
}): string {
  if (score >= 80)  return "Block immediately at firewall. Escalate to L2. Preserve forensic artifacts.";
  if (score >= 60)  return "Investigate immediately. Check for lateral movement. Do not block without L2 approval.";
  if (score >= 40)  return "Monitor closely. Correlate with other alerts from this source. Low urgency escalation.";
  if (context.isTor) return "TOR exit node detected. Consider blocking. Correlate with user activity.";
  return "No immediate action required. Log for baseline analysis.";
}
```

---

## 6. Database / Schema

### New Tables in SecOps PostgreSQL

Add to `secops-backend/src/db/schema/enrichment.ts`:

```typescript
// Drizzle ORM schema

// ─── IOC Enrichment Cache ─────────────────────────────────────────
export const iocEnrichmentCache = pgTable("ioc_enrichment_cache", {
  id:              uuid("id").primaryKey().defaultRandom(),
  iocValue:        text("ioc_value").notNull(),
  iocType:         text("ioc_type").notNull(),          // ip | domain | url | md5 | sha256

  // ThreatLens result fields
  threatScore:     real("threat_score"),                // 0.00-100.00
  riskLevel:       text("risk_level"),                  // clean|low|suspicious|malicious|critical
  confidence:      text("confidence"),                  // high|medium|low
  breakdown:       jsonb("breakdown"),                  // { virustotal, abuseipdb, alienvault, urlhaus, greynoise }
  mitreMappings:   jsonb("mitre_mappings"),             // array of MITRETechnique
  sourceResults:   jsonb("source_results"),             // { virustotal: {...}, abuseipdb: {...}, ... }
  tags:            jsonb("tags").$type<string[]>(),

  // Derived in SecOps (not from ThreatLens)
  recommendedAction: text("recommended_action"),
  verdict:           text("verdict"),                   // derived string for display

  // Enrichment metadata
  queriedAt:       timestamp("queried_at").defaultNow().notNull(),
  expiresAt:       timestamp("expires_at"),             // queriedAt + 4h
  sourceScanId:    integer("source_scan_id"),           // ThreatLens scan_id for reference
  queryTimeMs:     integer("query_time_ms"),
  enrichmentSource: text("enrichment_source").default("threatlens"),
},
(table) => ({
  iocValueIdx: index("idx_ioc_cache_value").on(table.iocValue),
  riskLevelIdx: index("idx_ioc_cache_risk").on(table.riskLevel),
  queriedAtIdx: index("idx_ioc_cache_queried").on(table.queriedAt),
}));

// ─── Alert ↔ IOC Enrichment Linking Table ─────────────────────────
export const alertIocEnrichments = pgTable("alert_ioc_enrichments", {
  id:             uuid("id").primaryKey().defaultRandom(),
  alertId:        uuid("alert_id").references(() => alerts.id, { onDelete: "cascade" }).notNull(),
  iocValue:       text("ioc_value").notNull(),
  iocType:        text("ioc_type").notNull(),
  enrichmentId:   uuid("enrichment_id").references(() => iocEnrichmentCache.id),
  extractedFrom:  text("extracted_from"),               // "srcIp" | "dnsQuery" | "fileHash"
  confidence:     text("confidence"),                   // "high" | "medium"
  createdAt:      timestamp("created_at").defaultNow().notNull(),
},
(table) => ({
  alertIdx: index("idx_alert_ioc_alert_id").on(table.alertId),
  iocValueIdx: index("idx_alert_ioc_value").on(table.iocValue),
}));

// ─── Enrichment Status on Alerts ──────────────────────────────────
// Add these columns to the existing alerts table via migration:
// enrichment_status: 'pending' | 'in_progress' | 'complete' | 'failed' | 'skipped'
// enrichment_completed_at: timestamp
// max_ioc_score: real (highest ThreatLens score among all IOCs for quick filtering)
// max_ioc_risk_level: text
```

### Migration for Existing Alerts Table

```sql
-- Add enrichment tracking columns to alerts
ALTER TABLE alerts ADD COLUMN enrichment_status TEXT DEFAULT 'pending'
  CHECK (enrichment_status IN ('pending', 'in_progress', 'complete', 'failed', 'skipped'));
ALTER TABLE alerts ADD COLUMN enrichment_completed_at TIMESTAMP;
ALTER TABLE alerts ADD COLUMN max_ioc_score REAL;
ALTER TABLE alerts ADD COLUMN max_ioc_risk_level TEXT;

-- Index for "show me all alerts with malicious IOCs"
CREATE INDEX idx_alerts_max_ioc_risk ON alerts(max_ioc_risk_level)
  WHERE max_ioc_risk_level IN ('malicious', 'critical');
```

### Cache Invalidation Strategy

Cache expiry is 4 hours in SecOps (vs 60 min in ThreatLens). Rationale: threat intel data doesn't change that fast. If analyst needs fresher data, the "Re-enrich" button forces a bypass. The `expiresAt` column is what `enrichment.service.ts` checks before calling ThreatLens:

```typescript
// In enrichment.service.ts
const cached = await db.select()
  .from(iocEnrichmentCache)
  .where(and(
    eq(iocEnrichmentCache.iocValue, value),
    gt(iocEnrichmentCache.expiresAt, new Date()),  // not expired
  ))
  .limit(1);

if (cached.length > 0) return { ...cached[0], fromCache: true };
```

---

## 7. Frontend Components

### Component Architecture

```
src/
  lib/
    threatlens.ts              ← API client (calls SecOps backend proxy, not ThreatLens directly)
    ioc-helpers.ts             ← getRiskColor(), getRiskLabel(), deriveVerdict()
  components/
    threat/
      ThreatBadge.tsx          ← Inline score chip (for alert table column)
      ThreatLensReportTab.tsx  ← Full report tab component (for AlertDetailPage)
      ThreatScoreBar.tsx       ← Horizontal breakdown bar (5 sources)
      SourceResultCard.tsx     ← Collapsible card per source (VT, AbuseIPDB, etc.)
      MitreTechniqueList.tsx   ← List of MITRE techniques from ThreatLens
      IocSelectorChip.tsx      ← Multi-IOC selector bar at top of tab
      RecommendedActionBadge.tsx
  pages/
    AlertDetailPage.tsx        ← Add tabbed layout + wire all tabs
```

### `src/lib/threatlens.ts` (SecOps frontend client)

This calls **SecOps backend**, not ThreatLens directly. The pattern is important:

```typescript
import { apiClient } from "./api.js";  // your existing axios instance

export async function getAlertEnrichments(alertId: string) {
  const { data } = await apiClient.get(`/enrichment/alert/${alertId}`);
  return data as AlertEnrichmentResult[];
}

export async function triggerAlertEnrichment(alertId: string) {
  const { data } = await apiClient.post(`/enrichment/alert/${alertId}`);
  return data;
}

export function getRiskColor(riskLevel: string): { text: string; bg: string; border: string } {
  const map: Record<string, { text: string; bg: string; border: string }> = {
    clean:      { text: "#86efac", bg: "#14532d", border: "#166534" },
    low:        { text: "#93c5fd", bg: "#1e3a5f", border: "#1e40af" },
    suspicious: { text: "#fde68a", bg: "#422006", border: "#92400e" },
    malicious:  { text: "#fed7aa", bg: "#431407", border: "#9a3412" },
    critical:   { text: "#fca5a5", bg: "#450a0a", border: "#991b1b" },
    unknown:    { text: "#94a3b8", bg: "#1e293b", border: "#334155" },
  };
  return map[riskLevel] ?? map.unknown;
}

// Derive recommended action — mirrors backend logic for client-side display
export function getRecommendedAction(score: number): string {
  if (score >= 80) return "Block immediately · Escalate to L2";
  if (score >= 60) return "Investigate immediately · Do not block without L2 approval";
  if (score >= 40) return "Monitor · Correlate with other alerts";
  return "No immediate action required";
}
```

### `ThreatLensReportTab.tsx` — Core New Component

```tsx
// src/components/threat/ThreatLensReportTab.tsx
import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getAlertEnrichments, triggerAlertEnrichment, getRiskColor } from "../../lib/threatlens";
import { ThreatScoreBar } from "./ThreatScoreBar";
import { SourceResultCard } from "./SourceResultCard";
import { MitreTechniqueList } from "./MitreTechniqueList";
import { IocSelectorChip } from "./IocSelectorChip";

interface Props { alertId: string; }

export function ThreatLensReportTab({ alertId }: Props) {
  const qc = useQueryClient();
  const [selectedIoc, setSelectedIoc] = useState<string | null>(null);

  // Fetch enrichment results
  const { data: enrichments, isLoading, isError } = useQuery({
    queryKey: ["enrichment", alertId],
    queryFn: () => getAlertEnrichments(alertId),
    staleTime: 5 * 60 * 1000,  // consider fresh for 5 min
  });

  // Trigger enrichment mutation
  const enrichMutation = useMutation({
    mutationFn: () => triggerAlertEnrichment(alertId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["enrichment", alertId] }),
  });

  // Auto-trigger if no data yet
  useEffect(() => {
    if (!isLoading && (!enrichments || enrichments.length === 0)) {
      enrichMutation.mutate();
    }
  }, [isLoading]);

  // Auto-select first IOC
  useEffect(() => {
    if (enrichments?.length && !selectedIoc) {
      setSelectedIoc(enrichments[0].iocValue);
    }
  }, [enrichments]);

  if (isLoading || enrichMutation.isPending) {
    return (
      <div className="flex flex-col items-center justify-center py-16 gap-3">
        <div className="animate-spin w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full" />
        <p className="text-slate-400 text-sm">Querying threat intelligence sources...</p>
        <p className="text-slate-500 text-xs">VirusTotal · AbuseIPDB · AlienVault · URLhaus · GreyNoise</p>
      </div>
    );
  }

  if (isError || !enrichments?.length) {
    return (
      <div className="flex flex-col items-center justify-center py-16 gap-4">
        <p className="text-slate-400">No enrichment data available</p>
        {/* Show if ThreatLens is unreachable */}
        <p className="text-slate-500 text-xs">ThreatLens may be offline or no IOCs were extracted</p>
        <button
          onClick={() => enrichMutation.mutate()}
          className="px-4 py-2 bg-blue-600 text-white text-sm rounded-lg hover:bg-blue-500"
        >
          Retry Enrichment
        </button>
      </div>
    );
  }

  const selected = enrichments.find(e => e.iocValue === selectedIoc) ?? enrichments[0];
  const { text, bg, border } = getRiskColor(selected.riskLevel);

  return (
    <div className="space-y-4 p-4">
      {/* Multi-IOC selector */}
      {enrichments.length > 1 && (
        <div className="flex gap-2 flex-wrap">
          {enrichments.map(e => (
            <IocSelectorChip
              key={e.iocValue}
              ioc={e.iocValue}
              score={e.threatScore}
              riskLevel={e.riskLevel}
              isSelected={e.iocValue === selectedIoc}
              onClick={() => setSelectedIoc(e.iocValue)}
            />
          ))}
        </div>
      )}

      {/* Verdict card */}
      <div
        className="rounded-xl p-5 text-center"
        style={{ background: bg, border: `1px solid ${border}` }}
      >
        <div style={{ color: text }} className="text-4xl font-bold font-mono">
          {selected.threatScore?.toFixed(1)}
        </div>
        <div style={{ color: text }} className="text-lg font-semibold tracking-widest uppercase mt-1">
          {selected.riskLevel}
        </div>
        <div className="text-slate-400 text-sm mt-1">
          Confidence: {selected.confidence} · Queried {formatRelativeTime(selected.queriedAt)}
        </div>
        <div style={{ color: text }} className="text-sm mt-3 font-medium">
          {selected.recommendedAction}
        </div>
      </div>

      {/* Score breakdown bars */}
      <ThreatScoreBar breakdown={selected.breakdown} />

      {/* Source result cards — collapsible */}
      <div className="space-y-2">
        {Object.entries(selected.sourceResults ?? {}).map(([source, result]) => (
          <SourceResultCard key={source} source={source} data={result} />
        ))}
      </div>

      {/* MITRE from ThreatLens */}
      {selected.mitreMappings?.length > 0 && (
        <MitreTechniqueList techniques={selected.mitreMappings} />
      )}

      {/* Re-enrich + open in ThreatLens */}
      <div className="flex gap-3 pt-2">
        <button
          onClick={() => enrichMutation.mutate()}
          className="flex-1 py-2 border border-slate-600 text-slate-300 text-sm rounded-lg hover:border-slate-400"
        >
          Re-enrich
        </button>
        <a
          href={`${import.meta.env.VITE_THREATLENS_URL}/lookup?q=${encodeURIComponent(selected.iocValue)}`}
          target="_blank"
          rel="noreferrer"
          className="flex-1 py-2 bg-blue-900/50 text-blue-300 text-sm rounded-lg text-center border border-blue-700 hover:bg-blue-900"
        >
          Open in ThreatLens →
        </a>
      </div>
    </div>
  );
}
```

### `ThreatBadge.tsx` — Alert Table Column

Used in the alert table to show a quick score chip without opening the full detail page:

```tsx
// src/components/threat/ThreatBadge.tsx
import { getRiskColor } from "../../lib/threatlens";

interface Props {
  score: number | null;
  riskLevel: string | null;
  confidence?: string;
}

export function ThreatBadge({ score, riskLevel, confidence }: Props) {
  if (!score || !riskLevel || riskLevel === "unknown") {
    return (
      <span className="text-slate-500 text-xs font-mono">—</span>
    );
  }

  const { text, bg, border } = getRiskColor(riskLevel);

  return (
    <span
      title={`ThreatLens: ${score.toFixed(0)}/100 · ${confidence ?? ""} confidence`}
      style={{ background: bg, color: text, border: `1px solid ${border}` }}
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono"
    >
      {score.toFixed(0)}/100 · {riskLevel.toUpperCase()}
    </span>
  );
}
```

In your alert table (wherever you render the alert list), add a column:
```tsx
// In your alert table columns definition:
{
  header: "Threat Score",
  cell: ({ row }) => (
    <ThreatBadge
      score={row.original.maxIocScore}
      riskLevel={row.original.maxIocRiskLevel}
    />
  )
}
```

### `AlertDetailPage.tsx` — Tabbed Restructure

Your current `AlertDetailPage.tsx` needs a tab system added. Do NOT rewrite it — wrap existing content into tabs:

```tsx
// Add to AlertDetailPage.tsx — tab state
const TABS = ["Overview", "Raw Logs", "Detection Logic", "IOC Enrichment", "ThreatLens Report", "Analyst Notes", "Timeline"] as const;
type Tab = typeof TABS[number];

const [activeTab, setActiveTab] = useState<Tab>("Overview");

// In your return JSX, add tab bar after the alert header:
<div className="flex gap-1 border-b border-slate-700 px-6 -mb-px">
  {TABS.map(tab => {
    // Highlight ThreatLens tab if malicious/critical
    const isThreatTab = tab === "ThreatLens Report";
    const hasThreat = alert.maxIocRiskLevel && ["malicious","critical"].includes(alert.maxIocRiskLevel);
    return (
      <button
        key={tab}
        onClick={() => setActiveTab(tab)}
        className={`px-4 py-3 text-sm border-b-2 transition-colors ${
          activeTab === tab
            ? "border-blue-500 text-white"
            : "border-transparent text-slate-400 hover:text-slate-200"
        } ${isThreatTab && hasThreat ? "text-red-400" : ""}`}
      >
        {tab}
        {isThreatTab && hasThreat && <span className="ml-1 w-2 h-2 rounded-full bg-red-500 inline-block" />}
      </button>
    );
  })}
</div>

// Tab content:
{activeTab === "Overview"           && <AlertOverviewTab alert={alert} />}
{activeTab === "Raw Logs"           && <RelatedLogsTab alertId={alert.id} srcIp={alert.sourceIp} />}
{activeTab === "Detection Logic"    && <DetectionLogicTab alert={alert} />}
{activeTab === "IOC Enrichment"     && <IocEnrichmentTab alert={alert} />}
{activeTab === "ThreatLens Report"  && <ThreatLensReportTab alertId={alert.id} />}
{activeTab === "Analyst Notes"      && <AnalystNotesTab alertId={alert.id} />}
{activeTab === "Timeline"           && <AlertTimelineTab alertId={alert.id} />}
```

---

## 8. File-by-File Implementation Plan

### Files to CREATE

| File | Purpose | Complexity |
|------|---------|-----------|
| `secops-backend/src/lib/threatlens-client.ts` | HTTP client for ThreatLens API | Low |
| `secops-backend/src/lib/ioc-extractor.ts` | Extract IOCs from alert context | Medium |
| `secops-backend/src/lib/recommended-action.ts` | Derive action string from score | Low |
| `secops-backend/src/db/schema/enrichment.ts` | Drizzle schema for 2 new tables | Low |
| `secops-backend/src/db/migrations/YYYYMMDD_enrichment.sql` | Migration for new tables + alert columns | Low |
| `secops-backend/src/modules/enrichment/enrichment.types.ts` | TypeScript interfaces for ThreatLens response | Low |
| `secops-backend/src/modules/enrichment/enrichment.service.ts` | Business logic: cache check, call, persist, auto-tag | High |
| `secops-backend/src/modules/enrichment/enrichment.routes.ts` | Express router | Medium |
| `secops-backend/src/lib/sla-config.ts` | SLA thresholds per severity | Low |
| `secops-backend/src/lib/notifications.ts` | Slack webhook sender | Low |
| `secops-frontend/src/lib/threatlens.ts` | Frontend API client → SecOps proxy | Low |
| `secops-frontend/src/lib/ioc-helpers.ts` | getRiskColor, getRecommendedAction | Low |
| `secops-frontend/src/components/threat/ThreatBadge.tsx` | Inline score chip | Low |
| `secops-frontend/src/components/threat/ThreatLensReportTab.tsx` | Full report tab | High |
| `secops-frontend/src/components/threat/ThreatScoreBar.tsx` | Breakdown bars (5 sources) | Medium |
| `secops-frontend/src/components/threat/SourceResultCard.tsx` | Collapsible source card | Medium |
| `secops-frontend/src/components/threat/MitreTechniqueList.tsx` | MITRE technique list from ThreatLens | Low |
| `secops-frontend/src/components/threat/IocSelectorChip.tsx` | Multi-IOC switcher | Low |
| `secops-frontend/src/components/threat/RecommendedActionBadge.tsx` | Action badge | Low |
| `secops-frontend/src/components/alert-detail/AlertOverviewTab.tsx` | Extract from AlertDetailPage | Medium |
| `secops-frontend/src/components/alert-detail/DetectionLogicTab.tsx` | Rule YAML + matched conditions | Medium |
| `secops-frontend/src/components/alert-detail/RelatedLogsTab.tsx` | Reuse LogsExplorer with filters | Medium |
| `secops-frontend/src/components/alert-detail/AnalystNotesTab.tsx` | Markdown notes editor | Medium |
| `secops-frontend/src/components/PlaybookChecklist.tsx` | Step-by-step checklist from rule YAML | Medium |
| `secops-frontend/src/components/SlaCountdown.tsx` | SLA timer with color states | Low |

### Files to MODIFY

| File | What Changes |
|------|-------------|
| `secops-backend/src/db/schema/index.ts` | Export enrichment tables |
| `secops-backend/src/db/schema/alerts.ts` | Add enrichmentStatus, maxIocScore, maxIocRiskLevel columns |
| `secops-backend/src/lib/detection/pipeline.ts` | After createAlert: setImmediate enrichAlertsIocs() for critical/high |
| `secops-backend/src/modules/alerts/alerts.routes.ts` | Add GET /alerts/:id/detection-context endpoint |
| `secops-backend/src/app.ts` | Mount enrichment router at /api/enrichment |
| `secops-backend/.env.example` | Add THREATLENS_URL, THREATLENS_TIMEOUT_MS, SLACK_WEBHOOK_URL |
| `secops-frontend/src/pages/AlertDetailPage.tsx` | Add tab system, wire all 7 tabs |
| `secops-frontend/src/lib/types.ts` | Add enrichment types, updated Alert type with max_ioc_* fields |
| `secops-frontend/src/lib/api.ts` | Add normalizeEnrichment(), update normalizeAlert() |
| `secops-frontend/.env.example` | Add VITE_THREATLENS_URL |

### Files in ThreatLens to MODIFY

| File | What Changes |
|------|-------------|
| `backend/app/config.py` | Add `CORS_ORIGINS: str = "*"` setting |
| `backend/app/main.py` | Read CORS_ORIGINS from settings instead of hardcoded list |
| `.env` | Add `CORS_ORIGINS=https://your-secops.replit.app,http://localhost:3000` |

---

## 9. Implementation Plan — Weeks 1, 2, 3

### Week 1 — Backend Integration Foundation

**Day 1–2: ThreatLens + SecOps plumbing**
1. Modify ThreatLens CORS config (30 min — trivial, do first)
2. Create `threatlens-client.ts` with `enrichIOC`, `enrichMultiple`, `isThreatLensHealthy`
3. Create `ioc-extractor.ts` — extract IPs, domains, hashes from alert context
4. Write unit tests for ioc-extractor (mock ThreatLens response)
5. Add `THREATLENS_URL` to `.env.example`

**Day 3–4: Database + enrichment service**
1. Create `db/schema/enrichment.ts` (2 tables)
2. Write migration: add tables + 3 columns to alerts table
3. Run migration, verify with `\d ioc_enrichment_cache`
4. Create `enrichment.service.ts`:
   - `enrichSingleIoc(value)` — cache check → ThreatLens call → persist
   - `enrichAlertIocs(alertId)` — extract IOCs → `enrichMultiple` → persist links → update alert `maxIocScore`
   - `getAlertEnrichments(alertId)` — JOIN query

**Day 5: API routes + pipeline integration**
1. Create `enrichment.routes.ts` with 4 endpoints
2. Mount router in `app.ts`
3. Add `setImmediate(() => enrichAlertIocs(alert.id))` in `pipeline.ts` for critical/high
4. Manual test: ingest a log that triggers a high-severity rule → call `GET /api/enrichment/alert/:id` → verify result

**Deliverable at end of Week 1:** SecOps backend can auto-enrich IOCs from alerts and cache results. No frontend yet.

### Week 2 — Frontend: ThreatLens Report Tab

**Day 1–2: Core components**
1. Create `src/lib/threatlens.ts` (frontend API client)
2. Create `src/lib/ioc-helpers.ts` (getRiskColor, matching ThreatLens color scheme exactly)
3. Create `ThreatBadge.tsx` — shows `maxIocScore/maxIocRiskLevel` from alert object
4. Add ThreatBadge column to AlertQueuePage table

**Day 3–4: Report tab component**
1. Create `ThreatScoreBar.tsx` (5-source breakdown with visual bars)
2. Create `SourceResultCard.tsx` (collapsible cards for VT, AbuseIPDB, OTX, URLhaus, GreyNoise)
3. Create `MitreTechniqueList.tsx`
4. Create `IocSelectorChip.tsx` for multi-IOC alerts
5. Assemble `ThreatLensReportTab.tsx` using the above components

**Day 5: AlertDetailPage tab restructure**
1. Refactor `AlertDetailPage.tsx` into 7-tab layout
2. Extract existing content into `AlertOverviewTab.tsx`, `AlertTimelineTab.tsx`
3. Wire `ThreatLensReportTab.tsx` into the tab system
4. Wire `RelatedLogsTab.tsx` (reuse LogsExplorer with pre-applied filters)

**Deliverable at end of Week 2:** Complete ThreatLens Report tab working in AlertDetailPage. Analyst can open any alert, go to the ThreatLens Report tab, and see the full enrichment report. Multi-IOC alerts have a switcher.

### Week 3 — SOC Quality Features

**Day 1: Playbook rendering (high value, low effort)**
1. Update `alerts.routes.ts` to parse `playbook:` YAML section and return steps in alert detail API response
2. Create `PlaybookChecklist.tsx` — step checkboxes, localStorage persistence per alertId
3. On step completion: POST to `alert_timeline` with `{ type: "playbook_step", content: "✓ Step N: ..." }`
4. Add PlaybookChecklist to Overview tab sidebar

**Day 2: SLA tracking**
1. Create `sla-config.ts` with SLA thresholds
2. Add `sla_ack_deadline` and `sla_resolve_deadline` columns to alerts table via migration
3. Populate deadlines when alert is created in pipeline.ts
4. Create `SlaCountdown.tsx` — countdown timer with amber/red states
5. Add countdown to AlertQueuePage rows and AlertDetailPage Overview tab

**Day 3: Slack notifications**
1. Create `notifications.ts` with `notifyCriticalAlert(alert, enrichmentResult)` function
2. Trigger in pipeline.ts after enrichment completes: if score > 60 AND severity critical/high
3. Include ThreatLens verdict in Slack message block

**Day 4: Detection Logic tab**
1. Add `GET /api/alerts/:id/detection-context` endpoint
2. Return: rule YAML, matched event fields, threshold window details
3. Create `DetectionLogicTab.tsx` — YAML code block + "why did this fire" panel

**Day 5: Polish + incident wire-up**
1. Wire "Create Incident from Alert" button in AlertDetailPage to existing incidents table
2. Add `enrichmentStatus` indicator to AlertQueuePage (spinner while pending, ✓ when complete, ✗ if failed)
3. Update README with architecture diagram, new screenshots, integration explanation

**Deliverable at end of Week 3:** Full SOC-grade mini SIEM with ThreatLens integration, playbooks, SLA timers, Slack notifications, tabbed alert investigation, and incident grouping.

---

## 10. Risks / Mistakes to Avoid

### Risk 1 — Calling ThreatLens Directly from the Frontend
**Problem:** Exposes ThreatLens URL in browser network tab. If ThreatLens has API keys in its responses, those are exposed. No caching, no rate limiting, no auto-tagging.
**Fix:** Always proxy through SecOps backend. The frontend only ever calls `/api/enrichment/*`.

### Risk 2 — Blocking the Detection Pipeline on ThreatLens
**Problem:** ThreatLens takes ~800ms per IOC. If you `await enrichAlertIocs()` inside the detection pipeline, every alert creation blocks for 800ms+ per IOC. At 100 events/second, this is a bottleneck.
**Fix:** `setImmediate(() => enrichAlertIocs(alert.id).catch(logger.error))` — fire and forget. The alert is created instantly. Enrichment runs after. The `enrichmentStatus: 'pending'` column tells the frontend to show a loading state.

### Risk 3 — No Graceful Degradation
**Problem:** ThreatLens is a separate service. It will be down sometimes (Replit goes to sleep, API keys expire, etc.). If SecOps crashes when ThreatLens is unavailable, you have a fragile system.
**Fix:** Every call in `threatlens-client.ts` returns `null` on failure, never throws. `enrichment.service.ts` sets `enrichmentStatus: 'failed'` when ThreatLens returns null. The UI shows a "ThreatLens offline" state gracefully. This is architecturally correct and a strong interview point.

### Risk 4 — Re-enriching on Every Page Load
**Problem:** If you call `POST /api/enrichment/alert/:id` on every alert detail page open, you'll spam ThreatLens and eat your free-tier API quota on VirusTotal/AbuseIPDB.
**Fix:** Check `alert.enrichmentStatus` first. Only trigger enrichment if status is `pending` or `failed`. If status is `complete` and `expiresAt` has not passed, return cached result immediately. The "Re-enrich" button bypasses this for explicit analyst requests.

### Risk 5 — Claiming ThreatLens MITRE Data as Your Own
**Problem:** The MITRE mappings in the ThreatLens Report tab come from ThreatLens, not from your detection rules. Your detection rules also have MITRE mappings. Don't confuse them.
**Fix:** Label clearly in the UI: "MITRE (from detection rule)" on the Overview tab, "MITRE (from ThreatLens threat intel)" on the ThreatLens Report tab. In interviews: "The alert has two sources of MITRE context: the rule that fired, and the threat intelligence from ThreatLens. They can differ — an alert for brute-force might have ThreatLens reporting T1595 active scanning, meaning the same IP has been seen doing reconnaissance."

### Risk 6 — Scope Creep on the ThreatLens Tab
**Problem:** Trying to replicate all of ThreatLens UI inside SecOps. You'll spend a week on it and the result will look worse than ThreatLens itself.
**Fix:** The ThreatLens Report tab should show: verdict + score + breakdown + MITRE + one collapsed card per source. A "Open in ThreatLens →" deep link handles everything else. Don't build PDF report generation inside SecOps — ThreatLens already has `POST /reports/generate`.

### Risk 7 — Inconsistent Color Schemes
**Problem:** SecOps has its own severity colors. ThreatLens has its own risk level colors. If you use different colors for the same risk level in different parts of the UI, it looks unprofessional.
**Fix:** In `src/lib/ioc-helpers.ts`, define the exact ThreatLens color map (copied from the integration doc). Use these colors consistently everywhere ThreatLens data is displayed. Keep your existing SecOps severity colors for detection engine alerts. Don't mix them.

### Risk 8 — Over-engineering the IOC Extractor
**Problem:** Building a complex regex-based IOC extractor that handles edge cases (IPv6, defanged IOCs like `1[.]2[.]3[.]4`, URLs with fragments, etc.) is a time sink.
**Fix:** Extract only from structured fields first (`srcIp`, `dstIp`, `dnsQuery`, `fileHash`). These are already parsed by your 7 parsers. Add basic regex for IPs/domains from the `description` field as a secondary pass. Mark structured extractions as `confidence: 'high'`, regex extractions as `confidence: 'medium'`. Ship it — don't over-engineer.

### Risk 9 — Not Handling Private IPs
**Problem:** ThreatLens already rejects private IPs (`10.x`, `192.168.x`, `172.16.x`) in its normalizer. If SecOps sends them, ThreatLens returns a 400 error. Your `enrichAlertIocs()` should pre-filter before calling ThreatLens.
**Fix:** In `ioc-extractor.ts`, the `!isPrivateIp(ip)` guard is already shown above. Add it. Also skip loopback (`127.x`) and link-local (`169.254.x`). Reuse the `isPrivateIp()` function from your enrichment lib which likely already has this logic.

### Risk 10 — Not Saying ThreatLens Is Yours
**The interview framing matters:** Both SecOps and ThreatLens are your projects. In interviews, say: "I built two separate security tools — ThreatLens, a threat intelligence enrichment platform that aggregates 5 external feeds, and SecOps, a mini SIEM. I integrated them: when SecOps detects an alert, it extracts IOCs and queries ThreatLens for reputation data. The analyst sees a full threat intelligence report inside the alert investigation page without switching tools."

This framing shows: systems integration skills, API design, microservice thinking, and security operations workflow understanding — all senior-relevant topics even for L1 applications.

---

## Quick Reference — Build Checklist

```
WEEK 1 — BACKEND
[ ] Modify ThreatLens CORS config
[ ] Create threatlens-client.ts
[ ] Create ioc-extractor.ts
[ ] Create db/schema/enrichment.ts + migration
[ ] Create enrichment.service.ts
[ ] Create enrichment.routes.ts
[ ] Mount router in app.ts
[ ] Add setImmediate enrichment trigger in pipeline.ts
[ ] Manual test: ingest → alert → enrich → GET enrichment result

WEEK 2 — FRONTEND
[ ] Create src/lib/threatlens.ts (frontend client)
[ ] Create src/lib/ioc-helpers.ts (getRiskColor, matching ThreatLens colors)
[ ] Create ThreatBadge.tsx
[ ] Add ThreatBadge column to AlertQueuePage
[ ] Create ThreatScoreBar.tsx
[ ] Create SourceResultCard.tsx
[ ] Create MitreTechniqueList.tsx
[ ] Create IocSelectorChip.tsx
[ ] Assemble ThreatLensReportTab.tsx
[ ] Refactor AlertDetailPage.tsx into 7-tab layout
[ ] Wire ThreatLensReportTab into tab system
[ ] End-to-end test: ingest log → alert fires → open alert → ThreatLens Report tab shows data

WEEK 3 — SOC FEATURES
[ ] Wire playbook: section from rule YAML to PlaybookChecklist.tsx
[ ] Add SLA columns to alerts + create SlaCountdown.tsx
[ ] Create notifications.ts + Slack webhook
[ ] Create DetectionLogicTab.tsx + detection-context endpoint
[ ] Wire "Create Incident" to existing incidents table
[ ] Add enrichmentStatus indicator to AlertQueuePage
[ ] Update README with screenshots + architecture diagram
[ ] Record 2-minute demo walkthrough for GitHub/LinkedIn
```
