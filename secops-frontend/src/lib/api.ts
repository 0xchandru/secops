import axios from "axios";
import type { Alert, AlertStatus, LogEntry, DetectionRule } from "./types";

const BASE = "/api";

export const apiClient = axios.create({
  baseURL: BASE,
  withCredentials: true,
});

apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem("access_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

apiClient.interceptors.response.use(
  (r) => r,
  async (error) => {
    const original = error.config;
    if (error.response?.status === 401 && !original._retry) {
      original._retry = true;
      const refreshToken = localStorage.getItem("refresh_token");
      if (refreshToken) {
        try {
          const { data } = await axios.post(`${BASE}/auth/refresh`, { refreshToken });
          localStorage.setItem("access_token", data.accessToken);
          localStorage.setItem("refresh_token", data.refreshToken);
          original.headers.Authorization = `Bearer ${data.accessToken}`;
          return apiClient(original);
        } catch {
          localStorage.removeItem("access_token");
          localStorage.removeItem("refresh_token");
          window.location.href = "/login";
        }
      } else {
        window.location.href = "/login";
      }
    }
    return Promise.reject(error);
  }
);

// ─── Normalizers ────────────────────────────────────────────────────────────

export function normalizeAlert(raw: any): Alert {
  const safeDate = (v: any) => { const d = v ? new Date(v) : null; return d && !isNaN(d.getTime()) ? d : new Date(); };
  return {
    id: raw.id,
    title: raw.title ?? "Untitled Alert",
    severity: raw.severity,
    status: raw.status,
    assignee: raw.assignedToName ?? (raw.assignedTo ? raw.assignedTo : undefined),
    createdAt: safeDate(raw.createdAt),
    updatedAt: safeDate(raw.updatedAt),
    mitreIds: raw.mitreIds ?? [],
    mitreTactics: raw.mitreTactic ? [raw.mitreTactic] : [],
    ruleId: raw.ruleId ?? "",
    ruleName: raw.ruleName ?? "Detection Alert",
    affectedAssets: [raw.hostname, raw.sourceIp, raw.destIp].filter(Boolean),
    relatedEventIds: [],
    description: raw.description ?? "No description provided.",
    timeline: (raw.timeline ?? []).map((t: any) => ({
      id: t.id,
      timestamp: safeDate(t.createdAt),
      action: t.type === "note" ? "Analyst Note Added"
        : t.type === "status_change" ? `Status changed to ${t.metadata?.newStatus ?? t.content ?? 'unknown'}`
        : t.type === "escalation" ? "Alert Escalated"
        : t.type === "assignment" ? "Alert Assigned"
        : (t.type ?? "System Event"),
      type: t.type ?? 'system',
      user: t.authorName ?? undefined,
      note: t.type === "note" ? t.content : t.content,
      targetUser: t.metadata?.targetUserName ?? t.metadata?.assigneeName ?? undefined,
      targetRole: t.metadata?.targetRole ?? undefined,
      previousStatus: t.metadata?.previousStatus ?? undefined,
      newStatus: t.metadata?.newStatus ?? undefined,
      isOverride: t.metadata?.isOverride ?? false,
      metadata: t.metadata ?? {},
    })),
    aiSummary: raw.description ?? "No AI analysis available for this alert.",
    enrichmentStatus: raw.enrichmentStatus ?? null,
    maxIocScore: raw.maxIocScore ?? null,
    maxIocRiskLevel: raw.maxIocRiskLevel ?? null,
  };
}

export function normalizeLog(raw: any): LogEntry {
  const tsRaw = raw.parsedTimestamp ?? raw.createdAt;
  const ts = tsRaw ? new Date(tsRaw) : null;
  const timestamp = ts && !isNaN(ts.getTime()) ? ts : new Date();

  return {
    id: raw.id,
    timestamp,
    source: raw.source,
    severity: raw.severity,
    eventType: raw.eventType ?? "unknown",
    category: raw.category ?? "",
    action: raw.action ?? "",
    outcome: raw.outcome ?? "",
    sourceIp: raw.sourceIp ?? "",
    destIp: raw.destIp ?? "",
    srcPort: raw.srcPort ?? null,
    dstPort: raw.dstPort ?? null,
    protocol: raw.protocol ?? "",
    hostname: raw.hostname ?? raw.sourceHost ?? "",
    user: raw.username ?? undefined,
    targetUsername: raw.targetUsername ?? undefined,
    logonType: raw.logonType ?? undefined,
    message: raw.message ?? "",
    rawLog: raw.rawData ? JSON.stringify(raw.rawData, null, 2) : "",
    parsed: raw.rawData ?? {},
    tags: raw.tags ?? [],
    direction: raw.direction ?? undefined,
    bytesIn: raw.bytesIn ?? undefined,
    bytesOut: raw.bytesOut ?? undefined,
    httpMethod: raw.httpMethod ?? undefined,
    httpUrl: raw.httpUrl ?? undefined,
    httpStatusCode: raw.httpStatusCode ? Number(raw.httpStatusCode) : undefined,
    httpUserAgent: raw.httpUserAgent ?? undefined,
    dnsQuery: raw.dnsQuery ?? undefined,
    dnsResponseCode: raw.dnsResponseCode ?? undefined,
    fileName: raw.fileName ?? undefined,
    filePath: raw.filePath ?? undefined,
    fileHash: raw.fileHash ?? undefined,
    registryKey: raw.registryKey ?? undefined,
    registryValue: raw.registryValue ?? undefined,
    processName: raw.processName ?? undefined,
    processId: raw.processId ?? undefined,
    processCommandLine: raw.processCommandLine ?? undefined,
    parentProcessId: raw.parentProcessId ?? undefined,
    vendorName: raw.vendorName ?? undefined,
    vendorProduct: raw.vendorProduct ?? undefined,
    deviceAction: raw.deviceAction ?? undefined,
    geoCountry: raw.geoCountry ?? undefined,
    geoCity: raw.geoCity ?? undefined,
    geoCountryDst: raw.geoCountryDst ?? undefined,
    geoCityDst: raw.geoCityDst ?? undefined,
    riskScore: raw.riskScore ?? undefined,
    assetCriticality: raw.assetCriticality ?? undefined,
    ruleMatched: undefined,
    alertId: undefined,
    sourcetype: raw.sourcetype ?? undefined,
    indexName: raw.indexName ?? undefined,
  };
}

export function normalizeRule(raw: any): DetectionRule {
  return {
    id: raw.id,
    name: raw.name,
    description: raw.description ?? "",
    severity: raw.severity,
    enabled: raw.enabled,
    conditions: [],
    yaml: raw.yamlContent ?? "",
    mitreIds: raw.mitreIds ?? [],
    mitreTactics: raw.mitreTactic ? [raw.mitreTactic] : [],
    createdAt: (() => { const d = raw.createdAt ? new Date(raw.createdAt) : null; return d && !isNaN(d.getTime()) ? d : new Date(); })(),
    updatedAt: (() => { const d = raw.updatedAt ? new Date(raw.updatedAt) : null; return d && !isNaN(d.getTime()) ? d : new Date(); })(),
    author: raw.createdBy ?? "system",
    triggerCount: raw.triggerCount ?? 0,
    ruleType: raw.ruleType ?? "sigma",
    splQuery: raw.splQuery ?? undefined,
    splThreshold: raw.splThreshold ?? undefined,
    scheduleInterval: raw.scheduleInterval ?? undefined,
  };
}

// ─── Auth ────────────────────────────────────────────────────────────────────

export const authApi = {
  login: (identifier: string, password: string) =>
    apiClient.post<{ accessToken: string; refreshToken: string; user: AuthUser }>("/auth/login", { identifier, password }),
  logout: () => apiClient.post("/auth/logout"),
  me: () => apiClient.get<{ user: AuthUser }>("/auth/me"),
  refresh: (refreshToken: string) =>
    apiClient.post<{ accessToken: string; refreshToken: string; user: AuthUser }>("/auth/refresh", { refreshToken }),
};

// ─── Me (self-service profile) ───────────────────────────────────────────────

export const meApi = {
  getProfile: () => apiClient.get<{ profile: MeProfile }>("/me"),
  updateProfile: (data: { displayName?: string; jobTitle?: string }) =>
    apiClient.patch<{ profile: MeProfile }>("/me", data),
  changePassword: (currentPassword: string, newPassword: string) =>
    apiClient.post<{ message: string }>("/me/password", { currentPassword, newPassword }),
  getSettings: () => apiClient.get<{ settings: UserSettings }>("/me/settings"),
  updateSettings: (patch: Partial<UserSettings>) =>
    apiClient.patch<{ settings: UserSettings }>("/me/settings", patch),
  listApiKeys: () => apiClient.get<{ keys: ApiKeyRecord[] }>("/me/api-keys"),
  createApiKey: (name: string, scopes?: string[]) =>
    apiClient.post<{ key: ApiKeyRecord & { rawKey: string } }>("/me/api-keys", { name, scopes }),
  deleteApiKey: (id: string) => apiClient.delete(`/me/api-keys/${id}`),
};

// ─── Users ───────────────────────────────────────────────────────────────────

export const usersApi = {
  list: (params?: { search?: string; role?: string; status?: string }) =>
    apiClient.get<{ users: ApiUser[] }>("/users", { params }),
  getById: (id: string) => apiClient.get<{ user: ApiUser }>(`/users/${id}`),
  create: (data: CreateUserPayload) => apiClient.post<{ user: ApiUser }>("/users", data),
  update: (id: string, data: Partial<ApiUser>) => apiClient.patch<{ user: ApiUser }>(`/users/${id}`, data),
  resetPassword: (id: string, newPassword: string) =>
    apiClient.post(`/users/${id}/reset-password`, { newPassword }),
  escalationTargets: (currentRole?: string) =>
    apiClient.get<{ targets: ApiUser[] }>("/users/escalation-targets", { params: currentRole ? { currentRole } : undefined }),
};

// ─── Roles & Permissions ─────────────────────────────────────────────────────

export const rolesApi = {
  list: () => apiClient.get<{ roles: ApiRole[] }>("/roles"),
  getById: (id: string) => apiClient.get<{ role: ApiRole }>(`/roles/${id}`),
  create: (data: { name: string; displayName: string; description?: string; priority: number; color?: string }) =>
    apiClient.post<{ role: ApiRole }>("/roles", data),
  update: (id: string, data: Partial<{ displayName: string; description: string; priority: number; color: string }>) =>
    apiClient.patch<{ role: ApiRole }>(`/roles/${id}`, data),
  delete: (id: string) => apiClient.delete(`/roles/${id}`),
  setPermissions: (id: string, permissionIds: string[]) =>
    apiClient.put<{ role: ApiRole }>(`/roles/${id}/permissions`, { permissionIds }),
  listPermissions: () => apiClient.get<{ permissions: ApiPermission[] }>("/permissions"),
  seed: () => apiClient.post<{ roles: number; permissions: number }>("/roles/seed"),
};

// ─── Alerts ──────────────────────────────────────────────────────────────────

export const alertsApi = {
  list: (params?: Record<string, string | number>) =>
    apiClient.get<{ alerts: any[]; total: number; page: number; limit: number }>("/alerts", { params }),
  getById: (id: string) => apiClient.get<{ alert: any }>(`/alerts/${id}`),
  investigate: (id: string) =>
    apiClient.post<{ alert: any }>(`/alerts/${id}/investigate`),
  updateStatus: (id: string, status: AlertStatus, resolutionNotes?: string) =>
    apiClient.patch<{ alert: any }>(`/alerts/${id}/status`, { status, resolutionNotes }),
  assign: (id: string, assignedTo: string) =>
    apiClient.patch<{ alert: any }>(`/alerts/${id}/assign`, { assignedTo }),
  clearAssignment: (id: string) =>
    apiClient.delete<{ alert: any }>(`/alerts/${id}/assign`),
  escalate: (id: string, escalateTo: string, reason: string) =>
    apiClient.post<{ alert: any }>(`/alerts/${id}/escalate`, { escalateTo, reason }),
  addNote: (id: string, content: string, type?: string) =>
    apiClient.post<{ entry: any }>(`/alerts/${id}/timeline`, { content, type }),
  bulkUpdate: (ids: string[], status: AlertStatus, resolutionNotes?: string) =>
    apiClient.post<{ updated: number }>("/alerts/bulk-update", { ids, status, resolutionNotes }),
  relatedEvents: (id: string, minutesBefore = 10, minutesAfter = 5) =>
    apiClient.get<{ events: any[]; total: number }>(`/alerts/${id}/related-events`, { params: { minutesBefore, minutesAfter } }),
  // Unified action endpoints (DB-driven RBAC)
  getActions: (id: string) =>
    apiClient.get<{ actions: string[]; alertId: string; status: string }>(`/alerts/${id}/actions`),
  executeAction: (id: string, action: string, payload?: Record<string, any>) =>
    apiClient.post<{ alert?: any; entry?: any }>(`/alerts/${id}/actions/${action}`, payload),
};

// ─── Rules ───────────────────────────────────────────────────────────────────

export const rulesApi = {
  list: () => apiClient.get<{ rules: any[] }>("/rules"),
  getById: (id: string) => apiClient.get(`/rules/${id}`),
  create: (data: unknown) => apiClient.post("/rules", data),
  update: (id: string, data: unknown) => apiClient.patch(`/rules/${id}`, data),
  delete: (id: string) => apiClient.delete(`/rules/${id}`),
  toggle: (id: string, enabled: boolean) => apiClient.patch(`/rules/${id}/toggle`, { enabled }),
  test: (ruleData: Record<string, any>) =>
    apiClient.post<{ matchedEvents?: number; totalEvents?: number; valid?: boolean; errors?: string[]; sampleEvents?: any[] }>("/rules/test", ruleData),
  stats: (id: string) => apiClient.get<Record<string, any>>(`/rules/${id}/stats`),
};

// ─── Logs ────────────────────────────────────────────────────────────────────

export const logsApi = {
  list: (params?: Record<string, string | number>) =>
    apiClient.get<{ logs: any[]; total: number; page: number; limit: number }>("/logs", { params }),
  filters: () =>
    apiClient.get<{ sources: string[]; severities: string[]; categories: string[] }>("/logs/filters"),
  facets: (body: { fields?: string[]; limit?: number; from?: string; q?: string }) =>
    apiClient.post<{ facets: Record<string, { value: string; count: number }[]> }>("/logs/facets", body),
  spl: (body: { query: string; from?: string; to?: string; limit?: number }) =>
    apiClient.post<{ logs: any[]; total: number; isSplResult: true; columns?: string[] }>("/logs/spl", body),
};

// ─── Events ──────────────────────────────────────────────────────────────────

export const eventsApi = {
  histogram: (params: { interval?: string; source?: string; severity?: string; hours?: number }) =>
    apiClient.post<{ buckets: Array<{ bucket: string; count: number }> }>("/events/histogram", params),
  context: (host: string) =>
    apiClient.get<{ events: any[]; alerts: any[]; bySource: Record<string, number>; total: number }>(`/events/context/${encodeURIComponent(host)}`),
};

// ─── Ingest ──────────────────────────────────────────────────────────────────

export const ingestApi = {
  single: (data: {
    source: string;
    severity?: string;
    eventType?: string;
    sourceIp?: string;
    destIp?: string;
    hostname?: string;
    username?: string;
    message?: string;
    rawData?: unknown;
  }) => apiClient.post<{ logId: string }>("/ingest-log", data),

  bulk: (logs: Record<string, unknown>[], sourcetype?: string) =>
    apiClient.post<{ inserted: number }>("/ingest/bulk", { logs, sourcetype }),

  raw: (text: string, params?: { source?: string; hostname?: string; sourcetype?: string }) =>
    apiClient.post<{ inserted: number; source: string }>("/ingest/raw", { text }, { params }),

  stats: () =>
    apiClient.get<{
      total: number;
      last24h: number;
      processed: number;
      unprocessed: number;
      unparseable: number;
      bySource: { source: string; count: number }[];
      bySeverity: { severity: string; count: number }[];
    }>("/ingest/stats"),

  reprocess: (opts?: { limit?: number; status?: string }) =>
    apiClient.post<{ reprocessed: number; status: string }>("/ingest/reprocess", opts),
};

// ─── Forwarders ──────────────────────────────────────────────────────────────

export interface ForwarderMonitor {
  path: string;
  sourcetype?: string;
  offset: number;
  eventsSent: number;
  eps: number;
}

export interface Forwarder {
  id: string;
  name: string;
  host: string;
  version: string;
  lastHeartbeatAt: string | null;
  totalEventsSent: number;
  eps: number;
  monitors: ForwarderMonitor[];
  status: string;
  online: boolean;
  createdAt: string;
}

export const forwardersApi = {
  list: () =>
    apiClient.get<{ forwarders: Forwarder[]; total: number }>("/forwarders"),
  delete: (id: string) =>
    apiClient.delete(`/forwarders/${id}`),
  heartbeat: (data: {
    name: string;
    host: string;
    version?: string;
    totalEventsSent?: number;
    eps?: number;
    monitors?: ForwarderMonitor[];
  }) => apiClient.post("/forwarders/heartbeat", data),
};

// ─── Assets ──────────────────────────────────────────────────────────────────

export const assetsApi = {
  list: (params?: Record<string, string | number>) =>
    apiClient.get<{ assets: any[]; total: number; page: number; limit: number }>("/assets", { params }),
  getById: (id: string) => apiClient.get<{ asset: any }>(`/assets/${id}`),
  byIdentifier: (params: { hostname?: string; ip?: string }) =>
    apiClient.get<{ asset: any; found: boolean; alertCount?: number; eventCount?: number }>("/assets/by-identifier", { params }),
  create: (data: {
    hostname: string;
    ip?: string;
    os?: string;
    criticality?: string;
    tags?: string[];
    owner?: string;
    department?: string;
    description?: string;
  }) => apiClient.post<{ asset: any }>("/assets", data),
  update: (id: string, data: Record<string, any>) => apiClient.put<{ asset: any }>(`/assets/${id}`, data),
  delete: (id: string) => apiClient.delete(`/assets/${id}`),
};

// ─── Dashboard ───────────────────────────────────────────────────────────────

export const dashboardApi = {
  stats: (range?: string) => apiClient.get<DashboardStats>("/dashboard/stats", { params: range ? { range } : undefined }),
};

// ─── Audit ───────────────────────────────────────────────────────────────────

export const auditApi = {
  list: (params?: Record<string, string>) => apiClient.get("/audit", { params }),
};

// ─── Notifications ───────────────────────────────────────────────────────────

export interface Notification {
  id: string;
  type: "alert_created" | "alert_assigned" | "alert_escalated" | "alert_resolved" | "rule_match" | "system";
  title: string;
  message: string | null;
  link: string | null;
  read: boolean;
  metadata: Record<string, any> | null;
  createdAt: string;
}

export const notificationsApi = {
  list: (params?: { unreadOnly?: boolean; limit?: number; offset?: number }) =>
    apiClient.get<{ notifications: Notification[]; unreadCount: number }>("/notifications", { params }),
  markRead: (id: string) =>
    apiClient.patch(`/notifications/${id}/read`),
  markAllRead: () =>
    apiClient.post("/notifications/read-all"),
  delete: (id: string) =>
    apiClient.delete(`/notifications/${id}`),
};

// ─── Enrichment ──────────────────────────────────────────────────────────────

export const enrichmentApi = {
  getAlertEnrichments: (alertId: string) =>
    apiClient.get<{ enrichments: any[]; count: number }>(`/enrichment/alert/${alertId}`),
  triggerAlertEnrichment: (alertId: string) =>
    apiClient.post<{ status: string; alertId: string }>(`/enrichment/alert/${alertId}`),
  enrichIoc: (value: string) =>
    apiClient.post<any>("/enrichment/ioc", { value }),
  clearAlertCache: (alertId: string) =>
    apiClient.delete(`/enrichment/alert/${alertId}/cache`),
  health: () =>
    apiClient.get<{ threatlens: "online" | "offline"; timestamp: string }>("/enrichment/health"),
};

// ─── ThreatLens Integration ──────────────────────────────────────────────────

export interface ThreatLensResult {
  source: string;
  ioc: { value: string; type: string; id: number };
  scan_id: number;
  score: number;
  risk_level: string;
  confidence: string;
  breakdown: Record<string, number>;
  mitre: Array<{ technique_id: string; technique: string; tactic: string; confidence: string }>;
  results: Record<string, any>;
  errors: string[];
  query_time_ms: number;
}

export const threatlensApi = {
  lookup: (value: string) =>
    apiClient.post<ThreatLensResult>("/threatlens/lookup", { value }),
  enrich: (value: string) =>
    apiClient.get<any>(`/threatlens/enrich/${encodeURIComponent(value)}`),
};

// ─── System Settings API ──────────────────────────────────────────────────────

export type SystemSettings = Record<string, string>;

export const settingsApi = {
  getSystem: () =>
    apiClient.get<{ settings: SystemSettings }>("/settings/system"),
  patchSystem: (updates: SystemSettings) =>
    apiClient.patch<{ ok: boolean }>("/settings/system", updates),
  testEmail: (to?: string) =>
    apiClient.post<{ ok: boolean; message: string }>("/settings/notifications/test-email", { to }),
  testSlack: () =>
    apiClient.post<{ ok: boolean; message: string }>("/settings/notifications/test-slack", {}),
  getThreatLensStatus: () =>
    apiClient.get<{ url: string; apiKeySet: boolean }>("/settings/integrations/threatlens"),
  testThreatLens: () =>
    apiClient.post<{ ok: boolean; latencyMs: number; body?: any }>("/settings/integrations/threatlens/test", {}),
};

// ─── Types ───────────────────────────────────────────────────────────────────

export interface AuthUser {
  userId: string;
  username: string;
  email: string;
  role: "admin" | "soc_manager" | "detection_engineer" | "soc_l2" | "soc_l1" | "viewer";
  displayName?: string | null;
  // DB-driven RBAC fields (populated when backend has seeded roles)
  roles?: string[];
  primaryRole?: string;
  effectivePriority?: number;
  permissions?: string[];
}

export interface MeProfile {
  id: string;
  username: string;
  email: string;
  role: string;
  displayName?: string | null;
  jobTitle?: string | null;
  lastLoginAt?: string | null;
  createdAt: string;
}

export interface UserSettings {
  timezone: string;
  notifications: {
    emailAlerts: boolean;
    emailDigest: boolean;
    slackIntegration: boolean;
    criticalOnly: boolean;
    newAlerts: boolean;
    assignedAlerts: boolean;
    ruleMatches: boolean;
    weeklyReport: boolean;
  };
  security: {
    mfaEnabled: boolean;
    sessionTimeout: number;
  };
}

export interface ApiKeyRecord {
  id: string;
  name: string;
  keyPrefix: string;
  scopes: string[];
  lastUsedAt: string | null;
  createdAt: string;
}

export interface ApiUser {
  id: string;
  username: string;
  email: string;
  role: string;
  status: string;
  displayName?: string;
  lastLoginAt?: string;
  createdAt: string;
}

export interface ApiRole {
  id: string;
  name: string;
  displayName: string;
  description?: string;
  priority: number;
  isSystem: boolean;
  color?: string;
  createdAt: string;
  updatedAt: string;
  permissions?: ApiPermission[];
}

export interface ApiPermission {
  id: string;
  code: string;
  resource: string;
  action: string;
  description?: string;
}

export interface CreateUserPayload {
  username: string;
  email: string;
  password: string;
  role: string;
  displayName?: string;
}

export interface DashboardStats {
  alerts: {
    total: number;
    last24h: number;
    byStatus: Record<string, number>;
    bySeverity: Record<string, number>;
  };
  logs: {
    total: number;
    eps: number;
    bySource: Record<string, number>;
  };
  rules: {
    active: number;
  };
  recentAlerts: Array<{
    id: string;
    alertCode: string;
    title: string;
    severity: string;
    status: string;
    createdAt: string;
  }>;
  alertTrend: Array<{ hour: string; count: number }>;
  mttr: number | null;
  mitreHeatmap: Array<{ tactic: string; technique: string; count: number }>;
  topTargetedHosts: Array<{ hostname: string; count: number }>;
}
