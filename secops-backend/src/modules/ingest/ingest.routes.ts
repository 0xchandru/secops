import { Router } from "express";
import { requireAuth } from "../../middlewares/auth.middleware";
import { can } from "../../middlewares/rbac.middleware";
import { db, rawLogsTable, alertsTable } from "../../db";
import { eq, desc, ilike, and, sql, gte, lte, or, countDistinct, type SQL } from "drizzle-orm";
import { logAuditEvent } from "../../lib/audit";
import { processLogRecord, processLogsBatch, tryEnqueueLog } from "../../lib/detection/pipeline";
import { incrementEps } from "../../lib/redis";
import { parseSplQuery } from "../../lib/search/spl-parser";
import { executeSplPipes } from "../../lib/search/spl-executor";
import type { Request, Response } from "express";

const router = Router();

router.post("/ingest-log", requireAuth, can("ingest:write"), async (req: Request, res: Response) => {
  const { source, severity, eventType, sourceIp, destIp, hostname, username, message, rawData, sourcetype } = req.body;

  if (!source) {
    res.status(400).json({ error: "source is required" });
    return;
  }

  const [log] = await db.insert(rawLogsTable).values({
    source,
    severity: severity ?? "info",
    eventType,
    sourceIp,
    destIp,
    hostname,
    username,
    message,
    rawData: rawData ?? null,
    sourcetype: sourcetype ?? null,
    processed: "false",
  }).returning();

  await logAuditEvent(req, "ingest.log", { resource: "ingest", resourceId: log.id, metadata: { source, severity } });

  const rawMsg = message ?? JSON.stringify(rawData ?? {});
  const enqueued = await tryEnqueueLog(log.id, rawMsg, source, hostname ?? sourceIp ?? "unknown", {
    srcIp: sourceIp ?? "",
    userName: username ?? "",
  });
  if (!enqueued) {
    processLogRecord(log.id, rawMsg, source, hostname ?? sourceIp ?? "unknown", { srcIp: sourceIp, userName: username }).catch(() => {});
  }
  await incrementEps();

  res.status(201).json({ message: "Log ingested successfully", logId: log.id });
});

router.get("/ingest/pending", requireAuth, can("ingest:pending"), async (req: Request, res: Response) => {
  const limit = Number(req.query.limit ?? 100);
  const logs = await db.select().from(rawLogsTable)
    .where(eq(rawLogsTable.processed, "false"))
    .limit(limit);
  res.json({ logs, count: logs.length });
});

router.post("/ingest/detections", requireAuth, can("ingest:write"), async (req: Request, res: Response) => {
  const { detections } = req.body;
  if (!Array.isArray(detections)) {
    res.status(400).json({ error: "detections must be an array" });
    return;
  }

  const created = [];
  for (const det of detections) {
    const [alert] = await db.insert(alertsTable).values({
      alertCode: `ALT-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      title: det.title ?? "Detection Alert",
      description: det.description,
      severity: det.severity ?? "medium",
      status: "new",
      source: det.source,
      ruleId: det.ruleId,
      ruleName: det.ruleName,
      mitreIds: det.mitreIds ?? [],
      mitreTactic: det.mitreTactic,
      sourceIp: det.sourceIp,
      destIp: det.destIp,
      hostname: det.hostname,
      rawLog: det.rawLog,
      createdBy: req.user!.userId,
    }).returning();
    created.push(alert);
  }

  res.status(201).json({ created: created.length, alerts: created });
});

router.post("/ingest/bulk", requireAuth, can("ingest:write"), async (req: Request, res: Response) => {
  const { logs, sourcetype: bulkSourcetype } = req.body;
  if (!Array.isArray(logs) || logs.length === 0) {
    res.status(400).json({ error: "logs must be a non-empty array" });
    return;
  }
  if (logs.length > 10_000) {
    res.status(400).json({ error: "Maximum 10,000 logs per bulk upload" });
    return;
  }

  const values = logs.map((l: Record<string, any>) => ({
    source: String(l.source ?? l.host ?? l.hostname ?? "file-upload"),
    severity: ["critical", "high", "medium", "low", "info"].includes(String(l.severity ?? "").toLowerCase())
      ? String(l.severity).toLowerCase()
      : "info",
    eventType: l.eventType ?? l.event_type ?? l.EventType ?? undefined,
    sourceIp: l.sourceIp ?? l.source_ip ?? l.src_ip ?? l.src ?? undefined,
    destIp: l.destIp ?? l.dest_ip ?? l.dst_ip ?? l.dst ?? undefined,
    hostname: l.hostname ?? l.host ?? undefined,
    username: l.username ?? l.user ?? undefined,
    message: l.message ?? l.msg ?? l.Message ?? JSON.stringify(l),
    rawData: l as any,
    sourcetype: l.sourcetype ?? l.source_type ?? bulkSourcetype ?? null,
    linecount: l.linecount ?? null,
    processed: "false" as const,
  }));

  const inserted = await db.insert(rawLogsTable).values(values).returning({
    id: rawLogsTable.id,
    message: rawLogsTable.message,
    source: rawLogsTable.source,
    hostname: rawLogsTable.hostname,
    sourceIp: rawLogsTable.sourceIp,
    username: rawLogsTable.username,
  });

  await logAuditEvent(req, "ingest.bulk", {
    resource: "ingest",
    resourceId: inserted[0]?.id,
    metadata: { count: inserted.length, sourcetype: bulkSourcetype },
  });

  processLogsBatch(inserted.map(l => ({ id: l.id, message: l.message ?? "", source: l.source, hostname: l.hostname ?? undefined, sourceIp: l.sourceIp ?? undefined, username: l.username ?? undefined }))).catch(() => {});

  res.status(201).json({ inserted: inserted.length });
});

router.get("/logs", requireAuth, can("alerts:view"), async (req: Request, res: Response) => {
  const { source, severity, search, q, category, action, page = "1", limit = "50", startTime, endTime, from } = req.query as Record<string, string>;
  const pageNum = Math.max(1, Number(page));
  const limitNum = Math.min(200, Math.max(1, Number(limit)));
  const offset = (pageNum - 1) * limitNum;

  const conditions = [];

  if (from && !startTime) {
    const match = /^(\d+)([mhd])$/.exec(from);
    if (match) {
      const amount = Number(match[1]);
      const unit = match[2];
      const ms = unit === "m" ? amount * 60_000 : unit === "h" ? amount * 3_600_000 : amount * 86_400_000;
      conditions.push(gte(rawLogsTable.createdAt, new Date(Date.now() - ms)));
    }
  }

  const splQuery = q || search;
  if (splQuery) {
    const isSpl = /[=|><]/.test(splQuery);
    if (isSpl) {
      const parsed = parseSplQuery(splQuery);
      if (parsed.conditions) conditions.push(parsed.conditions);
    } else {
      const pattern = `%${splQuery}%`;
      conditions.push(
        sql`(${rawLogsTable.message} ilike ${pattern} OR ${rawLogsTable.sourceIp} ilike ${pattern} OR ${rawLogsTable.eventType} ilike ${pattern} OR ${rawLogsTable.username} ilike ${pattern} OR ${rawLogsTable.hostname} ilike ${pattern} OR ${rawLogsTable.action} ilike ${pattern} OR ${rawLogsTable.dnsQuery} ilike ${pattern} OR ${rawLogsTable.httpUrl} ilike ${pattern})`
      );
    }
  }

  if (source) conditions.push(eq(rawLogsTable.source, source));
  if (severity) conditions.push(eq(rawLogsTable.severity, severity));
  if (category) conditions.push(eq(rawLogsTable.category as any, category));
  if (action) conditions.push(eq(rawLogsTable.action as any, action));
  if (startTime) conditions.push(gte(rawLogsTable.createdAt, new Date(startTime)));
  if (endTime) conditions.push(lte(rawLogsTable.createdAt, new Date(endTime)));

  const where = conditions.length > 0 ? and(...conditions) : undefined;

  const [logs, [{ count }]] = await Promise.all([
    db.select().from(rawLogsTable).where(where).orderBy(desc(rawLogsTable.createdAt)).limit(limitNum).offset(offset),
    db.select({ count: sql<number>`count(*)` }).from(rawLogsTable).where(where),
  ]);

  res.json({ logs, total: Number(count), page: pageNum, limit: limitNum });
});

// ─── SPL Full Execution Endpoint ──────────────────────────────────────────────
// POST /logs/spl — executes a full SPL query including pipe transformations
// Returns: { results, count, took, pipe? }
router.post("/logs/spl", requireAuth, can("alerts:view"), async (req: Request, res: Response) => {
  const { query, from: relFrom, limit: limitParam = 10_000 } = req.body as {
    query?: string;
    from?: string;
    limit?: number;
  };

  if (!query?.trim()) {
    res.status(400).json({ error: "query is required" });
    return;
  }

  const start = Date.now();
  const maxRows = Math.min(50_000, Math.max(1, Number(limitParam)));
  const conditions: SQL[] = [];

  // Time range
  if (relFrom) {
    const match = /^(\d+)([mhd])$/.exec(relFrom);
    if (match) {
      const amount = Number(match[1]);
      const unit = match[2];
      const ms = unit === "m" ? amount * 60_000 : unit === "h" ? amount * 3_600_000 : amount * 86_400_000;
      conditions.push(gte(rawLogsTable.createdAt, new Date(Date.now() - ms)));
    }
  }

  const parsed = parseSplQuery(query);
  if (parsed.conditions) conditions.push(parsed.conditions);

  const where = conditions.length > 0 ? and(...conditions) : undefined;

  const rows = await db.select()
    .from(rawLogsTable)
    .where(where)
    .orderBy(desc(rawLogsTable.createdAt))
    .limit(maxRows);

  // Stamp Splunk canonical fields on every row so SPL queries using
  // _time, _raw, host, source, sourcetype, index, eventtype, etc. work correctly.
  const stampedRows = rows.map(row => ({
    ...row,
    _time: row.parsedTimestamp ?? row.createdAt,
    _raw: row.message ?? (row.rawData ? JSON.stringify(row.rawData) : ""),
    _indextime: row.createdAt,
    host: row.hostname ?? row.source ?? "",
    source: row.source ?? "",
    sourcetype: row.sourcetype ?? "generic",
    index: row.indexName ?? "main",
    eventtype: row.eventType ?? "",
    linecount: row.linecount ?? 1,
    src: row.sourceIp ?? "",
    dst: row.destIp ?? "",
    src_ip: row.sourceIp ?? "",
    dst_ip: row.destIp ?? "",
    src_port: row.srcPort ?? null,
    dst_port: row.dstPort ?? null,
    user: row.username ?? "",
    process: row.processName ?? "",
    pid: row.processId ?? null,
  }));

  // Apply pipe transformations in memory
  let results: Record<string, unknown>[];
  if (parsed.pipe) {
    results = executeSplPipes(stampedRows as Record<string, unknown>[], parsed.pipe);
  } else {
    results = stampedRows as Record<string, unknown>[];
  }

  // Normalize SPL results to match the standard { logs, total } response shape
  // so the frontend's LogsExplorerPage can render them without special casing.
  // Also expose raw SPL metadata for display purposes.
  const took = Date.now() - start;
  res.json({
    logs: results,
    total: results.length,
    isSplResult: true,
    took,
    pipe: parsed.pipe ?? null,
    baseQuery: query.split("|")[0].trim(),
    page: 1,
    limit: results.length,
  });
});

// Dynamic filter options
router.get("/logs/filters", requireAuth, can("alerts:view"), async (_req: Request, res: Response) => {
  const [sources, severities, categories, sourcetypes] = await Promise.all([
    db.selectDistinct({ value: rawLogsTable.source }).from(rawLogsTable).limit(100),
    db.selectDistinct({ value: rawLogsTable.severity }).from(rawLogsTable).limit(20),
    db.selectDistinct({ value: rawLogsTable.category }).from(rawLogsTable).where(sql`${rawLogsTable.category} is not null`).limit(100),
    db.selectDistinct({ value: rawLogsTable.sourcetype }).from(rawLogsTable).where(sql`${rawLogsTable.sourcetype} is not null`).limit(50),
  ]);
  res.json({
    sources: sources.map(r => r.value),
    severities: severities.map(r => r.value),
    categories: categories.map(r => r.value).filter(Boolean),
    sourcetypes: sourcetypes.map(r => r.value).filter(Boolean),
  });
});

// Field facets
router.post("/logs/facets", requireAuth, can("alerts:view"), async (req: Request, res: Response) => {
  const { fields, limit: facetLimit = 15, from: relFrom, q: searchQuery } = req.body as {
    fields?: string[];
    limit?: number;
    from?: string;
    q?: string;
  };

  const FACET_COLUMNS: Record<string, any> = {
    source: rawLogsTable.source,
    severity: rawLogsTable.severity,
    category: rawLogsTable.category,
    eventType: rawLogsTable.eventType,
    action: rawLogsTable.action,
    outcome: rawLogsTable.outcome,
    sourceIp: rawLogsTable.sourceIp,
    destIp: rawLogsTable.destIp,
    hostname: rawLogsTable.hostname,
    username: rawLogsTable.username,
    protocol: rawLogsTable.protocol,
    direction: rawLogsTable.direction,
    httpMethod: rawLogsTable.httpMethod,
    vendorName: rawLogsTable.vendorName,
    vendorProduct: rawLogsTable.vendorProduct,
    geoCountry: rawLogsTable.geoCountry,
    facilityName: rawLogsTable.facilityName,
    processName: rawLogsTable.processName,
    dnsResponseCode: rawLogsTable.dnsResponseCode,
    sourcetype: rawLogsTable.sourcetype,
  };

  const requestedFields = fields && fields.length > 0 ? fields : Object.keys(FACET_COLUMNS);
  const maxLimit = Math.min(50, Math.max(1, facetLimit));

  const conditions: SQL[] = [];
  if (relFrom) {
    const match = /^(\d+)([mhd])$/.exec(relFrom);
    if (match) {
      const amount = Number(match[1]);
      const unit = match[2];
      const ms = unit === "m" ? amount * 60_000 : unit === "h" ? amount * 3_600_000 : amount * 86_400_000;
      conditions.push(gte(rawLogsTable.createdAt, new Date(Date.now() - ms)));
    }
  }
  if (searchQuery) {
    const isSpl = /[=|><]/.test(searchQuery);
    if (isSpl) {
      const parsed = parseSplQuery(searchQuery);
      if (parsed.conditions) conditions.push(parsed.conditions);
    } else {
      const pattern = `%${searchQuery}%`;
      conditions.push(
        sql`(${rawLogsTable.message} ilike ${pattern} OR ${rawLogsTable.sourceIp} ilike ${pattern} OR ${rawLogsTable.hostname} ilike ${pattern})`
      );
    }
  }
  const where = conditions.length > 0 ? and(...conditions) : undefined;

  const facets: Record<string, { value: string; count: number }[]> = {};

  await Promise.all(
    requestedFields.filter(f => FACET_COLUMNS[f]).map(async (field) => {
      const col = FACET_COLUMNS[field];
      const rows = await db
        .select({ value: col, count: sql<number>`count(*)` })
        .from(rawLogsTable)
        .where(where ? and(where, sql`${col} is not null AND ${col} != ''`) : sql`${col} is not null AND ${col} != ''`)
        .groupBy(col)
        .orderBy(sql`count(*) desc`)
        .limit(maxLimit);
      facets[field] = rows.map(r => ({ value: String(r.value), count: Number(r.count) }));
    })
  );

  res.json({ facets });
});

// Event histogram
router.post("/events/histogram", requireAuth, can("alerts:view"), async (req: Request, res: Response) => {
  const { startTime, endTime, interval = "1h", source, severity, hours } = req.body;
  const start = startTime ? new Date(startTime) : hours ? new Date(Date.now() - Number(hours) * 3_600_000) : new Date(Date.now() - 24 * 60 * 60 * 1000);
  const end = endTime ? new Date(endTime) : new Date();

  const intervalSeconds: Record<string, number> = {
    "5m": 300, "15m": 900, "1h": 3600, "6h": 21600, "1d": 86400,
  };
  const bucketSize = intervalSeconds[interval] ?? 3600;

  const conditions = [
    gte(rawLogsTable.createdAt, start),
    lte(rawLogsTable.createdAt, end),
  ];
  if (source) conditions.push(eq(rawLogsTable.source, source));
  if (severity) conditions.push(eq(rawLogsTable.severity, severity));

  const bucketExpr = sql`to_timestamp(floor(extract(epoch from ${rawLogsTable.createdAt}) / ${sql.raw(String(bucketSize))}) * ${sql.raw(String(bucketSize))})`;

  const results = await db
    .select({
      bucket: sql<string>`to_char(${bucketExpr}, 'YYYY-MM-DD"T"HH24:MI:SS')`,
      count: sql<number>`count(*)`,
    })
    .from(rawLogsTable)
    .where(and(...conditions))
    .groupBy(bucketExpr)
    .orderBy(bucketExpr);

  res.json({
    buckets: results.map((r) => ({ bucket: r.bucket, count: Number(r.count) })),
    interval,
    startTime: start.toISOString(),
    endTime: end.toISOString(),
  });
});

// Host context
router.get("/events/context/:host", requireAuth, can("alerts:view"), async (req: Request, res: Response) => {
  const host = String(req.params.host);
  const limit = Math.min(200, Number(req.query.limit ?? 50));

  const [events, alerts, sourceSummary] = await Promise.all([
    db.select().from(rawLogsTable)
      .where(or(
        eq(rawLogsTable.hostname, host),
        eq(rawLogsTable.sourceIp, host),
        sql`${rawLogsTable.sourceHost} = ${host}`,
      ))
      .orderBy(desc(rawLogsTable.createdAt))
      .limit(limit),
    db.select().from(alertsTable)
      .where(or(
        eq(alertsTable.hostname, host),
        eq(alertsTable.sourceIp, host),
        eq(alertsTable.sourceHost, host),
      ))
      .orderBy(desc(alertsTable.createdAt))
      .limit(20),
    db.select({
      source: rawLogsTable.source,
      count: sql<number>`count(*)`,
    }).from(rawLogsTable)
      .where(or(
        eq(rawLogsTable.hostname, host),
        eq(rawLogsTable.sourceIp, host),
        sql`${rawLogsTable.sourceHost} = ${host}`,
      ))
      .groupBy(rawLogsTable.source),
  ]);

  const sourceMap: Record<string, number> = {};
  sourceSummary.forEach((r) => { sourceMap[r.source] = Number(r.count); });

  res.json({
    host,
    totalEvents: events.length,
    totalAlerts: alerts.length,
    events,
    alerts,
    sourceBreakdown: sourceMap,
  });
});

// Raw Text Ingestion
router.post("/ingest/raw", requireAuth, can("ingest:write"), async (req: Request, res: Response) => {
  const source = (req.query.source as string) || (req.headers["x-log-source"] as string) || "raw-text";
  const hostname = (req.query.hostname as string) || (req.headers["x-log-hostname"] as string) || "unknown";
  const sourcetype = (req.query.sourcetype as string) || (req.headers["x-log-sourcetype"] as string) || null;

  let body = "";
  if (typeof req.body === "string") {
    body = req.body;
  } else if (Buffer.isBuffer(req.body)) {
    body = req.body.toString("utf-8");
  } else if (typeof req.body === "object" && req.body.text) {
    body = String(req.body.text);
  } else {
    res.status(400).json({ error: "Expected plain text body (Content-Type: text/plain)" });
    return;
  }

  const lines = body.split("\n").map(l => l.trim()).filter(Boolean);
  if (lines.length === 0) {
    res.status(400).json({ error: "No log lines found in body" });
    return;
  }
  if (lines.length > 10_000) {
    res.status(400).json({ error: "Maximum 10,000 lines per request" });
    return;
  }

  const values = lines.map(line => ({
    source,
    severity: "info",
    hostname,
    message: line,
    rawData: { raw: line } as any,
    sourcetype,
    linecount: 1,
    processed: "false" as const,
  }));

  const inserted = await db.insert(rawLogsTable).values(values).returning({
    id: rawLogsTable.id,
    message: rawLogsTable.message,
    source: rawLogsTable.source,
    hostname: rawLogsTable.hostname,
    sourceIp: rawLogsTable.sourceIp,
    username: rawLogsTable.username,
  });

  await logAuditEvent(req, "ingest.raw", {
    resource: "ingest",
    resourceId: inserted[0]?.id,
    metadata: { count: inserted.length, source, sourcetype },
  });

  processLogsBatch(inserted.map(l => ({
    id: l.id,
    message: l.message ?? "",
    source: l.source,
    hostname: l.hostname ?? undefined,
    sourceIp: l.sourceIp ?? undefined,
    username: l.username ?? undefined,
  }))).catch(() => {});

  res.status(201).json({ inserted: inserted.length, source, sourcetype });
});

// Pipeline Statistics
router.get("/ingest/stats", requireAuth, can("alerts:view"), async (_req: Request, res: Response) => {
  const [totals, bySource, bySeverity, byProcessed, recent24h, bySourcetype] = await Promise.all([
    db.select({ count: sql<number>`count(*)` }).from(rawLogsTable),
    db.select({ source: rawLogsTable.source, count: sql<number>`count(*)` })
      .from(rawLogsTable)
      .groupBy(rawLogsTable.source)
      .orderBy(sql`count(*) desc`)
      .limit(20),
    db.select({ severity: rawLogsTable.severity, count: sql<number>`count(*)` })
      .from(rawLogsTable)
      .groupBy(rawLogsTable.severity),
    db.select({ processed: rawLogsTable.processed, count: sql<number>`count(*)` })
      .from(rawLogsTable)
      .groupBy(rawLogsTable.processed),
    db.select({ count: sql<number>`count(*)` })
      .from(rawLogsTable)
      .where(gte(rawLogsTable.createdAt, new Date(Date.now() - 86_400_000))),
    db.select({ sourcetype: rawLogsTable.sourcetype, count: sql<number>`count(*)` })
      .from(rawLogsTable)
      .where(sql`${rawLogsTable.sourcetype} is not null`)
      .groupBy(rawLogsTable.sourcetype)
      .orderBy(sql`count(*) desc`)
      .limit(20),
  ]);

  const processedMap: Record<string, number> = {};
  byProcessed.forEach(r => { processedMap[r.processed ?? "unknown"] = Number(r.count); });

  res.json({
    total: Number(totals[0]?.count ?? 0),
    last24h: Number(recent24h[0]?.count ?? 0),
    processed: Number(processedMap["true"] ?? 0),
    unprocessed: Number(processedMap["false"] ?? 0),
    unparseable: Number(processedMap["unparseable"] ?? 0),
    bySource: bySource.map(r => ({ source: r.source, count: Number(r.count) })),
    bySeverity: bySeverity.map(r => ({ severity: r.severity, count: Number(r.count) })),
    bySourcetype: bySourcetype.map(r => ({ sourcetype: r.sourcetype, count: Number(r.count) })),
  });
});

// Reprocess unprocessed/unparseable logs
router.post("/ingest/reprocess", requireAuth, can("ingest:write"), async (req: Request, res: Response) => {
  const limit = Math.min(1000, Number(req.body.limit ?? 500));
  const status = req.body.status === "unparseable" ? "unparseable" : "false";

  const logs = await db.select({
    id: rawLogsTable.id,
    message: rawLogsTable.message,
    source: rawLogsTable.source,
    hostname: rawLogsTable.hostname,
    sourceIp: rawLogsTable.sourceIp,
    username: rawLogsTable.username,
  }).from(rawLogsTable)
    .where(eq(rawLogsTable.processed, status))
    .limit(limit);

  if (logs.length === 0) {
    res.json({ reprocessed: 0, message: "No logs to reprocess" });
    return;
  }

  await logAuditEvent(req, "ingest.reprocess", {
    resource: "ingest",
    metadata: { count: logs.length, status },
  });

  processLogsBatch(logs.map(l => ({
    id: l.id,
    message: l.message ?? "",
    source: l.source,
    hostname: l.hostname ?? undefined,
    sourceIp: l.sourceIp ?? undefined,
    username: l.username ?? undefined,
  }))).catch(() => {});

  res.json({ reprocessed: logs.length, status });
});

export default router;
