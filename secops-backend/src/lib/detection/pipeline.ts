import { db, rawLogsTable, alertsTable, rulesTable } from "../../db";
import { eq, sql } from "drizzle-orm";
import { detectionEngine } from "./engine";
import { parseLog } from "../parsers";
import { enrichEvent } from "../enrichment";
import type { NormalizedEvent } from "./types";
import { broadcastAlert } from "../websocket";
import { enqueueLog, isRedisAvailable, incrementEps } from "../redis";
import { notifyByRole } from "../notifications";

let engineLoaded = false;
let engineLoading = false;

export async function ensureEngineLoaded(): Promise<void> {
  if (engineLoaded || engineLoading) return;
  engineLoading = true;
  try {
    await detectionEngine.loadRulesFromDb();
    engineLoaded = true;
  } finally {
    engineLoading = false;
  }
}

export function invalidateEngine(): void {
  engineLoaded = false;
}

/**
 * Try to enqueue the log into Redis Streams for async processing.
 * Returns true if enqueued, false if Redis unavailable (falls back to inline).
 */
export async function tryEnqueueLog(logId: string, raw: string, sourceType: string, sourceHost: string, extra: Record<string, string> = {}): Promise<boolean> {
  if (!isRedisAvailable()) return false;
  const result = await enqueueLog({
    logId,
    raw,
    sourceType,
    sourceHost,
    ...extra,
  });
  if (result) {
    await incrementEps();
    return true;
  }
  return false;
}

export async function processLogRecord(logId: string, raw: string, sourceType: string, sourceHost: string, extraFields: Partial<NormalizedEvent> = {}): Promise<void> {
  await ensureEngineLoaded();

  // Parse
  const parsed = parseLog(raw, sourceType, sourceHost);
  if (!parsed) {
    await db.update(rawLogsTable).set({ processed: "unparseable", detectionRunAt: new Date() }).where(eq(rawLogsTable.id, logId));
    return;
  }

  // Build normalized event
  const event: NormalizedEvent = {
    id: logId,
    timestamp: parsed.parsedTimestamp ?? new Date(),
    parsedTimestamp: parsed.parsedTimestamp,
    ingestedAt: new Date(),
    sourceType: parsed.sourceType,
    sourceHost: parsed.sourceHost,
    category: parsed.category,
    action: parsed.action,
    outcome: parsed.outcome,
    severity: parsed.severity,
    eventType: parsed.eventType,

    // User context
    userName: parsed.userName ?? extraFields.userName,
    userDomain: parsed.userDomain,
    userId: parsed.userId,
    targetUserName: parsed.targetUserName,
    logonType: parsed.logonType,

    // Process context
    processName: parsed.processName ?? extraFields.processName,
    processId: parsed.processId,
    processCommandLine: parsed.processCommandLine ?? extraFields.processCommandLine,
    parentProcessName: parsed.parentProcessName,
    parentProcessId: parsed.parentProcessId,

    // Network context
    srcIp: parsed.srcIp ?? extraFields.srcIp,
    srcPort: parsed.srcPort ?? extraFields.srcPort,
    dstIp: parsed.dstIp ?? extraFields.dstIp,
    dstPort: parsed.dstPort ?? extraFields.dstPort,
    protocol: parsed.protocol,
    bytesIn: parsed.bytesIn,
    bytesOut: parsed.bytesOut,
    direction: parsed.direction,
    packetCount: parsed.packetCount,
    networkInterface: parsed.networkInterface,

    // HTTP context
    httpMethod: parsed.httpMethod,
    httpUrl: parsed.httpUrl,
    httpStatusCode: parsed.httpStatusCode,
    httpUserAgent: parsed.httpUserAgent,
    httpReferrer: parsed.httpReferrer,

    // DNS context
    dnsQuery: parsed.dnsQuery,
    dnsResponseCode: parsed.dnsResponseCode,
    dnsRecordType: parsed.dnsRecordType,

    // File context
    fileName: parsed.fileName,
    filePath: parsed.filePath,
    fileHash: parsed.fileHash,

    // Registry context
    registryKey: parsed.registryKey,
    registryValue: parsed.registryValue,

    // Vendor context
    vendorName: parsed.vendorName,
    vendorProduct: parsed.vendorProduct,
    deviceAction: parsed.deviceAction,
    deviceEventClassId: parsed.deviceEventClassId,

    // Syslog context
    facility: parsed.facility,
    facilityName: parsed.facilityName,
    severityCode: parsed.severityCode,

    // Tags
    tags: parsed.tags,

    message: parsed.message,
    rawLog: raw,
  };

  // Enrich
  const enriched = await enrichEvent(event);

  // Update the raw_log record with normalized fields
  await db.update(rawLogsTable).set({
    eventType: enriched.eventType,
    category: enriched.category,
    action: enriched.action,
    outcome: enriched.outcome,
    sourceHost: enriched.sourceHost,

    // User
    username: enriched.userName,
    targetUsername: enriched.targetUserName,
    logonType: enriched.logonType,
    userId: enriched.userId,
    userDomain: enriched.userDomain,

    // Process
    processName: enriched.processName,
    processId: enriched.processId,
    processCommandLine: enriched.processCommandLine,
    parentProcessName: enriched.parentProcessName,
    parentProcessId: enriched.parentProcessId,

    // Network
    srcPort: enriched.srcPort,
    dstPort: enriched.dstPort,
    protocol: enriched.protocol,
    bytesIn: enriched.bytesIn,
    bytesOut: enriched.bytesOut,
    direction: enriched.direction,

    // HTTP
    httpMethod: enriched.httpMethod,
    httpUrl: enriched.httpUrl,
    httpStatusCode: enriched.httpStatusCode,
    httpUserAgent: enriched.httpUserAgent,

    // DNS
    dnsQuery: enriched.dnsQuery,
    dnsResponseCode: enriched.dnsResponseCode,
    dnsRecordType: enriched.dnsRecordType,

    // File
    fileName: enriched.fileName,
    filePath: enriched.filePath,
    fileHash: enriched.fileHash,

    // Registry
    registryKey: enriched.registryKey,
    registryValue: enriched.registryValue,

    // Vendor
    vendorName: enriched.vendorName,
    vendorProduct: enriched.vendorProduct,
    deviceAction: enriched.deviceAction,
    deviceEventClassId: enriched.deviceEventClassId,

    // Syslog
    facility: enriched.facility,
    facilityName: enriched.facilityName,

    // Enrichment
    geoCountry: enriched.geoCountry,
    geoCity: enriched.geoCity,
    geoCountryDst: enriched.geoCountryDst,
    geoCityDst: enriched.geoCityDst,
    assetCriticality: enriched.assetCriticality,
    riskScore: enriched.riskScore,

    // Tags & timestamp
    tags: enriched.tags,
    parsedTimestamp: enriched.parsedTimestamp,
    processed: "true",
    detectionRunAt: new Date(),
  }).where(eq(rawLogsTable.id, logId));

  // Run detection
  const triggeredAlerts = detectionEngine.evaluate(enriched as NormalizedEvent);

  // Create alerts in DB and broadcast via WebSocket
  for (const ta of triggeredAlerts) {
    try {
      const alertCode = `ALT-${Date.now()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`;
      const [created] = await db.insert(alertsTable).values({
        alertCode,
        title: ta.title,
        description: ta.description,
        severity: ta.severity as any,
        severityScore: ta.severityScore,
        status: "new",
        ruleId: ta.ruleId,
        ruleName: ta.ruleName,
        mitreTactic: ta.mitreTactic,
        mitreTechniqueId: ta.mitreTechniqueId,
        mitreTechniqueName: ta.mitreTechniqueName,
        mitreSubtechniqueId: ta.mitreSubtechniqueId,
        mitreIds: [ta.mitreTechniqueId].filter(Boolean) as string[],
        sourceIp: ta.sourceIp,
        destIp: ta.destIp,
        hostname: ta.hostname,
        sourceHost: ta.sourceHost,
        triggerEventId: ta.triggerEventId,
        triggerTimestamp: ta.triggerTimestamp,
        context: ta.context as any,
        tags: ta.tags ?? [],
        dedupKey: ta.dedupKey,
        rawLog: { sourceType, sourceHost, logId } as any,
      }).onConflictDoNothing().returning();

      if (created) {
        // Increment trigger count on the rule
        await db.execute(sql`UPDATE rules SET trigger_count = trigger_count + 1, updated_at = NOW() WHERE name = ${ta.ruleName}`);
        broadcastAlert(created);

        // Notify SOC analysts about high/critical alerts
        if (ta.severity === "critical" || ta.severity === "high") {
          notifyByRole("soc_l1", "alert_created", `New ${ta.severity} alert: ${ta.title}`, {
            message: `Alert ${alertCode} triggered by rule "${ta.ruleName}"`,
            link: `/alerts/${created.id}`,
            metadata: { alertId: created.id, alertCode, severity: ta.severity },
          });
        }
      }
    } catch {
      // Dedup conflict - already exists
    }
  }
}

export async function processLogsBatch(logs: Array<{ id: string; message: string; source: string; hostname?: string; sourceIp?: string; username?: string }>): Promise<number> {
  let count = 0;
  for (const log of logs) {
    try {
      const sourceType = detectSourceType(log.source, log.message);
      await processLogRecord(
        log.id,
        log.message ?? JSON.stringify(log),
        sourceType,
        log.hostname ?? log.sourceIp ?? "unknown",
        { srcIp: log.sourceIp, userName: log.username },
      );
      count++;
    } catch {}
  }
  return count;
}

function detectSourceType(source: string, message: string): string {
  const s = source.toLowerCase();
  if (s.includes("windows") || s.includes("winlog") || message.includes("<EventID>")) return "windows_eventlog";
  if (s.includes("syslog") || s.includes("linux") || message.match(/^<\d+>/)) return "syslog";
  if (s.includes("firewall") || s.includes("iptables") || message.includes("SRC=")) return "firewall";
  // Detect raw BSD syslog without <priority>: "Mon DD HH:MM:SS hostname program[pid]:"
  if (/^\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+(?:\[\d+\])?:/.test(message)) return "syslog";
  return "generic";
}
