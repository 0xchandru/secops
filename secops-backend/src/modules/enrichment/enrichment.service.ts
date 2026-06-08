import { db } from "../../db/index.js";
import { iocEnrichmentCacheTable, alertIocEnrichmentsTable } from "../../db/schema/enrichment.js";
import { alertsTable } from "../../db/schema/alerts.js";
import { eq, and, gt } from "drizzle-orm";
import { enrichMultiple } from "../../lib/threatlens-client.js";
import { extractIocsFromAlert } from "../../lib/ioc-extractor.js";
import { deriveRecommendedAction } from "../../lib/recommended-action.js";
import { logger } from "../../lib/logger.js";
import type { AlertEnrichmentResult } from "./enrichment.types.js";

const CACHE_TTL_MS = 4 * 60 * 60 * 1000; // 4 hours

// ─── Single IOC Enrichment (cache-first) ────────────────────────────────────

export async function enrichSingleIoc(value: string): Promise<AlertEnrichmentResult | null> {
  // Check cache first
  const cached = await db.select()
    .from(iocEnrichmentCacheTable)
    .where(and(
      eq(iocEnrichmentCacheTable.iocValue, value),
      gt(iocEnrichmentCacheTable.expiresAt, new Date()),
    ))
    .limit(1);

  if (cached.length > 0) {
    const c = cached[0];
    return {
      iocValue: c.iocValue,
      iocType: c.iocType,
      extractedFrom: null,
      confidence: c.confidence,
      threatScore: c.threatScore,
      riskLevel: c.riskLevel,
      iocConfidence: c.confidence,
      breakdown: c.breakdown as any,
      mitreMappings: c.mitreMappings as any,
      sourceResults: c.sourceResults as any,
      recommendedAction: c.recommendedAction,
      tags: c.tags as any,
      queriedAt: c.queriedAt,
      queryTimeMs: c.queryTimeMs,
      fromCache: true,
    };
  }

  // Call ThreatLens
  const result = await enrichMultiple([value]);
  const tl = result.get(value);
  if (!tl) return null;

  const recommended = deriveRecommendedAction(tl.score, tl.risk_level);
  const expiresAt = new Date(Date.now() + CACHE_TTL_MS);
  const iocType = tl.ioc?.type ?? "unknown";

  try {
    const [inserted] = await db.insert(iocEnrichmentCacheTable).values({
      iocValue: value,
      iocType,
      threatScore: tl.score,
      riskLevel: tl.risk_level,
      confidence: tl.confidence,
      breakdown: tl.breakdown as any,
      mitreMappings: tl.mitre as any,
      sourceResults: tl.results as any,
      tags: (tl.tags ?? []) as any,
      recommendedAction: recommended,
      verdict: tl.risk_level,
      queriedAt: new Date(),
      expiresAt,
      sourceScanId: tl.scan_id ?? null,
      queryTimeMs: tl.query_time_ms ?? null,
      enrichmentSource: "threatlens",
    }).returning();

    if (!inserted) return null;

    return {
      iocValue: value,
      iocType,
      extractedFrom: null,
      confidence: tl.confidence,
      threatScore: tl.score,
      riskLevel: tl.risk_level,
      iocConfidence: tl.confidence,
      breakdown: tl.breakdown,
      mitreMappings: tl.mitre,
      sourceResults: tl.results,
      recommendedAction: recommended,
      tags: tl.tags ?? null,
      queriedAt: inserted.queriedAt,
      queryTimeMs: tl.query_time_ms ?? null,
      fromCache: false,
    };
  } catch {
    // Conflict — return what we have
    return null;
  }
}

// ─── Enrich All IOCs for an Alert ───────────────────────────────────────────

export async function enrichAlertIocs(alertId: string): Promise<void> {
  try {
    const alerts = await db.select().from(alertsTable).where(eq(alertsTable.id, alertId)).limit(1);
    if (!alerts.length) return;
    const alert = alerts[0];

    await db.update(alertsTable)
      .set({ enrichmentStatus: "in_progress" })
      .where(eq(alertsTable.id, alertId));

    const iocs = extractIocsFromAlert({
      sourceIp: alert.sourceIp,
      destIp: alert.destIp,
      description: alert.description,
      context: (alert.context ?? {}) as Record<string, any>,
    });

    if (iocs.length === 0) {
      await db.update(alertsTable)
        .set({ enrichmentStatus: "skipped" })
        .where(eq(alertsTable.id, alertId));
      return;
    }

    // Skip IOCs already linked
    const existing = await db.select({ iocValue: alertIocEnrichmentsTable.iocValue })
      .from(alertIocEnrichmentsTable)
      .where(eq(alertIocEnrichmentsTable.alertId, alertId));
    const existingValues = new Set(existing.map(e => e.iocValue));
    const toEnrich = iocs.filter(i => !existingValues.has(i.value));

    if (toEnrich.length === 0) {
      await db.update(alertsTable)
        .set({ enrichmentStatus: "complete", enrichmentCompletedAt: new Date() })
        .where(eq(alertsTable.id, alertId));
      return;
    }

    const results = await enrichMultiple(toEnrich.map(i => i.value));

    let maxScore = 0;
    let maxRiskLevel = "unknown";

    for (const ioc of toEnrich) {
      const tl = results.get(ioc.value);
      let enrichmentId: string | null = null;

      if (tl) {
        const recommended = deriveRecommendedAction(tl.score, tl.risk_level);
        const expiresAt = new Date(Date.now() + CACHE_TTL_MS);

        try {
          const [cached] = await db.insert(iocEnrichmentCacheTable).values({
            iocValue: ioc.value,
            iocType: ioc.type,
            threatScore: tl.score,
            riskLevel: tl.risk_level,
            confidence: tl.confidence,
            breakdown: tl.breakdown as any,
            mitreMappings: tl.mitre as any,
            sourceResults: tl.results as any,
            tags: (tl.tags ?? []) as any,
            recommendedAction: recommended,
            verdict: tl.risk_level,
            queriedAt: new Date(),
            expiresAt,
            sourceScanId: tl.scan_id ?? null,
            queryTimeMs: tl.query_time_ms ?? null,
          }).returning();
          enrichmentId = cached?.id ?? null;
        } catch {
          const existing = await db.select({ id: iocEnrichmentCacheTable.id })
            .from(iocEnrichmentCacheTable)
            .where(eq(iocEnrichmentCacheTable.iocValue, ioc.value))
            .limit(1);
          enrichmentId = existing[0]?.id ?? null;
        }

        if (tl.score > maxScore) {
          maxScore = tl.score;
          maxRiskLevel = tl.risk_level;
        }
      }

      await db.insert(alertIocEnrichmentsTable).values({
        alertId,
        iocValue: ioc.value,
        iocType: ioc.type,
        enrichmentId,
        extractedFrom: ioc.field,
        confidence: ioc.confidence,
      }).onConflictDoNothing();
    }

    // Auto-tag for malicious/critical
    const highRiskLevels = new Set(["critical", "malicious", "suspicious"]);
    const isHighThreat = highRiskLevels.has(maxRiskLevel);
    const newTags = isHighThreat
      ? [...new Set([...(alert.tags ?? []), "threat:enriched", `risk:${maxRiskLevel}`])]
      : alert.tags ?? [];

    const shouldUpgradeSeverity = maxScore > 80 && alert.severity !== "critical" && alert.severity !== "high";

    await db.update(alertsTable).set({
      enrichmentStatus: "complete",
      enrichmentCompletedAt: new Date(),
      maxIocScore: maxScore > 0 ? maxScore : null,
      maxIocRiskLevel: maxRiskLevel,
      tags: newTags,
      ...(shouldUpgradeSeverity ? { severity: "critical" as any } : {}),
      updatedAt: new Date(),
    }).where(eq(alertsTable.id, alertId));

    logger.info({ alertId, iocCount: toEnrich.length, maxScore, maxRiskLevel }, "Alert IOC enrichment complete");
  } catch (err: any) {
    logger.warn({ alertId, err: err.message }, "Alert IOC enrichment failed");
    await db.update(alertsTable)
      .set({ enrichmentStatus: "failed" })
      .where(eq(alertsTable.id, alertId))
      .catch(() => {});
  }
}

// ─── Get Alert Enrichments (for frontend) ───────────────────────────────────

export async function getAlertEnrichments(alertId: string): Promise<AlertEnrichmentResult[]> {
  const rows = await db
    .select({
      iocValue:         alertIocEnrichmentsTable.iocValue,
      iocType:          alertIocEnrichmentsTable.iocType,
      extractedFrom:    alertIocEnrichmentsTable.extractedFrom,
      linkConfidence:   alertIocEnrichmentsTable.confidence,
      threatScore:      iocEnrichmentCacheTable.threatScore,
      riskLevel:        iocEnrichmentCacheTable.riskLevel,
      iocConfidence:    iocEnrichmentCacheTable.confidence,
      breakdown:        iocEnrichmentCacheTable.breakdown,
      mitreMappings:    iocEnrichmentCacheTable.mitreMappings,
      sourceResults:    iocEnrichmentCacheTable.sourceResults,
      recommendedAction: iocEnrichmentCacheTable.recommendedAction,
      tags:             iocEnrichmentCacheTable.tags,
      queriedAt:        iocEnrichmentCacheTable.queriedAt,
      queryTimeMs:      iocEnrichmentCacheTable.queryTimeMs,
    })
    .from(alertIocEnrichmentsTable)
    .leftJoin(iocEnrichmentCacheTable, eq(alertIocEnrichmentsTable.enrichmentId, iocEnrichmentCacheTable.id))
    .where(eq(alertIocEnrichmentsTable.alertId, alertId));

  return rows.map(r => ({
    iocValue:         r.iocValue,
    iocType:          r.iocType,
    extractedFrom:    r.extractedFrom,
    confidence:       r.linkConfidence,
    threatScore:      r.threatScore,
    riskLevel:        r.riskLevel,
    iocConfidence:    r.iocConfidence,
    breakdown:        r.breakdown as any,
    mitreMappings:    r.mitreMappings as any,
    sourceResults:    r.sourceResults as any,
    recommendedAction: r.recommendedAction,
    tags:             r.tags as any,
    queriedAt:        r.queriedAt,
    queryTimeMs:      r.queryTimeMs,
    fromCache:        true,
  }));
}
