import { pgTable, text, uuid, timestamp, real, integer, jsonb, index } from "drizzle-orm/pg-core";
import { alertsTable } from "./alerts";

export const iocEnrichmentCacheTable = pgTable("ioc_enrichment_cache", {
  id:               uuid("id").primaryKey().defaultRandom(),
  iocValue:         text("ioc_value").notNull(),
  iocType:          text("ioc_type").notNull(),
  threatScore:      real("threat_score"),
  riskLevel:        text("risk_level"),
  confidence:       text("confidence"),
  breakdown:        jsonb("breakdown"),
  mitreMappings:    jsonb("mitre_mappings"),
  sourceResults:    jsonb("source_results"),
  tags:             jsonb("tags").$type<string[]>(),
  recommendedAction: text("recommended_action"),
  verdict:          text("verdict"),
  queriedAt:        timestamp("queried_at").defaultNow().notNull(),
  expiresAt:        timestamp("expires_at"),
  sourceScanId:     integer("source_scan_id"),
  queryTimeMs:      integer("query_time_ms"),
  enrichmentSource: text("enrichment_source").default("threatlens"),
}, (table) => [
  index("idx_ioc_cache_value").on(table.iocValue),
  index("idx_ioc_cache_risk").on(table.riskLevel),
  index("idx_ioc_cache_queried").on(table.queriedAt),
]);

export const alertIocEnrichmentsTable = pgTable("alert_ioc_enrichments", {
  id:           uuid("id").primaryKey().defaultRandom(),
  alertId:      uuid("alert_id").references(() => alertsTable.id, { onDelete: "cascade" }).notNull(),
  iocValue:     text("ioc_value").notNull(),
  iocType:      text("ioc_type").notNull(),
  enrichmentId: uuid("enrichment_id").references(() => iocEnrichmentCacheTable.id),
  extractedFrom: text("extracted_from"),
  confidence:   text("confidence"),
  createdAt:    timestamp("created_at").defaultNow().notNull(),
}, (table) => [
  index("idx_alert_ioc_alert_id").on(table.alertId),
  index("idx_alert_ioc_value").on(table.iocValue),
]);

export type IocEnrichmentCache = typeof iocEnrichmentCacheTable.$inferSelect;
export type AlertIocEnrichment = typeof alertIocEnrichmentsTable.$inferSelect;
