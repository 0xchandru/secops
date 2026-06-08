import { pgTable, text, uuid, timestamp, pgEnum, jsonb, integer, boolean, real } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";
import { usersTable } from "./users";

export const alertSeverityEnum = pgEnum("alert_severity", ["critical", "high", "medium", "low", "info"]);
export const alertStatusEnum = pgEnum("alert_status", ["new", "investigating", "escalated", "resolved", "false_positive"]);

export const alertsTable = pgTable("alerts", {
  id: uuid("id").primaryKey().defaultRandom(),
  alertCode: text("alert_code").notNull().unique(),
  title: text("title").notNull(),
  description: text("description"),
  severity: alertSeverityEnum("severity").notNull(),
  severityScore: integer("severity_score").notNull().default(50),
  status: alertStatusEnum("status").notNull().default("new"),
  source: text("source"),
  ruleId: text("rule_id"),
  ruleName: text("rule_name"),
  mitreIds: text("mitre_ids").array(),
  mitreTactic: text("mitre_tactic"),
  mitreTechniqueId: text("mitre_technique_id"),
  mitreTechniqueName: text("mitre_technique_name"),
  mitreSubtechniqueId: text("mitre_subtechnique_id"),
  sourceIp: text("source_ip"),
  destIp: text("dest_ip"),
  hostname: text("hostname"),
  sourceHost: text("source_host"),
  triggerEventId: text("trigger_event_id"),
  triggerTimestamp: timestamp("trigger_timestamp"),
  context: jsonb("context").default({}),
  tags: text("tags").array().default([]),
  relatedEventIds: text("related_event_ids").array().default([]),
  rawLog: jsonb("raw_log"),
  dedupKey: text("dedup_key").unique(),
  enrichmentStatus: text("enrichment_status").default("pending"),
  enrichmentCompletedAt: timestamp("enrichment_completed_at"),
  maxIocScore: real("max_ioc_score"),
  maxIocRiskLevel: text("max_ioc_risk_level"),
  resolutionNotes: text("resolution_notes"),
  createdBy: uuid("created_by").references(() => usersTable.id),
  assignedTo: uuid("assigned_to").references(() => usersTable.id),
  escalatedTo: uuid("escalated_to").references(() => usersTable.id),
  escalationReason: text("escalation_reason"),
  updatedBy: uuid("updated_by").references(() => usersTable.id),
  investigationStartedAt: timestamp("investigation_started_at"),
  resolvedAt: timestamp("resolved_at"),
  escalatedAt: timestamp("escalated_at"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
});

export const alertTimelineTable = pgTable("alert_timeline", {
  id: uuid("id").primaryKey().defaultRandom(),
  alertId: uuid("alert_id").notNull().references(() => alertsTable.id, { onDelete: "cascade" }),
  authorId: uuid("author_id").references(() => usersTable.id),
  authorName: text("author_name"),
  type: text("type").notNull().default("note"),
  content: text("content").notNull(),
  metadata: jsonb("metadata"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const insertAlertSchema = createInsertSchema(alertsTable).omit({
  id: true,
  alertCode: true,
  createdAt: true,
  updatedAt: true,
});

export const insertTimelineSchema = createInsertSchema(alertTimelineTable).omit({
  id: true,
  createdAt: true,
});

export type Alert = typeof alertsTable.$inferSelect;
export type InsertAlert = z.infer<typeof insertAlertSchema>;
export type AlertTimeline = typeof alertTimelineTable.$inferSelect;
