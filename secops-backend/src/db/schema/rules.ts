import { pgTable, text, uuid, timestamp, boolean, integer, jsonb } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";
import { usersTable } from "./users";
import { alertSeverityEnum } from "./alerts";

export const rulesTable = pgTable("rules", {
  id: uuid("id").primaryKey().defaultRandom(),
  name: text("name").notNull(),
  description: text("description"),
  severity: alertSeverityEnum("severity").notNull().default("medium"),
  enabled: boolean("enabled").notNull().default(true),
  yamlContent: text("yaml_content"),
  logSource: text("log_source"),
  mitreIds: text("mitre_ids").array(),
  mitreTactic: text("mitre_tactic"),
  triggerCount: integer("trigger_count").notNull().default(0),
  tags: text("tags").array(),
  falsePositiveRate: integer("false_positive_rate").notNull().default(0),
  createdBy: uuid("created_by").references(() => usersTable.id),
  updatedBy: uuid("updated_by").references(() => usersTable.id),
  lastModifiedAt: timestamp("last_modified_at").notNull().defaultNow(),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
});

export const insertRuleSchema = createInsertSchema(rulesTable).omit({
  id: true,
  triggerCount: true,
  falsePositiveRate: true,
  createdAt: true,
  updatedAt: true,
  lastModifiedAt: true,
});

export type Rule = typeof rulesTable.$inferSelect;
export type InsertRule = z.infer<typeof insertRuleSchema>;
