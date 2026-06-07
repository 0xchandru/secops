import { pgTable, text, uuid, timestamp, jsonb, pgEnum, integer, boolean } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";
import { usersTable } from "./users";

export const auditActionEnum = pgEnum("audit_action", [
  // Auth
  "login",
  "logout",
  "login_failed",
  "token_refresh",
  // Alert lifecycle
  "alert_created",
  "alert_status_changed",
  "alert_assigned",
  "alert_unassigned",
  "alert_investigated",
  "alert_escalated",
  "alert_resolved",
  "alert_reopened",
  "alert_false_positive",
  "alert_bulk_update",
  "alert_note_added",
  // Rules
  "rule_created",
  "rule_updated",
  "rule_deleted",
  "rule_toggled",
  // Users & Roles
  "user_created",
  "user_updated",
  "user_deleted",
  "user_role_assigned",
  "user_role_removed",
  "user_roles_changed",
  "role_created",
  "role_updated",
  "role_deleted",
  "role_permission_changed",
  // System
  "settings_changed",
  "api_key_created",
  "api_key_revoked",
]);

export const auditLogsTable = pgTable("audit_logs", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: uuid("user_id").references(() => usersTable.id),
  username: text("username"),
  action: auditActionEnum("action").notNull(),
  entityType: text("entity_type"),
  entityId: text("entity_id"),
  // Legacy columns kept for backward compatibility
  resource: text("resource"),
  resourceId: text("resource_id"),
  // Enhanced audit fields
  previousState: jsonb("previous_state"),
  newState: jsonb("new_state"),
  diff: jsonb("diff"),
  performerPriority: integer("performer_priority"),
  isOverride: boolean("is_override").notNull().default(false),
  metadata: jsonb("metadata"),
  ipAddress: text("ip_address"),
  userAgent: text("user_agent"),
  success: text("success").notNull().default("true"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const insertAuditLogSchema = createInsertSchema(auditLogsTable).omit({
  id: true,
  createdAt: true,
});

export type AuditLog = typeof auditLogsTable.$inferSelect;
export type InsertAuditLog = z.infer<typeof insertAuditLogSchema>;
export type AuditAction = typeof auditActionEnum.enumValues[number];
