import { pgTable, text, uuid, timestamp, integer, boolean, jsonb } from "drizzle-orm/pg-core";
import { alertsTable, alertStatusEnum } from "./alerts.js";
import { usersTable } from "./users.js";

/**
 * Alert state transitions — immutable audit log of every status change.
 * Records who performed the transition, their priority, and whether
 * it was a priority-based override of another analyst's work.
 */
export const alertStateTransitionsTable = pgTable("alert_state_transitions", {
  id: uuid("id").primaryKey().defaultRandom(),
  alertId: uuid("alert_id").notNull().references(() => alertsTable.id, { onDelete: "cascade" }),
  fromStatus: alertStatusEnum("from_status").notNull(),
  toStatus: alertStatusEnum("to_status").notNull(),
  performedBy: uuid("performed_by").notNull().references(() => usersTable.id),
  performerPriority: integer("performer_priority").notNull(),
  isOverride: boolean("is_override").notNull().default(false),
  reason: text("reason"),
  metadata: jsonb("metadata").default({}),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

/**
 * Escalation history — tracks each escalation event with
 * from/to analyst info and priority context.
 */
export const escalationHistoryTable = pgTable("escalation_history", {
  id: uuid("id").primaryKey().defaultRandom(),
  alertId: uuid("alert_id").notNull().references(() => alertsTable.id, { onDelete: "cascade" }),
  fromUserId: uuid("from_user_id").references(() => usersTable.id, { onDelete: "set null" }),
  toUserId: uuid("to_user_id").references(() => usersTable.id, { onDelete: "set null" }),
  fromPriority: integer("from_priority"),
  toPriority: integer("to_priority"),
  reason: text("reason").notNull(),
  metadata: jsonb("metadata").default({}),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export type AlertStateTransition = typeof alertStateTransitionsTable.$inferSelect;
export type InsertAlertStateTransition = typeof alertStateTransitionsTable.$inferInsert;
export type EscalationHistory = typeof escalationHistoryTable.$inferSelect;
export type InsertEscalationHistory = typeof escalationHistoryTable.$inferInsert;
