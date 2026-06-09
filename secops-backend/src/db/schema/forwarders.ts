import { pgTable, text, uuid, timestamp, integer, real, jsonb } from "drizzle-orm/pg-core";

export const forwardersTable = pgTable("forwarders", {
  id: uuid("id").primaryKey().defaultRandom(),
  name: text("name").notNull(),
  host: text("host").notNull(),
  version: text("version").notNull().default("1.0.0"),
  lastHeartbeatAt: timestamp("last_heartbeat_at").defaultNow(),
  totalEventsSent: integer("total_events_sent").notNull().default(0),
  eps: real("eps").notNull().default(0),
  monitors: jsonb("monitors").notNull().default([]),
  status: text("status").notNull().default("active"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
});

export type Forwarder = typeof forwardersTable.$inferSelect;
export type InsertForwarder = typeof forwardersTable.$inferInsert;
