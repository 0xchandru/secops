import { pgTable, text, uuid, timestamp, jsonb } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";
import { usersTable } from "./users";
import { alertsTable } from "./alerts";

export const incidentsTable = pgTable("incidents", {
  id: uuid("id").primaryKey().defaultRandom(),
  incidentCode: text("incident_code").notNull().unique(),
  title: text("title").notNull(),
  description: text("description"),
  severity: text("severity").notNull().default("medium"),
  status: text("status").notNull().default("open"),
  alertIds: uuid("alert_ids").array(),
  assignedTo: uuid("assigned_to").references(() => usersTable.id),
  createdBy: uuid("created_by").references(() => usersTable.id),
  updatedBy: uuid("updated_by").references(() => usersTable.id),
  resolvedAt: timestamp("resolved_at"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
});

export const insertIncidentSchema = createInsertSchema(incidentsTable).omit({
  id: true,
  incidentCode: true,
  createdAt: true,
  updatedAt: true,
});

export type Incident = typeof incidentsTable.$inferSelect;
export type InsertIncident = z.infer<typeof insertIncidentSchema>;
