import { pgTable, text, uuid, timestamp, boolean, pgEnum, jsonb } from "drizzle-orm/pg-core";
import { usersTable } from "./users";

export const notificationTypeEnum = pgEnum("notification_type", [
  "alert_created",
  "alert_assigned",
  "alert_escalated",
  "alert_resolved",
  "rule_match",
  "system",
]);

export const notificationsTable = pgTable("notifications", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: uuid("user_id").notNull().references(() => usersTable.id, { onDelete: "cascade" }),
  type: notificationTypeEnum("type").notNull(),
  title: text("title").notNull(),
  message: text("message"),
  link: text("link"),
  read: boolean("read").notNull().default(false),
  metadata: jsonb("metadata").default({}),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});
