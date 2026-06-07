import { pgTable, text, uuid, timestamp } from "drizzle-orm/pg-core";
import { usersTable } from "./users";

export const apiKeysTable = pgTable("api_keys", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: uuid("user_id").notNull().references(() => usersTable.id, { onDelete: "cascade" }),
  name: text("name").notNull(),
  keyHash: text("key_hash").notNull(),
  keyPrefix: text("key_prefix").notNull(),
  scopes: text("scopes").array().notNull().default([]),
  lastUsedAt: timestamp("last_used_at"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export type ApiKey = typeof apiKeysTable.$inferSelect;
