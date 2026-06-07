import { pgTable, text, uuid, timestamp, pgEnum } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const assetCriticalityEnum = pgEnum("asset_criticality_level", ["high", "medium", "low"]);
export const assetOsEnum = pgEnum("asset_os", ["windows", "linux", "macos", "other", "network", "unknown"]);

export const assetsTable = pgTable("assets", {
  id: uuid("id").primaryKey().defaultRandom(),
  hostname: text("hostname").notNull().unique(),
  ip: text("ip"),
  os: text("os"),
  criticality: assetCriticalityEnum("criticality").notNull().default("medium"),
  tags: text("tags").array().default([]),
  owner: text("owner"),
  department: text("department"),
  description: text("description"),
  lastSeen: timestamp("last_seen"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
});

export const insertAssetSchema = createInsertSchema(assetsTable).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export type Asset = typeof assetsTable.$inferSelect;
export type InsertAsset = z.infer<typeof insertAssetSchema>;
