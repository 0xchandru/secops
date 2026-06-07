import { pgTable, text, uuid, timestamp, pgEnum, integer, jsonb } from "drizzle-orm/pg-core";
import { createInsertSchema, createSelectSchema } from "drizzle-zod";
import { z } from "zod/v4";

export interface UserSettings {
  timezone: string;
  notifications: {
    emailAlerts: boolean;
    emailDigest: boolean;
    slackIntegration: boolean;
    criticalOnly: boolean;
    newAlerts: boolean;
    assignedAlerts: boolean;
    ruleMatches: boolean;
    weeklyReport: boolean;
  };
  security: {
    mfaEnabled: boolean;
    sessionTimeout: number;
  };
}

export const DEFAULT_USER_SETTINGS: UserSettings = {
  timezone: "UTC",
  notifications: {
    emailAlerts: true,
    emailDigest: false,
    slackIntegration: false,
    criticalOnly: false,
    newAlerts: true,
    assignedAlerts: true,
    ruleMatches: false,
    weeklyReport: true,
  },
  security: {
    mfaEnabled: false,
    sessionTimeout: 8,
  },
};

export const roleEnum = pgEnum("user_role", [
  "admin",
  "soc_manager",
  "detection_engineer",
  "soc_l2",
  "soc_l1",
  "viewer",
]);
export const userStatusEnum = pgEnum("user_status", ["active", "inactive", "locked"]);

export const usersTable = pgTable("users", {
  id: uuid("id").primaryKey().defaultRandom(),
  username: text("username").notNull().unique(),
  email: text("email").notNull().unique(),
  passwordHash: text("password_hash").notNull(),
  role: roleEnum("role").notNull().default("soc_l1"),
  status: userStatusEnum("status").notNull().default("active"),
  displayName: text("display_name"),
  failedLoginAttempts: integer("failed_login_attempts").notNull().default(0),
  lockedUntil: timestamp("locked_until"),
  lastLoginAt: timestamp("last_login_at"),
  jobTitle: text("job_title"),
  settings: jsonb("settings").$type<UserSettings>(),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
});

export const insertUserSchema = createInsertSchema(usersTable).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
  passwordHash: true,
  failedLoginAttempts: true,
  lockedUntil: true,
  lastLoginAt: true,
}).extend({
  password: z.string().min(8),
});

export const selectUserSchema = createSelectSchema(usersTable).omit({ passwordHash: true });

export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof usersTable.$inferSelect;
export type SafeUser = Omit<User, "passwordHash">;
export type UserRole =
  | "admin"
  | "soc_manager"
  | "detection_engineer"
  | "soc_l2"
  | "soc_l1"
  | "viewer";
