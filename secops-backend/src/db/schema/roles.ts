import { pgTable, text, uuid, timestamp, integer, boolean, unique } from "drizzle-orm/pg-core";
import { createInsertSchema, createSelectSchema } from "drizzle-zod";
import { z } from "zod/v4";

/**
 * Roles table — database-driven RBAC with numeric priority (0–100).
 * Priority 0 = highest (admin), 100 = lowest (viewer).
 * Lower number = higher authority.
 */
export const rolesTable = pgTable("roles", {
  id: uuid("id").primaryKey().defaultRandom(),
  name: text("name").notNull().unique(),
  displayName: text("display_name").notNull(),
  description: text("description"),
  priority: integer("priority").notNull(),
  isSystem: boolean("is_system").notNull().default(false),
  color: text("color"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
}, (table) => [
  unique("roles_priority_unique").on(table.priority),
]);

/**
 * Permissions table — granular permission codes (resource:action).
 */
export const permissionsTable = pgTable("permissions", {
  id: uuid("id").primaryKey().defaultRandom(),
  code: text("code").notNull().unique(),
  resource: text("resource").notNull(),
  action: text("action").notNull(),
  description: text("description"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
}, (table) => [
  unique("permissions_resource_action_unique").on(table.resource, table.action),
]);

/**
 * Role-permissions junction — which permissions each role has.
 */
export const rolePermissionsTable = pgTable("role_permissions", {
  id: uuid("id").primaryKey().defaultRandom(),
  roleId: uuid("role_id").notNull().references(() => rolesTable.id, { onDelete: "cascade" }),
  permissionId: uuid("permission_id").notNull().references(() => permissionsTable.id, { onDelete: "cascade" }),
  createdAt: timestamp("created_at").notNull().defaultNow(),
}, (table) => [
  unique("role_permissions_unique").on(table.roleId, table.permissionId),
]);

// ─── Zod Schemas ─────────────────────────────────────────────────────────────

export const insertRoleSchema = createInsertSchema(rolesTable).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const selectRoleSchema = createSelectSchema(rolesTable);

export const insertPermissionSchema = createInsertSchema(permissionsTable).omit({
  id: true,
  createdAt: true,
});

export const selectPermissionSchema = createSelectSchema(permissionsTable);

// ─── Types ───────────────────────────────────────────────────────────────────

export type Role = typeof rolesTable.$inferSelect;
export type InsertRole = z.infer<typeof insertRoleSchema>;
export type Permission = typeof permissionsTable.$inferSelect;
export type InsertPermission = z.infer<typeof insertPermissionSchema>;
export type RolePermission = typeof rolePermissionsTable.$inferSelect;
