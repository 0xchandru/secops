import { pgTable, uuid, timestamp, boolean, unique } from "drizzle-orm/pg-core";
import { usersTable } from "./users.js";
import { rolesTable } from "./roles.js";

/**
 * User-roles junction table — supports multi-role assignment.
 * Each user can have multiple roles; exactly one must be marked isPrimary.
 * The primary role's priority becomes the user's effective priority.
 */
export const userRolesTable = pgTable("user_roles", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: uuid("user_id").notNull().references(() => usersTable.id, { onDelete: "cascade" }),
  roleId: uuid("role_id").notNull().references(() => rolesTable.id, { onDelete: "cascade" }),
  isPrimary: boolean("is_primary").notNull().default(false),
  assignedBy: uuid("assigned_by").references(() => usersTable.id, { onDelete: "set null" }),
  assignedAt: timestamp("assigned_at").notNull().defaultNow(),
}, (table) => [
  unique("user_roles_unique").on(table.userId, table.roleId),
]);

export type UserRoleAssignment = typeof userRolesTable.$inferSelect;
export type InsertUserRoleAssignment = typeof userRolesTable.$inferInsert;
