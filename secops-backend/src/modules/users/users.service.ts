import { db, usersTable } from "../../db";
import { eq, and, ilike, sql } from "drizzle-orm";
import { hashPassword } from "../auth/auth.service";
import type { UserRole } from "../../db";
import { userRolesTable } from "../../db/schema/user-roles";
import { rolesTable } from "../../db/schema/roles";
import { permissionEngine } from "../../lib/permission-engine";

const userColumns = {
  id: usersTable.id,
  username: usersTable.username,
  email: usersTable.email,
  role: usersTable.role,
  status: usersTable.status,
  displayName: usersTable.displayName,
  lastLoginAt: usersTable.lastLoginAt,
  createdAt: usersTable.createdAt,
  updatedAt: usersTable.updatedAt,
};

export async function getUsers(filters: { search?: string; role?: string; status?: string } = {}) {
  const conditions: any[] = [];
  if (filters.role) conditions.push(eq(usersTable.role, filters.role as any));
  if (filters.status) conditions.push(eq(usersTable.status, filters.status as any));
  if (filters.search) {
    conditions.push(
      sql`(${usersTable.username} ilike ${"%" + filters.search + "%"} OR ${usersTable.email} ilike ${"%" + filters.search + "%"} OR ${usersTable.displayName} ilike ${"%" + filters.search + "%"})`
    );
  }
  const where = conditions.length > 0 ? and(...conditions) : undefined;
  return db.select(userColumns).from(usersTable).where(where).orderBy(usersTable.createdAt);
}

export async function getUserById(id: string) {
  const [user] = await db.select(userColumns).from(usersTable).where(eq(usersTable.id, id)).limit(1);
  return user ?? null;
}

export async function getActiveAnalysts() {
  return db.select(userColumns).from(usersTable)
    .where(and(eq(usersTable.status, "active")))
    .orderBy(usersTable.role, usersTable.displayName);
}

export async function createUser(data: {
  username: string;
  email: string;
  password: string;
  role: UserRole;
  displayName?: string;
}) {
  const passwordHash = await hashPassword(data.password);
  const [user] = await db.insert(usersTable).values({
    username: data.username,
    email: data.email,
    passwordHash,
    role: data.role,
    displayName: data.displayName ?? data.username,
    status: "active",
  }).returning({
    id: usersTable.id,
    username: usersTable.username,
    email: usersTable.email,
    role: usersTable.role,
    status: usersTable.status,
    displayName: usersTable.displayName,
    createdAt: usersTable.createdAt,
  });
  return user;
}

export async function updateUser(id: string, data: {
  role?: UserRole;
  status?: "active" | "inactive" | "locked";
  displayName?: string;
}) {
  const [user] = await db.update(usersTable)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(usersTable.id, id))
    .returning({
      id: usersTable.id,
      username: usersTable.username,
      email: usersTable.email,
      role: usersTable.role,
      status: usersTable.status,
      displayName: usersTable.displayName,
    });
  return user ?? null;
}

export async function resetUserPassword(id: string, newPassword: string) {
  const passwordHash = await hashPassword(newPassword);
  await db.update(usersTable)
    .set({ passwordHash, failedLoginAttempts: 0, status: "active", lockedUntil: null, updatedAt: new Date() })
    .where(eq(usersTable.id, id));
}

// ─── DB-Driven Role Assignment ───────────────────────────────────────────────

export async function getUserRoles(userId: string) {
  return db.select({
    roleId: userRolesTable.roleId,
    roleName: rolesTable.name,
    displayName: rolesTable.displayName,
    priority: rolesTable.priority,
    isPrimary: userRolesTable.isPrimary,
  })
    .from(userRolesTable)
    .innerJoin(rolesTable, eq(userRolesTable.roleId, rolesTable.id))
    .where(eq(userRolesTable.userId, userId))
    .orderBy(rolesTable.priority);
}

export async function assignRole(userId: string, roleId: string, assignedBy: string, isPrimary = false) {
  // If setting as primary, clear existing primary first
  if (isPrimary) {
    await db.update(userRolesTable)
      .set({ isPrimary: false })
      .where(eq(userRolesTable.userId, userId));
  }

  await db.insert(userRolesTable)
    .values({ userId, roleId, assignedBy, isPrimary })
    .onConflictDoNothing();

  if (isPrimary) {
    await db.update(userRolesTable)
      .set({ isPrimary: true })
      .where(and(
        eq(userRolesTable.userId, userId),
        eq(userRolesTable.roleId, roleId),
      ));
  }

  // Invalidate cached permission context
  await permissionEngine.invalidateUserContext(userId);
}

export async function removeRole(userId: string, roleId: string) {
  await db.delete(userRolesTable)
    .where(and(
      eq(userRolesTable.userId, userId),
      eq(userRolesTable.roleId, roleId),
    ));
  await permissionEngine.invalidateUserContext(userId);
}

export async function setUserRoles(userId: string, roleIds: string[], primaryRoleId: string | null, assignedBy: string) {
  // Replace all roles atomically
  await db.delete(userRolesTable).where(eq(userRolesTable.userId, userId));
  if (roleIds.length > 0) {
    await db.insert(userRolesTable).values(
      roleIds.map(roleId => ({
        userId,
        roleId,
        assignedBy,
        isPrimary: roleId === primaryRoleId,
      })),
    );
  }
  await permissionEngine.invalidateUserContext(userId);
}
