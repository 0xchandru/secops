import { db } from "../../db";
import {
  rolesTable, permissionsTable, rolePermissionsTable,
  type InsertRole, type InsertPermission,
} from "../../db/schema/roles";
import { userRolesTable } from "../../db/schema/user-roles";
import { eq, and, inArray } from "drizzle-orm";
import { permissionEngine } from "../../lib/permission-engine";

// ─── Roles ───────────────────────────────────────────────────────────────────

export async function getRoles() {
  return db.select().from(rolesTable).orderBy(rolesTable.priority);
}

export async function getRoleById(id: string) {
  const [role] = await db.select().from(rolesTable).where(eq(rolesTable.id, id)).limit(1);
  return role ?? null;
}

export async function getRoleByName(name: string) {
  const [role] = await db.select().from(rolesTable).where(eq(rolesTable.name, name)).limit(1);
  return role ?? null;
}

export async function createRole(data: InsertRole) {
  const [role] = await db.insert(rolesTable).values(data).returning();
  return role;
}

export async function updateRole(id: string, data: Partial<Omit<InsertRole, "id">>) {
  const [role] = await db.update(rolesTable)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(rolesTable.id, id))
    .returning();
  return role ?? null;
}

export async function deleteRole(id: string) {
  const existing = await getRoleById(id);
  if (!existing) return null;
  if (existing.isSystem) throw new Error("Cannot delete system role");
  await db.delete(rolesTable).where(eq(rolesTable.id, id));
  return existing;
}

// ─── Permissions ─────────────────────────────────────────────────────────────

export async function getPermissions() {
  return db.select().from(permissionsTable).orderBy(permissionsTable.resource, permissionsTable.action);
}

export async function createPermission(data: InsertPermission) {
  const [perm] = await db.insert(permissionsTable).values(data).returning();
  return perm;
}

// ─── Role–Permission Linking ─────────────────────────────────────────────────

export async function getRolePermissions(roleId: string) {
  return db.select({ permission: permissionsTable })
    .from(rolePermissionsTable)
    .innerJoin(permissionsTable, eq(rolePermissionsTable.permissionId, permissionsTable.id))
    .where(eq(rolePermissionsTable.roleId, roleId));
}

export async function setRolePermissions(roleId: string, permissionIds: string[]) {
  // Replace all permissions for a role atomically
  await db.delete(rolePermissionsTable).where(eq(rolePermissionsTable.roleId, roleId));
  if (permissionIds.length > 0) {
    await db.insert(rolePermissionsTable).values(
      permissionIds.map(permissionId => ({ roleId, permissionId })),
    );
  }
  // Invalidate cached contexts for all users with this role
  const userRoles = await db.select({ userId: userRolesTable.userId })
    .from(userRolesTable)
    .where(eq(userRolesTable.roleId, roleId));
  for (const ur of userRoles) {
    await permissionEngine.invalidateUserContext(ur.userId);
  }
}

export async function addPermissionToRole(roleId: string, permissionId: string) {
  await db.insert(rolePermissionsTable)
    .values({ roleId, permissionId })
    .onConflictDoNothing();
}

export async function removePermissionFromRole(roleId: string, permissionId: string) {
  await db.delete(rolePermissionsTable)
    .where(and(
      eq(rolePermissionsTable.roleId, roleId),
      eq(rolePermissionsTable.permissionId, permissionId),
    ));
}

// ─── Seed Default Roles & Permissions ────────────────────────────────────────

const DEFAULT_PERMISSIONS: InsertPermission[] = [
  { code: "alerts:view",    resource: "alerts",  action: "view",    description: "View alerts" },
  { code: "alerts:triage",  resource: "alerts",  action: "triage",  description: "Triage alerts (investigate, reopen)" },
  { code: "alerts:assign",  resource: "alerts",  action: "assign",  description: "Assign/unassign alerts" },
  { code: "alerts:close",   resource: "alerts",  action: "close",   description: "Close alerts (resolve, false positive, escalate)" },
  { code: "alerts:note",    resource: "alerts",  action: "note",    description: "Add timeline notes" },
  { code: "rules:view",     resource: "rules",   action: "view",    description: "View detection rules" },
  { code: "rules:toggle",   resource: "rules",   action: "toggle",  description: "Enable/disable rules" },
  { code: "rules:write",    resource: "rules",   action: "write",   description: "Create and edit rules" },
  { code: "rules:delete",   resource: "rules",   action: "delete",  description: "Delete rules" },
  { code: "rules:test",     resource: "rules",   action: "test",    description: "Test rules" },
  { code: "ingest:write",   resource: "ingest",  action: "write",   description: "Ingest logs" },
  { code: "ingest:pending", resource: "ingest",  action: "pending", description: "Reprocess pending logs" },
  { code: "users:manage",   resource: "users",   action: "manage",  description: "Manage users and roles" },
  { code: "audit:view",     resource: "audit",   action: "view",    description: "View audit logs" },
  { code: "reports:view",   resource: "reports",  action: "view",    description: "View reports and dashboards" },
];

interface DefaultRole {
  name: string;
  displayName: string;
  description: string;
  priority: number;
  color: string;
  permissions: string[]; // permission codes
}

const DEFAULT_ROLES: DefaultRole[] = [
  {
    name: "admin", displayName: "Administrator", description: "Full system access",
    priority: 0, color: "#dc2626",
    permissions: DEFAULT_PERMISSIONS.map(p => p.code),
  },
  {
    name: "soc_manager", displayName: "SOC Manager", description: "SOC operations management",
    priority: 20, color: "#ea580c",
    permissions: [
      "alerts:view", "alerts:triage", "alerts:assign", "alerts:close", "alerts:note",
      "rules:view", "ingest:write", "ingest:pending", "audit:view", "reports:view",
    ],
  },
  {
    name: "detection_engineer", displayName: "Detection Engineer", description: "Detection rule authoring",
    priority: 30, color: "#7c3aed",
    permissions: [
      "alerts:view", "alerts:note",
      "rules:view", "rules:toggle", "rules:write", "rules:delete", "rules:test",
      "ingest:write", "ingest:pending", "reports:view",
    ],
  },
  {
    name: "soc_l2", displayName: "SOC Analyst L2", description: "Senior analyst with full alert lifecycle",
    priority: 50, color: "#2563eb",
    permissions: [
      "alerts:view", "alerts:triage", "alerts:assign", "alerts:close", "alerts:note",
      "rules:view", "rules:toggle", "rules:write", "rules:test",
      "ingest:write", "ingest:pending", "reports:view",
    ],
  },
  {
    name: "soc_l1", displayName: "SOC Analyst L1", description: "Junior analyst for initial triage",
    priority: 70, color: "#0891b2",
    permissions: [
      "alerts:view", "alerts:triage", "alerts:note",
      "rules:view", "reports:view",
    ],
  },
  {
    name: "viewer", displayName: "Viewer", description: "Read-only access",
    priority: 100, color: "#6b7280",
    permissions: ["alerts:view", "rules:view", "reports:view"],
  },
];

export async function seedRolesAndPermissions() {
  // Upsert permissions
  const permMap = new Map<string, string>(); // code → id
  for (const perm of DEFAULT_PERMISSIONS) {
    const existing = await db.select().from(permissionsTable)
      .where(eq(permissionsTable.code, perm.code)).limit(1);
    if (existing.length > 0) {
      permMap.set(perm.code, existing[0].id);
    } else {
      const [created] = await db.insert(permissionsTable).values(perm).returning();
      permMap.set(perm.code, created.id);
    }
  }

  // Upsert roles + link permissions
  for (const roleDef of DEFAULT_ROLES) {
    let roleId: string;
    const existing = await db.select().from(rolesTable)
      .where(eq(rolesTable.name, roleDef.name)).limit(1);

    if (existing.length > 0) {
      roleId = existing[0].id;
      // Update priority/display if changed
      await db.update(rolesTable).set({
        displayName: roleDef.displayName,
        description: roleDef.description,
        priority: roleDef.priority,
        color: roleDef.color,
        isSystem: true,
        updatedAt: new Date(),
      }).where(eq(rolesTable.id, roleId));
    } else {
      const [created] = await db.insert(rolesTable).values({
        name: roleDef.name,
        displayName: roleDef.displayName,
        description: roleDef.description,
        priority: roleDef.priority,
        color: roleDef.color,
        isSystem: true,
      }).returning();
      roleId = created.id;
    }

    // Set permissions for this role
    const permIds = roleDef.permissions
      .map(code => permMap.get(code))
      .filter((id): id is string => !!id);
    await setRolePermissions(roleId, permIds);
  }
}
