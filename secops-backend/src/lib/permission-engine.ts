import { eq, inArray } from "drizzle-orm";
import { db } from "../db";
import {
  rolesTable,
  permissionsTable,
  rolePermissionsTable,
  userRolesTable,
} from "../db/schema";
import { cacheGet, cacheSet, cacheDel } from "./redis";
import { logger } from "./logger";

/** Hydrated user context attached to req.user after auth middleware. */
export interface UserContext {
  userId: string;
  username: string;
  email: string;
  displayName: string | null;
  /** All role names the user holds. */
  roles: string[];
  /** The primary role name. */
  primaryRole: string;
  /** Effective priority — lowest value (highest authority) across all roles. */
  effectivePriority: number;
  /** All permission codes merged from every assigned role. */
  permissions: string[];
}

const CACHE_TTL = 300; // 5 minutes
const CACHE_PREFIX = "perm:user:";

/**
 * PermissionEngine — single source of truth for authorization.
 *
 * Resolves a user's roles, priority, and permissions from the database,
 * caches the result in Redis, and exposes check helpers.
 */
export class PermissionEngine {
  // ─── Context resolution ──────────────────────────────────────────────

  /**
   * Build the full UserContext for a given userId.
   * Checks Redis cache first; falls back to DB query.
   */
  async resolveUserContext(userId: string): Promise<UserContext | null> {
    // 1. Try cache
    const cacheKey = `${CACHE_PREFIX}${userId}`;
    const cached = await cacheGet<UserContext>(cacheKey);
    if (cached) return cached;

    // 2. Load from DB
    try {
      const context = await this.loadContextFromDb(userId);
      if (!context) return null;

      // 3. Cache
      await cacheSet(cacheKey, context, CACHE_TTL);
      return context;
    } catch (err) {
      logger.error({ err, userId }, "PermissionEngine: failed to resolve user context");
      return null;
    }
  }

  /**
   * Invalidate the cached context for a user (call after role/permission changes).
   */
  async invalidateUserContext(userId: string): Promise<void> {
    await cacheDel(`${CACHE_PREFIX}${userId}`);
  }

  // ─── Permission checks ──────────────────────────────────────────────

  /** Does the user have the exact permission code? */
  hasPermission(ctx: UserContext, permission: string): boolean {
    return ctx.permissions.includes(permission);
  }

  /** Does the user have ALL of the listed permissions? */
  hasAllPermissions(ctx: UserContext, permissions: string[]): boolean {
    return permissions.every((p) => ctx.permissions.includes(p));
  }

  /** Does the user have ANY of the listed permissions? */
  hasAnyPermission(ctx: UserContext, permissions: string[]): boolean {
    return permissions.some((p) => ctx.permissions.includes(p));
  }

  /**
   * Priority-based override check.
   * Returns true when `actorPriority` is strictly lower (= higher authority)
   * than `targetPriority`, meaning the actor outranks the target.
   */
  canOverride(actorPriority: number, targetPriority: number): boolean {
    return actorPriority < targetPriority;
  }

  /**
   * Check if user has at least the given priority level.
   * Lower numbers = higher authority, so user priority must be <= requiredPriority.
   */
  hasMinPriority(ctx: UserContext, requiredPriority: number): boolean {
    return ctx.effectivePriority <= requiredPriority;
  }

  // ─── Internal DB load ────────────────────────────────────────────────

  private async loadContextFromDb(userId: string): Promise<UserContext | null> {
    // Fetch user's assigned roles via junction table
    const userRoleRows = await db
      .select({
        roleId: userRolesTable.roleId,
        isPrimary: userRolesTable.isPrimary,
        roleName: rolesTable.name,
        rolePriority: rolesTable.priority,
      })
      .from(userRolesTable)
      .innerJoin(rolesTable, eq(userRolesTable.roleId, rolesTable.id))
      .where(eq(userRolesTable.userId, userId));

    if (userRoleRows.length === 0) return null;

    // Determine primary role and effective priority
    const primary = userRoleRows.find((r: typeof userRoleRows[0]) => r.isPrimary) ?? userRoleRows[0]!;
    const effectivePriority = Math.min(...userRoleRows.map((r: typeof userRoleRows[0]) => r.rolePriority));
    const roleNames = userRoleRows.map((r: typeof userRoleRows[0]) => r.roleName);
    const roleIds = userRoleRows.map((r: typeof userRoleRows[0]) => r.roleId);

    // Fetch merged permissions for all roles
    const permRows = await db
      .select({ code: permissionsTable.code })
      .from(rolePermissionsTable)
      .innerJoin(permissionsTable, eq(rolePermissionsTable.permissionId, permissionsTable.id))
      .where(inArray(rolePermissionsTable.roleId, roleIds));

    const permissions = [...new Set(permRows.map((r: typeof permRows[0]) => r.code))];

    // Fetch basic user data
    const { usersTable } = await import("../db/schema/users");
    const [user] = await db
      .select({
        username: usersTable.username,
        email: usersTable.email,
        displayName: usersTable.displayName,
      })
      .from(usersTable)
      .where(eq(usersTable.id, userId))
      .limit(1);

    if (!user) return null;

    return {
      userId,
      username: user.username,
      email: user.email,
      displayName: user.displayName,
      roles: roleNames,
      primaryRole: primary.roleName,
      effectivePriority,
      permissions,
    };
  }
}

/** Singleton instance used across the application. */
export const permissionEngine = new PermissionEngine();
