import { db, usersTable, apiKeysTable, DEFAULT_USER_SETTINGS } from "../../db";
import type { UserSettings } from "../../db";
import { eq, and } from "drizzle-orm";
import bcrypt from "bcryptjs";
import crypto from "crypto";

export async function getProfile(userId: string) {
  const [user] = await db
    .select({
      id: usersTable.id,
      username: usersTable.username,
      email: usersTable.email,
      role: usersTable.role,
      displayName: usersTable.displayName,
      jobTitle: usersTable.jobTitle,
      lastLoginAt: usersTable.lastLoginAt,
      createdAt: usersTable.createdAt,
    })
    .from(usersTable)
    .where(eq(usersTable.id, userId))
    .limit(1);
  return user ?? null;
}

export async function updateProfile(userId: string, data: { displayName?: string; jobTitle?: string }) {
  const [user] = await db
    .update(usersTable)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(usersTable.id, userId))
    .returning({
      id: usersTable.id,
      username: usersTable.username,
      email: usersTable.email,
      role: usersTable.role,
      displayName: usersTable.displayName,
      jobTitle: usersTable.jobTitle,
    });
  return user ?? null;
}

export async function changePassword(userId: string, currentPassword: string, newPassword: string) {
  const [user] = await db.select().from(usersTable).where(eq(usersTable.id, userId)).limit(1);
  if (!user) return { success: false, error: "User not found" };

  const valid = await bcrypt.compare(currentPassword, user.passwordHash);
  if (!valid) return { success: false, error: "Current password is incorrect" };

  if (newPassword.length < 8) return { success: false, error: "Password must be at least 8 characters" };

  const passwordHash = await bcrypt.hash(newPassword, 12);
  await db.update(usersTable).set({ passwordHash, updatedAt: new Date() }).where(eq(usersTable.id, userId));
  return { success: true };
}

export async function getSettings(userId: string): Promise<UserSettings> {
  const [user] = await db.select({ settings: usersTable.settings }).from(usersTable).where(eq(usersTable.id, userId)).limit(1);
  return user?.settings ?? DEFAULT_USER_SETTINGS;
}

export async function updateSettings(userId: string, patch: Partial<UserSettings>): Promise<UserSettings> {
  const current = await getSettings(userId);
  const merged: UserSettings = {
    timezone: patch.timezone ?? current.timezone,
    notifications: { ...current.notifications, ...(patch.notifications ?? {}) },
    security: { ...current.security, ...(patch.security ?? {}) },
  };
  await db.update(usersTable).set({ settings: merged, updatedAt: new Date() }).where(eq(usersTable.id, userId));
  return merged;
}

export async function listApiKeys(userId: string) {
  return db
    .select({
      id: apiKeysTable.id,
      name: apiKeysTable.name,
      keyPrefix: apiKeysTable.keyPrefix,
      scopes: apiKeysTable.scopes,
      lastUsedAt: apiKeysTable.lastUsedAt,
      createdAt: apiKeysTable.createdAt,
    })
    .from(apiKeysTable)
    .where(eq(apiKeysTable.userId, userId));
}

export async function createApiKey(userId: string, name: string, scopes: string[]) {
  const rawKey = `sk_${crypto.randomBytes(24).toString("hex")}`;
  const keyPrefix = rawKey.slice(0, 10);
  const keyHash = await bcrypt.hash(rawKey, 10);

  const [key] = await db
    .insert(apiKeysTable)
    .values({ userId, name, keyHash, keyPrefix, scopes })
    .returning({
      id: apiKeysTable.id,
      name: apiKeysTable.name,
      keyPrefix: apiKeysTable.keyPrefix,
      scopes: apiKeysTable.scopes,
      createdAt: apiKeysTable.createdAt,
    });

  return { ...key, rawKey };
}

export async function deleteApiKey(userId: string, keyId: string) {
  const result = await db
    .delete(apiKeysTable)
    .where(and(eq(apiKeysTable.id, keyId), eq(apiKeysTable.userId, userId)))
    .returning({ id: apiKeysTable.id });
  return result.length > 0;
}
