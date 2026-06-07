import bcrypt from "bcryptjs";
import { db, usersTable } from "../../db";
import { eq } from "drizzle-orm";
import { signAccessToken, signRefreshToken, verifyRefreshToken, type JwtPayload } from "../../lib/jwt";
import { permissionEngine } from "../../lib/permission-engine";

const SALT_ROUNDS = 12;
const MAX_FAILED_ATTEMPTS = 5;
const LOCK_DURATION_MS = 15 * 60 * 1000;

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, SALT_ROUNDS);
}

export async function login(identifier: string, password: string) {
  const [user] = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.email, identifier))
    .limit(1);

  if (!user) {
    const [byUsername] = await db
      .select()
      .from(usersTable)
      .where(eq(usersTable.username, identifier))
      .limit(1);

    if (!byUsername) {
      throw new Error("Invalid credentials");
    }
    return performLogin(byUsername, password);
  }

  return performLogin(user, password);
}

async function performLogin(user: typeof usersTable.$inferSelect, password: string) {
  if (user.status === "inactive") {
    throw new Error("Account is deactivated");
  }

  if (user.status === "locked" && user.lockedUntil && user.lockedUntil > new Date()) {
    const remaining = Math.ceil((user.lockedUntil.getTime() - Date.now()) / 60000);
    throw new Error(`Account locked. Try again in ${remaining} minutes`);
  }

  const isValid = await bcrypt.compare(password, user.passwordHash);

  if (!isValid) {
    const attempts = user.failedLoginAttempts + 1;
    const updates: Partial<typeof usersTable.$inferInsert> = {
      failedLoginAttempts: attempts,
    };

    if (attempts >= MAX_FAILED_ATTEMPTS) {
      updates.status = "locked";
      updates.lockedUntil = new Date(Date.now() + LOCK_DURATION_MS);
    }

    await db.update(usersTable).set(updates).where(eq(usersTable.id, user.id));
    throw new Error("Invalid credentials");
  }

  await db.update(usersTable).set({
    failedLoginAttempts: 0,
    status: user.status === "locked" ? "active" : user.status,
    lockedUntil: null,
    lastLoginAt: new Date(),
    updatedAt: new Date(),
  }).where(eq(usersTable.id, user.id));

  // Resolve DB-driven RBAC context (roles, permissions, priority)
  const userCtx = await permissionEngine.resolveUserContext(user.id);

  const payload: JwtPayload = {
    userId: user.id,
    username: user.username,
    email: user.email,
    role: user.role, // legacy single-role field
    displayName: user.displayName,
    roles: userCtx?.roles,
    primaryRole: userCtx?.primaryRole,
    effectivePriority: userCtx?.effectivePriority,
    permissions: userCtx?.permissions,
  };

  return {
    accessToken: signAccessToken(payload),
    refreshToken: signRefreshToken(payload),
    user: { ...payload },
  };
}

export async function refresh(refreshToken: string) {
  const payload = verifyRefreshToken(refreshToken);

  const [user] = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.id, payload.userId))
    .limit(1);

  if (!user || user.status !== "active") {
    throw new Error("User not found or inactive");
  }

  // Resolve DB-driven RBAC context on refresh
  const userCtx = await permissionEngine.resolveUserContext(user.id);

  const newPayload: JwtPayload = {
    userId: user.id,
    username: user.username,
    email: user.email,
    role: user.role, // legacy
    displayName: user.displayName,
    roles: userCtx?.roles,
    primaryRole: userCtx?.primaryRole,
    effectivePriority: userCtx?.effectivePriority,
    permissions: userCtx?.permissions,
  };

  return {
    accessToken: signAccessToken(newPayload),
    refreshToken: signRefreshToken(newPayload),
    user: { ...newPayload },
  };
}
