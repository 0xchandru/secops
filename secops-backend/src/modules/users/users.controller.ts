import type { Request, Response } from "express";
import * as usersService from "./users.service";
import { logAuditEvent } from "../../lib/audit";
import { auditService } from "../../lib/audit";
import type { UserRole } from "../../db";

const ROLE_HIERARCHY: Record<UserRole, number> = {
  admin: 6, soc_manager: 5, detection_engineer: 4, soc_l2: 3, soc_l1: 2, viewer: 1,
};

export async function listUsers(req: Request, res: Response): Promise<void> {
  const { search, role, status } = req.query;
  const users = await usersService.getUsers({
    search: search as string,
    role: role as string,
    status: status as string,
  });
  res.json({ users });
}

export async function getUser(req: Request, res: Response): Promise<void> {
  const id = req.params.id as string;
  const user = await usersService.getUserById(id);
  if (!user) { res.status(404).json({ error: "User not found" }); return; }
  res.json({ user });
}

export async function getEscalationTargets(req: Request, res: Response): Promise<void> {
  const currentRole = (req.query.currentRole as UserRole) || req.user!.role;
  const currentLevel = ROLE_HIERARCHY[currentRole] ?? 0;
  const currentUserId = req.user!.userId;
  const users = await usersService.getActiveAnalysts();
  // Return all active analysts (excluding viewers and the requesting user)
  // sorted by role level descending so higher-authority targets appear first
  const targets = users
    .filter(u => u.role !== 'viewer' && u.id !== currentUserId)
    .sort((a, b) => (ROLE_HIERARCHY[b.role as UserRole] ?? 0) - (ROLE_HIERARCHY[a.role as UserRole] ?? 0));
  res.json({ targets });
}

export async function createUser(req: Request, res: Response): Promise<void> {
  const { username, email, password, role, displayName } = req.body;
  if (!username || !email || !password || !role) {
    res.status(400).json({ error: "username, email, password, and role are required" });
    return;
  }
  const validRoles: UserRole[] = ["admin", "soc_manager", "detection_engineer", "soc_l2", "soc_l1", "viewer"];
  if (!validRoles.includes(role)) {
    res.status(400).json({ error: "Invalid role" });
    return;
  }
  // Role hierarchy: can only create users at or below own level
  const actorLevel = ROLE_HIERARCHY[req.user!.role] ?? 0;
  const targetLevel = ROLE_HIERARCHY[role as UserRole] ?? 0;
  if (targetLevel > actorLevel) {
    res.status(403).json({ error: "Cannot create user with role above your own" });
    return;
  }
  try {
    const user = await usersService.createUser({ username, email, password, role, displayName });
    await logAuditEvent(req, "users.create", { resource: "users", resourceId: user.id, metadata: { username, role } });
    res.status(201).json({ user });
  } catch (err: any) {
    if (err.code === "23505") {
      res.status(409).json({ error: "Username or email already exists" });
    } else {
      res.status(500).json({ error: "Failed to create user" });
    }
  }
}

export async function updateUser(req: Request, res: Response): Promise<void> {
  const { role, status, displayName } = req.body;
  // Role hierarchy: can only set role at or below own level
  if (role) {
    const actorLevel = ROLE_HIERARCHY[req.user!.role] ?? 0;
    const targetLevel = ROLE_HIERARCHY[role as UserRole] ?? 0;
    if (targetLevel > actorLevel) {
      res.status(403).json({ error: "Cannot set role above your own" });
      return;
    }
  }
  const id = req.params.id as string;
  const user = await usersService.updateUser(id, { role, status, displayName });
  if (!user) { res.status(404).json({ error: "User not found" }); return; }
  await logAuditEvent(req, "users.update", { resource: "users", resourceId: id, metadata: { role, status } });
  res.json({ user });
}

export async function resetPassword(req: Request, res: Response): Promise<void> {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 8) {
    res.status(400).json({ error: "Password must be at least 8 characters" });
    return;
  }
  const id = req.params.id as string;
  await usersService.resetUserPassword(id, newPassword);
  await logAuditEvent(req, "users.reset_password", { resource: "users", resourceId: id });
  res.json({ message: "Password reset successfully" });
}

// ─── DB-Driven Role Endpoints ────────────────────────────────────────────────

export async function getUserRoles(req: Request, res: Response): Promise<void> {
  const id = req.params.id as string;
  const roles = await usersService.getUserRoles(id);
  res.json({ roles });
}

export async function assignUserRole(req: Request, res: Response): Promise<void> {
  const id = req.params.id as string;
  const { roleId, isPrimary } = req.body;
  if (!roleId) { res.status(400).json({ error: "roleId is required" }); return; }

  const user = await usersService.getUserById(id);
  if (!user) { res.status(404).json({ error: "User not found" }); return; }

  const assignedBy = req.userContext?.userId ?? req.user!.userId;
  await usersService.assignRole(id, roleId, assignedBy, isPrimary);

  await auditService.log(req, req.userContext ?? null, {
    action: "user_role_assigned",
    entityType: "user",
    entityId: id,
    newState: { roleId, isPrimary },
  });
  res.json({ message: "Role assigned" });
}

export async function removeUserRole(req: Request, res: Response): Promise<void> {
  const id = req.params.id as string;
  const roleId = req.params.roleId as string;
  await usersService.removeRole(id, roleId);

  await auditService.log(req, req.userContext ?? null, {
    action: "user_role_removed",
    entityType: "user",
    entityId: id,
    previousState: { roleId },
  });
  res.json({ message: "Role removed" });
}

export async function setUserRoles(req: Request, res: Response): Promise<void> {
  const id = req.params.id as string;
  const { roleIds, primaryRoleId } = req.body;
  if (!Array.isArray(roleIds)) { res.status(400).json({ error: "roleIds must be an array" }); return; }

  const user = await usersService.getUserById(id);
  if (!user) { res.status(404).json({ error: "User not found" }); return; }

  const assignedBy = req.userContext?.userId ?? req.user!.userId;
  const previousRoles = await usersService.getUserRoles(id);

  await usersService.setUserRoles(id, roleIds, primaryRoleId ?? null, assignedBy);

  await auditService.log(req, req.userContext ?? null, {
    action: "user_roles_changed",
    entityType: "user",
    entityId: id,
    previousState: { roles: previousRoles },
    newState: { roleIds, primaryRoleId },
  });
  res.json({ message: "Roles updated" });
}
