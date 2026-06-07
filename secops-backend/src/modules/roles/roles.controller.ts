import type { Request, Response } from "express";
import * as rolesService from "./roles.service";
import { auditService } from "../../lib/audit";

export async function listRoles(req: Request, res: Response): Promise<void> {
  const roles = await rolesService.getRoles();
  res.json({ roles });
}

export async function getRole(req: Request, res: Response): Promise<void> {
  const id = req.params.id as string;
  const role = await rolesService.getRoleById(id);
  if (!role) { res.status(404).json({ error: "Role not found" }); return; }

  const perms = await rolesService.getRolePermissions(role.id);
  res.json({ role, permissions: perms.map(p => p.permission) });
}

export async function createRole(req: Request, res: Response): Promise<void> {
  const { name, displayName, description, priority, color } = req.body;
  if (!name || priority == null) {
    res.status(400).json({ error: "name and priority are required" });
    return;
  }
  try {
    const role = await rolesService.createRole({ name, displayName, description, priority, color });
    await auditService.log(req, req.userContext ?? null, {
      action: "role_created",
      entityType: "role",
      entityId: role.id,
      newState: role as unknown as Record<string, unknown>,
    });
    res.status(201).json({ role });
  } catch (err: any) {
    if (err.code === "23505") {
      res.status(409).json({ error: "Role name or priority already exists" });
    } else {
      res.status(500).json({ error: "Failed to create role" });
    }
  }
}

export async function updateRole(req: Request, res: Response): Promise<void> {
  const id = req.params.id as string;
  const existing = await rolesService.getRoleById(id);
  if (!existing) { res.status(404).json({ error: "Role not found" }); return; }

  const { displayName, description, priority, color } = req.body;
  const role = await rolesService.updateRole(id, { displayName, description, priority, color });

  await auditService.log(req, req.userContext ?? null, {
    action: "role_updated",
    entityType: "role",
    entityId: id,
    previousState: existing as unknown as Record<string, unknown>,
    newState: role as unknown as Record<string, unknown>,
  });
  res.json({ role });
}

export async function deleteRole(req: Request, res: Response): Promise<void> {
  const id = req.params.id as string;
  try {
    const role = await rolesService.deleteRole(id);
    if (!role) { res.status(404).json({ error: "Role not found" }); return; }

    await auditService.log(req, req.userContext ?? null, {
      action: "role_deleted",
      entityType: "role",
      entityId: id,
      previousState: role as unknown as Record<string, unknown>,
    });
    res.json({ message: "Role deleted" });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
}

export async function setPermissions(req: Request, res: Response): Promise<void> {
  const { permissionIds } = req.body;
  if (!Array.isArray(permissionIds)) {
    res.status(400).json({ error: "permissionIds must be an array" });
    return;
  }

  const id = req.params.id as string;
  const role = await rolesService.getRoleById(id);
  if (!role) { res.status(404).json({ error: "Role not found" }); return; }

  await rolesService.setRolePermissions(id, permissionIds);

  await auditService.log(req, req.userContext ?? null, {
    action: "role_permission_changed",
    entityType: "role",
    entityId: id,
    newState: { permissionIds } as unknown as Record<string, unknown>,
  });
  res.json({ message: "Permissions updated" });
}

export async function listPermissions(req: Request, res: Response): Promise<void> {
  const permissions = await rolesService.getPermissions();
  res.json({ permissions });
}

export async function seedHandler(req: Request, res: Response): Promise<void> {
  await rolesService.seedRolesAndPermissions();
  res.json({ message: "Roles and permissions seeded" });
}
