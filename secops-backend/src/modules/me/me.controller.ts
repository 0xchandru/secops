import type { Request, Response } from "express";
import * as meService from "./me.service";
import { logAuditEvent } from "../../lib/audit";

export async function getProfile(req: Request, res: Response): Promise<void> {
  const profile = await meService.getProfile(req.user!.userId);
  if (!profile) { res.status(404).json({ error: "User not found" }); return; }
  res.json({ profile });
}

export async function updateProfile(req: Request, res: Response): Promise<void> {
  const { displayName, jobTitle } = req.body;
  if (!displayName && !jobTitle) { res.status(400).json({ error: "At least one field required" }); return; }
  const profile = await meService.updateProfile(req.user!.userId, { displayName, jobTitle });
  await logAuditEvent(req, "me.profile_update", { resource: "users", resourceId: req.user!.userId });
  res.json({ profile });
}

export async function changePassword(req: Request, res: Response): Promise<void> {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) {
    res.status(400).json({ error: "currentPassword and newPassword are required" });
    return;
  }
  const result = await meService.changePassword(req.user!.userId, currentPassword, newPassword);
  if (!result.success) { res.status(400).json({ error: result.error }); return; }
  await logAuditEvent(req, "me.password_change", { resource: "users", resourceId: req.user!.userId });
  res.json({ message: "Password updated successfully" });
}

export async function getSettings(req: Request, res: Response): Promise<void> {
  const settings = await meService.getSettings(req.user!.userId);
  res.json({ settings });
}

export async function updateSettings(req: Request, res: Response): Promise<void> {
  const settings = await meService.updateSettings(req.user!.userId, req.body);
  res.json({ settings });
}

export async function listApiKeys(req: Request, res: Response): Promise<void> {
  const keys = await meService.listApiKeys(req.user!.userId);
  res.json({ keys });
}

export async function createApiKey(req: Request, res: Response): Promise<void> {
  const { name, scopes } = req.body;
  if (!name?.trim()) { res.status(400).json({ error: "Key name is required" }); return; }
  const key = await meService.createApiKey(req.user!.userId, name.trim(), scopes ?? ["read:alerts"]);
  await logAuditEvent(req, "me.api_key_create", { resource: "api_keys", metadata: { name } });
  res.status(201).json({ key });
}

export async function deleteApiKey(req: Request, res: Response): Promise<void> {
  const keyId = req.params.keyId as string;
  const deleted = await meService.deleteApiKey(req.user!.userId, keyId);
  if (!deleted) { res.status(404).json({ error: "API key not found" }); return; }
  await logAuditEvent(req, "me.api_key_delete", { resource: "api_keys", resourceId: keyId });
  res.json({ message: "API key deleted" });
}
