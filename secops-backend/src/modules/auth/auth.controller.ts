import type { Request, Response } from "express";
import * as authService from "./auth.service";
import { logAuditEvent } from "../../lib/audit";
import { permissionEngine } from "../../lib/permission-engine";

export async function loginHandler(req: Request, res: Response): Promise<void> {
  const { identifier, password } = req.body;

  if (!identifier || !password) {
    res.status(400).json({ error: "Username/email and password are required" });
    return;
  }

  try {
    const result = await authService.login(identifier, password);
    await logAuditEvent(req, "auth.login", {
      resource: "auth",
      metadata: { username: result.user.username },
      success: true,
      userId: result.user.userId,
      username: result.user.username,
    });
    res.json(result);
  } catch (err: any) {
    await logAuditEvent(req, "auth.login_failed", { resource: "auth", metadata: { identifier }, success: false });
    res.status(401).json({ error: err.message ?? "Invalid credentials" });
  }
}

export async function refreshHandler(req: Request, res: Response): Promise<void> {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    res.status(400).json({ error: "Refresh token is required" });
    return;
  }

  try {
    const result = await authService.refresh(refreshToken);
    res.json(result);
  } catch {
    res.status(401).json({ error: "Invalid or expired refresh token" });
  }
}

export async function logoutHandler(req: Request, res: Response): Promise<void> {
  await logAuditEvent(req, "auth.logout", { resource: "auth" });
  res.json({ message: "Logged out successfully" });
}

export async function meHandler(req: Request, res: Response): Promise<void> {
  const userCtx = await permissionEngine.resolveUserContext(req.user!.userId);
  res.json({
    user: {
      ...req.user,
      roles: userCtx?.roles,
      primaryRole: userCtx?.primaryRole,
      effectivePriority: userCtx?.effectivePriority,
      permissions: userCtx?.permissions,
    },
  });
}
