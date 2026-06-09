import { Router } from "express";
import type { Request, Response } from "express";
import { requireAuth, requireAuthOrApiKey } from "../../middlewares/auth.middleware";
import { can } from "../../middlewares/rbac.middleware";
import { db, forwardersTable } from "../../db";
import { eq, desc, sql } from "drizzle-orm";

const router = Router();

// POST /forwarders/heartbeat — upsert forwarder registration + last-seen stats
// Auth: Bearer token (API key or session JWT)
router.post("/forwarders/heartbeat", requireAuthOrApiKey, async (req: Request, res: Response) => {
  const { name, host, version, totalEventsSent, eps, monitors } = req.body as {
    name?: string;
    host?: string;
    version?: string;
    totalEventsSent?: number;
    eps?: number;
    monitors?: unknown[];
  };

  if (!name || !host) {
    res.status(400).json({ error: "name and host are required" });
    return;
  }

  const existing = await db
    .select({ id: forwardersTable.id })
    .from(forwardersTable)
    .where(eq(forwardersTable.name, name))
    .limit(1);

  const now = new Date();

  if (existing.length > 0) {
    await db
      .update(forwardersTable)
      .set({
        host: host ?? "unknown",
        version: version ?? "1.0.0",
        lastHeartbeatAt: now,
        totalEventsSent: totalEventsSent ?? 0,
        eps: eps ?? 0,
        monitors: (monitors ?? []) as any,
        status: "active",
        updatedAt: now,
      })
      .where(eq(forwardersTable.name, name));
  } else {
    await db.insert(forwardersTable).values({
      name,
      host: host ?? "unknown",
      version: version ?? "1.0.0",
      lastHeartbeatAt: now,
      totalEventsSent: totalEventsSent ?? 0,
      eps: eps ?? 0,
      monitors: (monitors ?? []) as any,
      status: "active",
    });
  }

  res.json({ ok: true });
});

// GET /forwarders — list all registered forwarders
router.get("/forwarders", requireAuth, can("ingest:write"), async (_req: Request, res: Response) => {
  const rows = await db
    .select()
    .from(forwardersTable)
    .orderBy(desc(forwardersTable.lastHeartbeatAt));

  const now = Date.now();
  const forwarders = rows.map(f => ({
    ...f,
    online: f.lastHeartbeatAt ? now - f.lastHeartbeatAt.getTime() < 120_000 : false,
  }));

  res.json({ forwarders, total: forwarders.length });
});

// DELETE /forwarders/:id — remove a forwarder record
router.delete("/forwarders/:id", requireAuth, can("ingest:write"), async (req: Request, res: Response) => {
  const id = req.params.id as string;
  await db.delete(forwardersTable).where(eq(forwardersTable.id, id));
  res.json({ ok: true });
});

export default router;
