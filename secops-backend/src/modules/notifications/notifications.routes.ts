import { Router } from "express";
import { requireAuth } from "../../middlewares/auth.middleware";
import { db } from "../../db";
import { notificationsTable } from "../../db/schema";
import { eq, desc, and, sql } from "drizzle-orm";

const router = Router();

// GET /api/notifications - list user's notifications
router.get("/notifications", requireAuth, async (req, res) => {
  try {
    const userId = req.user!.userId;
    const limit = Math.min(Number(req.query.limit) || 30, 100);
    const unreadOnly = req.query.unreadOnly === "true";

    const conditions = [eq(notificationsTable.userId, userId)];
    if (unreadOnly) conditions.push(eq(notificationsTable.read, false));

    const notifications = await db
      .select()
      .from(notificationsTable)
      .where(and(...conditions))
      .orderBy(desc(notificationsTable.createdAt))
      .limit(limit);

    const unreadResult = await db
      .select({ count: sql<number>`count(*)::int` })
      .from(notificationsTable)
      .where(and(eq(notificationsTable.userId, userId), eq(notificationsTable.read, false)));

    const unreadCount = unreadResult[0]?.count ?? 0;

    res.json({ notifications, unreadCount });
  } catch (err: any) {
    res.status(500).json({ error: "Failed to fetch notifications", details: err.message });
  }
});

// PATCH /api/notifications/:id/read - mark single as read
router.patch("/notifications/:id/read", requireAuth, async (req, res) => {
  try {
    const userId = req.user!.userId;
    const id = req.params.id as string;

    const result = await db
      .update(notificationsTable)
      .set({ read: true })
      .where(and(eq(notificationsTable.id, id), eq(notificationsTable.userId, userId)))
      .returning();

    if (result.length === 0) {
      res.status(404).json({ error: "Notification not found" });
      return;
    }

    res.json({ notification: result[0] });
  } catch (err: any) {
    res.status(500).json({ error: "Failed to mark notification read", details: err.message });
  }
});

// POST /api/notifications/read-all - mark all as read
router.post("/notifications/read-all", requireAuth, async (req, res) => {
  try {
    const userId = req.user!.userId;

    const result = await db
      .update(notificationsTable)
      .set({ read: true })
      .where(and(eq(notificationsTable.userId, userId), eq(notificationsTable.read, false)))
      .returning();

    res.json({ updated: result.length });
  } catch (err: any) {
    res.status(500).json({ error: "Failed to mark all read", details: err.message });
  }
});

// DELETE /api/notifications/:id - delete single
router.delete("/notifications/:id", requireAuth, async (req, res) => {
  try {
    const userId = req.user!.userId;
    const id = req.params.id as string;

    const result = await db
      .delete(notificationsTable)
      .where(and(eq(notificationsTable.id, id), eq(notificationsTable.userId, userId)))
      .returning();

    if (result.length === 0) {
      res.status(404).json({ error: "Notification not found" });
      return;
    }

    res.json({ deleted: true });
  } catch (err: any) {
    res.status(500).json({ error: "Failed to delete notification", details: err.message });
  }
});

export default router;
