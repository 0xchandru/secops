import { db } from "../db";
import { notificationsTable, usersTable } from "../db/schema";
import { broadcastNotification } from "./websocket";
import { eq, inArray } from "drizzle-orm";

type NotificationType = "alert_created" | "alert_assigned" | "alert_escalated" | "alert_resolved" | "rule_match" | "system";

interface CreateNotificationInput {
  userId: string;
  type: NotificationType;
  title: string;
  message?: string;
  link?: string;
  metadata?: Record<string, unknown>;
}

export async function createNotification(input: CreateNotificationInput): Promise<void> {
  try {
    const [notification] = await db
      .insert(notificationsTable)
      .values({
        userId: input.userId,
        type: input.type,
        title: input.title,
        message: input.message ?? null,
        link: input.link ?? null,
        metadata: input.metadata ?? {},
      })
      .returning();

    broadcastNotification(input.userId, notification);
  } catch {
    // Non-critical — log but don't throw
  }
}

/** Notify all users with a given role (e.g. all soc_manager users for escalations) */
export async function notifyByRole(
  role: string,
  type: NotificationType,
  title: string,
  opts?: { message?: string; link?: string; metadata?: Record<string, unknown> },
): Promise<void> {
  try {
    const users = await db
      .select({ id: usersTable.id })
      .from(usersTable)
      .where(eq(usersTable.role, role as any));

    await Promise.allSettled(
      users.map((u) =>
        createNotification({
          userId: u.id,
          type,
          title,
          message: opts?.message,
          link: opts?.link,
          metadata: opts?.metadata,
        }),
      ),
    );
  } catch {
    // Non-critical
  }
}

/** Notify a specific user */
export async function notifyUser(
  userId: string,
  type: NotificationType,
  title: string,
  opts?: { message?: string; link?: string; metadata?: Record<string, unknown> },
): Promise<void> {
  return createNotification({ userId, type, title, ...opts });
}
