import { db, rulesTable } from "../../db";
import { eq, desc } from "drizzle-orm";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function getRules() {
  return db.select().from(rulesTable).orderBy(desc(rulesTable.createdAt));
}

export async function getRuleById(id: string) {
  if (!UUID_RE.test(id)) return null;
  const [rule] = await db.select().from(rulesTable).where(eq(rulesTable.id, id)).limit(1);
  return rule ?? null;
}

export async function createRule(data: {
  name: string;
  description?: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  yamlContent?: string;
  logSource?: string;
  mitreIds?: string[];
  mitreTactic?: string;
  tags?: string[];
  createdBy?: string;
}) {
  const [rule] = await db.insert(rulesTable).values({
    ...data,
    enabled: true,
    updatedBy: data.createdBy,
  }).returning();
  return rule;
}

export async function updateRule(id: string, data: {
  name?: string;
  description?: string;
  severity?: "critical" | "high" | "medium" | "low" | "info";
  enabled?: boolean;
  yamlContent?: string;
  mitreIds?: string[];
  updatedBy?: string;
}) {
  const [rule] = await db.update(rulesTable)
    .set({ ...data, updatedAt: new Date(), lastModifiedAt: new Date() })
    .where(eq(rulesTable.id, id))
    .returning();
  return rule ?? null;
}

export async function deleteRule(id: string) {
  await db.delete(rulesTable).where(eq(rulesTable.id, id));
}

export async function toggleRule(id: string, enabled: boolean, userId: string) {
  const [rule] = await db.update(rulesTable)
    .set({ enabled, updatedBy: userId, updatedAt: new Date(), lastModifiedAt: new Date() })
    .where(eq(rulesTable.id, id))
    .returning();
  return rule ?? null;
}
