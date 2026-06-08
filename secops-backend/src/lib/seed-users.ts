import bcrypt from "bcryptjs";
import { count } from "drizzle-orm";
import { db } from "../db/index.js";
import { usersTable, DEFAULT_USER_SETTINGS } from "../db/schema/users.js";
import { logger } from "./logger.js";

const SALT_ROUNDS = 12;

const DEMO_USERS: {
  username: string;
  email: string;
  password: string;
  role: "admin" | "soc_manager" | "detection_engineer" | "soc_l2" | "soc_l1" | "viewer";
  displayName: string;
  jobTitle: string;
}[] = [
  { username: "admin",  email: "admin@secops.local",  password: "Admin@SecOps1!",  role: "admin",               displayName: "Admin User",   jobTitle: "System Administrator" },
  { username: "morgan", email: "morgan@secops.local", password: "Manager@1234!",   role: "soc_manager",         displayName: "Morgan",       jobTitle: "SOC Manager" },
  { username: "elena",  email: "elena@secops.local",  password: "Engineer@1234!",  role: "detection_engineer",  displayName: "Elena",        jobTitle: "Detection Engineer" },
  { username: "alice",  email: "alice@secops.local",  password: "Analyst@1234!",   role: "soc_l2",              displayName: "Alice",        jobTitle: "SOC L2 Analyst" },
  { username: "bob",    email: "bob@secops.local",    password: "Analyst@1234!",   role: "soc_l1",              displayName: "Bob",          jobTitle: "SOC L1 Analyst" },
  { username: "viewer", email: "viewer@secops.local", password: "Viewer@1234!",    role: "viewer",              displayName: "Viewer",       jobTitle: "Read-Only Viewer" },
];

export async function seedDefaultUsers(): Promise<void> {
  const [row] = await db.select({ total: count() }).from(usersTable);
  const existing = Number(row?.total ?? 0);

  if (existing >= DEMO_USERS.length) {
    logger.info({ existingUsers: existing }, "Users already seeded, skipping");
    return;
  }

  let created = 0;
  for (const user of DEMO_USERS) {
    const passwordHash = await bcrypt.hash(user.password, SALT_ROUNDS);
    const inserted = await db
      .insert(usersTable)
      .values({
        username: user.username,
        email: user.email,
        passwordHash,
        role: user.role,
        displayName: user.displayName,
        jobTitle: user.jobTitle,
        status: "active",
        settings: DEFAULT_USER_SETTINGS,
      })
      .onConflictDoNothing()
      .returning({ id: usersTable.id });

    if (inserted.length > 0) created++;
  }

  logger.info({ created }, "Demo users seeded");
}
