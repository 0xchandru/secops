/**
 * seed-users.ts
 *
 * Standalone script to seed all demo users into the database.
 * Safe to run multiple times — uses ON CONFLICT DO NOTHING.
 *
 * Usage:
 *   npm run seed:users
 *
 * Users seeded (matching the one-click login buttons on the login page):
 *   admin   / Admin@SecOps1!    — admin
 *   morgan  / Manager@1234!     — soc_manager
 *   elena   / Engineer@1234!    — detection_engineer
 *   alice   / Analyst@1234!     — soc_l2
 *   bob     / Analyst@1234!     — soc_l1
 *   viewer  / Viewer@1234!      — viewer
 */

import "dotenv/config";
import bcrypt from "bcryptjs";
import { drizzle } from "drizzle-orm/node-postgres";
import pg from "pg";
import { usersTable } from "../src/db/schema/users.js";
import { DEFAULT_USER_SETTINGS } from "../src/db/schema/users.js";

const { Pool } = pg;

const SALT_ROUNDS = 12;

const DEMO_USERS: {
  username: string;
  email: string;
  password: string;
  role: "admin" | "soc_manager" | "detection_engineer" | "soc_l2" | "soc_l1" | "viewer";
  displayName: string;
  jobTitle: string;
}[] = [
  {
    username: "admin",
    email: "admin@secops.local",
    password: "Admin@SecOps1!",
    role: "admin",
    displayName: "Admin User",
    jobTitle: "System Administrator",
  },
  {
    username: "morgan",
    email: "morgan@secops.local",
    password: "Manager@1234!",
    role: "soc_manager",
    displayName: "Morgan",
    jobTitle: "SOC Manager",
  },
  {
    username: "elena",
    email: "elena@secops.local",
    password: "Engineer@1234!",
    role: "detection_engineer",
    displayName: "Elena",
    jobTitle: "Detection Engineer",
  },
  {
    username: "alice",
    email: "alice@secops.local",
    password: "Analyst@1234!",
    role: "soc_l2",
    displayName: "Alice",
    jobTitle: "SOC L2 Analyst",
  },
  {
    username: "bob",
    email: "bob@secops.local",
    password: "Analyst@1234!",
    role: "soc_l1",
    displayName: "Bob",
    jobTitle: "SOC L1 Analyst",
  },
  {
    username: "viewer",
    email: "viewer@secops.local",
    password: "Viewer@1234!",
    role: "viewer",
    displayName: "Viewer",
    jobTitle: "Read-Only Viewer",
  },
];

const rawUrl = process.env["DATABASE_URL"];
if (!rawUrl) {
  console.error("❌  DATABASE_URL is not set.");
  process.exit(1);
}

const pool = new Pool({ connectionString: rawUrl });
const db = drizzle(pool);

console.log("\n👤  Seeding demo users …\n");

let created = 0;
let skipped = 0;

for (const user of DEMO_USERS) {
  const passwordHash = await bcrypt.hash(user.password, SALT_ROUNDS);

  const result = await db
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

  if (result.length > 0) {
    console.log(`  ✅  Created   ${user.username.padEnd(10)} (${user.role})`);
    created++;
  } else {
    console.log(`  ⏭   Skipped   ${user.username.padEnd(10)} — already exists`);
    skipped++;
  }
}

await pool.end();

console.log(`\n🎉  Done — ${created} created, ${skipped} skipped.\n`);
console.log("Demo credentials (for local development):");
console.log("  admin   / Admin@SecOps1!");
console.log("  morgan  / Manager@1234!");
console.log("  elena   / Engineer@1234!");
console.log("  alice   / Analyst@1234!");
console.log("  bob     / Analyst@1234!");
console.log("  viewer  / Viewer@1234!\n");
