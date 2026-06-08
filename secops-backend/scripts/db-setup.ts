/**
 * db-setup.ts
 *
 * One-shot script that:
 *   1. Creates the PostgreSQL database if it does not already exist
 *   2. Pushes the Drizzle schema (drizzle-kit push)
 *
 * Usage:
 *   npm run db:setup          — create DB + push schema
 *   npm run db:setup -- --no-push   — create DB only, skip push
 *
 * Requires DATABASE_URL in environment / .env file.
 */

import "dotenv/config";
import pg from "pg";
import { execSync } from "child_process";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const { Client } = pg;

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── 1. Resolve DATABASE_URL ────────────────────────────────────────────────

const rawUrl = process.env["DATABASE_URL"];
if (!rawUrl) {
  console.error("❌  DATABASE_URL is not set. Add it to secops-backend/.env");
  process.exit(1);
}

let parsedUrl: URL;
try {
  parsedUrl = new URL(rawUrl);
} catch {
  console.error("❌  DATABASE_URL is not a valid URL:", rawUrl);
  process.exit(1);
}

const targetDb = parsedUrl.pathname.replace(/^\//, "");
if (!targetDb) {
  console.error("❌  DATABASE_URL does not contain a database name (e.g. /secops)");
  process.exit(1);
}

// Build the admin connection URL (same host/user/pass, but connecting to 'postgres')
const adminUrl = new URL(rawUrl);
adminUrl.pathname = "/postgres";

// ── 2. Create database if missing ─────────────────────────────────────────

console.log(`\n🔌  Connecting to PostgreSQL at ${parsedUrl.hostname}:${parsedUrl.port || 5432} …`);

const client = new Client({ connectionString: adminUrl.toString() });

try {
  await client.connect();
} catch (err: any) {
  console.error(`❌  Could not connect to PostgreSQL: ${err.message}`);
  console.error(
    "\n   Make sure PostgreSQL is running and the host/port in DATABASE_URL is reachable."
  );
  process.exit(1);
}

try {
  const { rows } = await client.query<{ exists: boolean }>(
    "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1) AS exists",
    [targetDb]
  );

  if (rows[0]?.exists) {
    console.log(`✅  Database "${targetDb}" already exists — skipping creation.`);
  } else {
    // Database names cannot be parameterised — safe because we parsed from a URL
    await client.query(`CREATE DATABASE "${targetDb.replace(/"/g, '""')}"`);
    console.log(`✅  Database "${targetDb}" created.`);
  }
} finally {
  await client.end();
}

// ── 3. Push Drizzle schema ─────────────────────────────────────────────────

const skipPush = process.argv.includes("--no-push");
if (skipPush) {
  console.log("\n⏭   Skipping schema push (--no-push flag set).");
} else {
  console.log("\n📐  Pushing Drizzle schema …");
  try {
    execSync("npm run db:push", {
      stdio: "inherit",
      cwd: resolve(__dirname, ".."),
    });
    console.log("✅  Schema push complete.");
  } catch (err: any) {
    console.error("❌  Schema push failed:", err.message);
    process.exit(1);
  }
}

console.log("\n🎉  Database setup done. You can now run: npm run dev\n");
