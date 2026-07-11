/**
 * AES-256-GCM encrypted secret store backed by PostgreSQL.
 *
 * Sensitive credentials (SMTP_PASSWORD, SLACK_WEBHOOK_URL, THREATLENS_API_KEY)
 * are stored encrypted in the system_settings table under the "__secret__:<name>"
 * namespace.  Values are decrypted into process.env at startup (loadSecretsIntoEnv)
 * and whenever getSecret is called, so the rest of the application continues to
 * read credentials via standard environment variable access.
 *
 * Encryption key: SECRET_ENCRYPTION_KEY env var (preferred, 32+ chars).
 * Falls back to JWT_SECRET if SECRET_ENCRYPTION_KEY is absent.  If neither is
 * set the module will throw at first use, failing loudly instead of silently
 * degrading to plaintext storage.
 */

import { createCipheriv, createDecipheriv, createHash, randomBytes } from "crypto";

const NS = "__secret__:";
const ALGO = "aes-256-gcm";

function encryptionKey(): Buffer {
  const raw = process.env["SECRET_ENCRYPTION_KEY"] ?? process.env["JWT_SECRET"] ?? "";
  if (!raw) throw new Error("Set SECRET_ENCRYPTION_KEY (or JWT_SECRET) to enable encrypted secret storage");
  return createHash("sha256").update(raw).digest();
}

function encrypt(plaintext: string): string {
  const key = encryptionKey();
  const iv = randomBytes(12);
  const cipher = createCipheriv(ALGO, key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString("base64")}.${tag.toString("base64")}.${enc.toString("base64")}`;
}

function decrypt(ciphertext: string): string {
  const key = encryptionKey();
  const parts = ciphertext.split(".");
  if (parts.length !== 3) throw new Error("Invalid ciphertext format");
  const [ivB64, tagB64, encB64] = parts;
  const decipher = createDecipheriv(ALGO, key, Buffer.from(ivB64, "base64"));
  decipher.setAuthTag(Buffer.from(tagB64, "base64"));
  return decipher.update(Buffer.from(encB64, "base64")).toString("utf8") + decipher.final("utf8");
}

async function getDb() {
  const { db, systemSettingsTable } = await import("../db");
  const { eq } = await import("drizzle-orm");
  return { db, systemSettingsTable, eq };
}

/** Encrypt and persist a secret to PostgreSQL, and cache it in process.env. */
export async function setSecret(name: string, value: string): Promise<void> {
  const { db, systemSettingsTable, eq } = await getDb();
  const key = `${NS}${name}`;
  const encryptedValue = encrypt(value);

  const existing = await db
    .select({ key: systemSettingsTable.key })
    .from(systemSettingsTable)
    .where(eq(systemSettingsTable.key, key))
    .limit(1);

  if (existing.length > 0) {
    await db
      .update(systemSettingsTable)
      .set({ value: encryptedValue, encrypted: true, updatedAt: new Date(), updatedBy: "system" })
      .where(eq(systemSettingsTable.key, key));
  } else {
    await db.insert(systemSettingsTable).values({
      key,
      value: encryptedValue,
      encrypted: true,
      updatedBy: "system",
    });
  }

  process.env[name] = value;
}

/**
 * Read a secret.  Returns the cached process.env value if available, otherwise
 * decrypts from PostgreSQL and caches the result.
 */
export async function getSecret(name: string): Promise<string> {
  if (process.env[name]) return process.env[name];

  try {
    const { db, systemSettingsTable, eq } = await getDb();
    const key = `${NS}${name}`;
    const rows = await db
      .select()
      .from(systemSettingsTable)
      .where(eq(systemSettingsTable.key, key))
      .limit(1);

    if (rows[0]?.value && rows[0]?.encrypted) {
      const plaintext = decrypt(rows[0].value);
      process.env[name] = plaintext;
      return plaintext;
    }
  } catch { /* DB not ready or decryption failed — fall back to env */ }

  return process.env[name] ?? "";
}

/** Remove a secret from PostgreSQL and process.env. */
export async function deleteSecret(name: string): Promise<void> {
  try {
    const { db, systemSettingsTable, eq } = await getDb();
    const key = `${NS}${name}`;
    await db.delete(systemSettingsTable).where(eq(systemSettingsTable.key, key));
  } catch { /* non-fatal */ }
  delete process.env[name];
}

/**
 * Bootstrap: load all persisted secrets from PostgreSQL into process.env.
 * Call once at server startup before any component reads credentials.
 */
export async function loadSecretsIntoEnv(): Promise<void> {
  try {
    const { db, systemSettingsTable } = await getDb();
    const { sql } = await import("drizzle-orm");
    const rows = await db
      .select()
      .from(systemSettingsTable)
      .where(sql`${systemSettingsTable.key} like ${NS + "%"} and ${systemSettingsTable.encrypted} = true`);

    for (const row of rows) {
      const envName = row.key.replace(NS, "");
      if (!process.env[envName] && row.value) {
        try {
          process.env[envName] = decrypt(row.value);
        } catch { /* skip corrupt entry */ }
      }
    }
  } catch { /* non-fatal — app works without persisted secrets */ }
}
