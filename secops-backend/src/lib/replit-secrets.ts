/**
 * Replit-DB-backed secret store.
 *
 * Sensitive credentials (SMTP_PASSWORD, SLACK_WEBHOOK_URL, THREATLENS_API_KEY)
 * are stored in Replit DB, which persists across server restarts.  Values are
 * also written into process.env so existing code that reads process.env works
 * without changes.
 *
 * All keys are stored under the "__secops_sec:<name>" namespace to avoid
 * colliding with other Replit DB entries.
 */

const DB_URL = process.env["REPLIT_DB_URL"];
const NS = "__secops_sec:";

function dbKey(name: string): string {
  return `${NS}${name}`;
}

/** Write a single secret to Replit DB + process.env. */
export async function setSecret(name: string, value: string): Promise<void> {
  if (!DB_URL) return;
  const body = new URLSearchParams({ [dbKey(name)]: value });
  await fetch(DB_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });
  process.env[name] = value;
}

/** Read a single secret from Replit DB (falls back to process.env). */
export async function getSecret(name: string): Promise<string> {
  if (DB_URL) {
    const resp = await fetch(`${DB_URL}/${encodeURIComponent(dbKey(name))}`);
    if (resp.ok) {
      const val = await resp.text();
      if (val) {
        process.env[name] = val;
        return val;
      }
    }
  }
  return process.env[name] ?? "";
}

/** Delete a single secret from Replit DB + process.env. */
export async function deleteSecret(name: string): Promise<void> {
  if (DB_URL) {
    await fetch(`${DB_URL}/${encodeURIComponent(dbKey(name))}`, { method: "DELETE" });
  }
  delete process.env[name];
}

/**
 * Bootstrap: load all persisted secrets into process.env at startup.
 * Call once from server startup code.
 */
export async function loadSecretsIntoEnv(): Promise<void> {
  if (!DB_URL) return;
  try {
    const resp = await fetch(`${DB_URL}?prefix=${encodeURIComponent(NS)}`);
    if (!resp.ok) return;
    const keys = (await resp.text()).split("\n").filter(Boolean);
    await Promise.all(
      keys.map(async (rawKey) => {
        const name = rawKey.replace(NS, "");
        const valResp = await fetch(`${DB_URL}/${encodeURIComponent(rawKey)}`);
        if (valResp.ok) {
          const val = await valResp.text();
          if (val && !process.env[name]) {
            process.env[name] = val;
          }
        }
      })
    );
  } catch { /* non-fatal — app works without Replit DB */ }
}
