import { logger } from "./logger.js";
import type { ThreatLensLookupResponse } from "../modules/enrichment/enrichment.types.js";

async function getBaseUrl(): Promise<string> {
  try {
    const { db } = await import("../db/index.js");
    const { systemSettingsTable } = await import("../db/schema/system-settings.js");
    const { decrypt } = await import("./crypto-utils.js");
    const { eq } = await import("drizzle-orm");

    const row = await db
      .select()
      .from(systemSettingsTable)
      .where(eq(systemSettingsTable.key, "integrations.threatlens.url"))
      .limit(1);

    if (row[0]?.value) {
      return row[0].value.replace(/\/$/, "");
    }
  } catch {
    // DB not ready yet, fall back to env
  }
  return (process.env["THREATLENS_API_URL"] ?? "http://localhost:8000").replace(/\/$/, "");
}

async function getApiKey(): Promise<string | undefined> {
  try {
    const { db } = await import("../db/index.js");
    const { systemSettingsTable } = await import("../db/schema/system-settings.js");
    const { decrypt } = await import("./crypto-utils.js");
    const { eq } = await import("drizzle-orm");

    const row = await db
      .select()
      .from(systemSettingsTable)
      .where(eq(systemSettingsTable.key, "integrations.threatlens.apiKey"))
      .limit(1);

    if (row[0]?.value) {
      return row[0].encrypted ? decrypt(row[0].value) : row[0].value;
    }
  } catch {
    // fall back to env
  }
  return process.env["THREATLENS_API_KEY"];
}

const THREATLENS_TIMEOUT_MS = parseInt(process.env["THREATLENS_TIMEOUT_MS"] ?? "35000");

async function tlFetch(path: string, options?: RequestInit): Promise<any> {
  const base = await getBaseUrl();
  const apiKey = await getApiKey();
  const url = `${base}/api/v1${path}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), THREATLENS_TIMEOUT_MS);
  try {
    const resp = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        "Content-Type": "application/json",
        ...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {}),
        ...(options?.headers ?? {}),
      },
    });
    if (!resp.ok) {
      const text = await resp.text().catch(() => "");
      throw new Error(`ThreatLens HTTP ${resp.status}: ${text}`);
    }
    return resp.json();
  } finally {
    clearTimeout(timer);
  }
}

export async function enrichIOC(value: string): Promise<ThreatLensLookupResponse | null> {
  try {
    return await tlFetch("/ioc/lookup", {
      method: "POST",
      body: JSON.stringify({ value }),
    });
  } catch (err: any) {
    logger.warn({ value, err: err.message }, "ThreatLens enrichment failed — degraded mode");
    return null;
  }
}

export async function enrichMultiple(values: string[]): Promise<Map<string, ThreatLensLookupResponse | null>> {
  const results = await Promise.allSettled(values.map(v => enrichIOC(v)));
  const map = new Map<string, ThreatLensLookupResponse | null>();
  values.forEach((v, i) => {
    const r = results[i];
    map.set(v, r.status === "fulfilled" ? r.value : null);
  });
  return map;
}

export async function addNoteToThreatLens(iocValue: string, note: string, analyst: string): Promise<void> {
  try {
    await tlFetch(`/ioc/${encodeURIComponent(iocValue)}/notes`, {
      method: "POST",
      body: JSON.stringify({ note, analyst }),
    });
  } catch (err: any) {
    logger.warn({ iocValue, err: err.message }, "Failed to write note to ThreatLens — continuing");
  }
}

export async function isThreatLensHealthy(): Promise<boolean> {
  try {
    const base = await getBaseUrl();
    const apiKey = await getApiKey();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3000);
    await fetch(`${base}/api/v1/health`, {
      signal: controller.signal,
      headers: apiKey ? { Authorization: `Bearer ${apiKey}` } : {},
    }).finally(() => clearTimeout(timer));
    return true;
  } catch {
    return false;
  }
}
