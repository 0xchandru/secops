import { db, assetsTable } from "../db";

let assetCache: Map<string, { criticality: string; tags: string[] }> = new Map();
let assetCacheLoadedAt = 0;
let geoipLite: any = null;
let geoipAvailable = false;

const ASSET_CACHE_TTL = 5 * 60 * 1000; // 5 minutes

// High-risk countries for severity bonus (common C2 destinations)
const HIGH_RISK_COUNTRIES = new Set(["CN", "RU", "IR", "KP", "SY"]);

// Base risk scores per severity
const SEVERITY_RISK: Record<string, number> = {
  critical: 90, high: 70, medium: 40, low: 15, info: 5,
};

// Lazily load geoip-lite without crashing if database is missing
async function getGeoip(): Promise<any> {
  if (geoipLite !== null) return geoipAvailable ? geoipLite : null;
  try {
    geoipLite = (await import("geoip-lite")).default;
    geoipAvailable = true;
  } catch {
    geoipLite = false;
    geoipAvailable = false;
  }
  return geoipAvailable ? geoipLite : null;
}

export async function loadAssetCache(): Promise<void> {
  try {
    const assets = await db.select().from(assetsTable);
    assetCache = new Map();
    for (const asset of assets) {
      const meta = { criticality: asset.criticality ?? "medium", tags: asset.tags ?? [] };
      assetCache.set(asset.hostname.toLowerCase(), meta);
      if (asset.ip) assetCache.set(asset.ip, meta);
    }
    assetCacheLoadedAt = Date.now();
  } catch {
    // silently fail if assets table doesn't exist yet
  }
}

export async function enrichEvent(event: Record<string, any>): Promise<Record<string, any>> {
  // Reload asset cache if stale
  if (Date.now() - assetCacheLoadedAt > ASSET_CACHE_TTL) {
    await loadAssetCache();
  }

  const geoip = await getGeoip();

  // GeoIP enrichment — source IP
  if (event.srcIp && !isPrivateIp(event.srcIp) && geoip) {
    try {
      const geo = geoip.lookup(event.srcIp);
      if (geo) {
        event.geoCountry = geo.country;
        event.geoCity = geo.city;
      }
    } catch {}
  }

  // GeoIP enrichment — destination IP
  if (event.dstIp && !isPrivateIp(event.dstIp) && geoip) {
    try {
      const geo = geoip.lookup(event.dstIp);
      if (geo) {
        event.geoCountryDst = geo.country;
        event.geoCityDst = geo.city;
      }
    } catch {}
  }

  // Asset enrichment
  const hostKey = event.sourceHost?.toLowerCase();
  const ipKey = event.srcIp;
  const assetMeta = (hostKey ? assetCache.get(hostKey) : null) ?? (ipKey ? assetCache.get(ipKey) : null);
  if (assetMeta) {
    event.assetCriticality = assetMeta.criticality;
    event.assetTags = assetMeta.tags;
  }

  // Risk score calculation
  event.riskScore = computeRiskScore(event);

  return event;
}

function computeRiskScore(event: Record<string, any>): number {
  let score = SEVERITY_RISK[event.severity] ?? 5;

  // +15 for failing outcomes (login_failure, connection_blocked, etc.)
  if (event.outcome === "failure") score += 15;

  // +10 for admin/root user involvement
  const user = (event.userName ?? "").toLowerCase();
  if (user === "root" || user === "admin" || user === "administrator") score += 10;

  // +10 for high-criticality asset
  if (event.assetCriticality === "critical") score += 15;
  else if (event.assetCriticality === "high") score += 10;

  // +10 for external source IP going to internal dest
  if (event.srcIp && !isPrivateIp(event.srcIp) && event.dstIp && isPrivateIp(event.dstIp)) {
    score += 10;
  }

  // +15 if source or dest country is high-risk
  if (HIGH_RISK_COUNTRIES.has(event.geoCountry)) score += 15;
  if (HIGH_RISK_COUNTRIES.has(event.geoCountryDst)) score += 15;

  // Cap at 100
  return Math.min(score, 100);
}

function isPrivateIp(ip: string): boolean {
  const parts = ip.split(".");
  if (parts.length !== 4) return false;
  const n = parseInt(parts[0]);
  const n1 = parseInt(parts[1]);
  if (n === 10) return true;
  if (n === 172 && n1 >= 16 && n1 <= 31) return true;
  if (n === 192 && n1 === 168) return true;
  if (n === 127) return true;
  return false;
}
