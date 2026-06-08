const THREATLENS_API_URL = process.env.THREATLENS_API_URL || "http://localhost:8000";

async function fetchFromThreatLens(path: string, options?: RequestInit): Promise<any> {
  const url = `${THREATLENS_API_URL}${path}`;
  const resp = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
  });
  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    throw new Error(`ThreatLens responded with ${resp.status}: ${text}`);
  }
  return resp.json();
}

export async function lookupIOC(value: string): Promise<any> {
  return fetchFromThreatLens("/api/v1/ioc/lookup", {
    method: "POST",
    body: JSON.stringify({ value }),
  });
}

export async function getIOCDetail(value: string): Promise<any> {
  return fetchFromThreatLens(`/api/v1/ioc/${encodeURIComponent(value)}`);
}
