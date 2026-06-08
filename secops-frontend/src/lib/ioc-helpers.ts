export interface RiskColors {
  text: string;
  bg: string;
  border: string;
  badge: string;
}

export function getRiskColor(riskLevel: string | null | undefined): RiskColors {
  const map: Record<string, RiskColors> = {
    clean:      { text: "#86efac", bg: "rgba(20,83,45,0.6)",   border: "#166534", badge: "text-green-300 bg-green-900/40 border-green-800" },
    low:        { text: "#93c5fd", bg: "rgba(30,58,95,0.6)",   border: "#1e40af", badge: "text-blue-300 bg-blue-900/40 border-blue-800" },
    suspicious: { text: "#fde68a", bg: "rgba(66,32,6,0.6)",    border: "#92400e", badge: "text-yellow-300 bg-yellow-900/40 border-yellow-800" },
    malicious:  { text: "#fed7aa", bg: "rgba(67,20,7,0.6)",    border: "#9a3412", badge: "text-orange-300 bg-orange-900/40 border-orange-800" },
    critical:   { text: "#fca5a5", bg: "rgba(69,10,10,0.6)",   border: "#991b1b", badge: "text-red-300 bg-red-900/40 border-red-800" },
    unknown:    { text: "#94a3b8", bg: "rgba(30,41,59,0.6)",   border: "#334155", badge: "text-slate-400 bg-slate-800/40 border-slate-700" },
  };
  return map[(riskLevel ?? "unknown").toLowerCase()] ?? map.unknown;
}

export function getRiskLabel(riskLevel: string | null | undefined): string {
  return (riskLevel ?? "unknown").toUpperCase();
}

export function getRecommendedAction(score: number | null | undefined): string {
  if (!score) return "No immediate action required";
  if (score >= 80) return "Block immediately · Escalate to L2";
  if (score >= 60) return "Investigate immediately · Do not block without L2 approval";
  if (score >= 40) return "Monitor · Correlate with other alerts";
  return "No immediate action required";
}

// Source display names
export const SOURCE_LABELS: Record<string, string> = {
  virustotal:    "VirusTotal",
  abuseipdb:     "AbuseIPDB",
  alienvault:    "AlienVault OTX",
  urlhaus:       "URLhaus",
  greynoise:     "GreyNoise",
  malwarebazaar: "MalwareBazaar",
  threatfox:     "ThreatFox",
};

// Max possible score contribution per source
export const SOURCE_MAX_SCORES: Record<string, number> = {
  virustotal:    32,
  abuseipdb:     25,
  alienvault:    22,
  urlhaus:       12,
  greynoise:     9,
  malwarebazaar: 10,
  threatfox:     10,
};

export function getSourceLabel(key: string): string {
  return SOURCE_LABELS[key.toLowerCase()] ?? key.charAt(0).toUpperCase() + key.slice(1);
}

export function getSourceMax(key: string): number {
  return SOURCE_MAX_SCORES[key.toLowerCase()] ?? 100;
}

export function scoreToPercent(score: number, max: number): number {
  return Math.min(100, Math.round((score / max) * 100));
}
