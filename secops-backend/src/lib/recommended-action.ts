export function deriveRecommendedAction(score: number, riskLevel: string): string {
  if (score >= 80 || riskLevel === "critical") {
    return "Block immediately at firewall. Escalate to L2. Preserve forensic artifacts.";
  }
  if (score >= 60 || riskLevel === "malicious") {
    return "Investigate immediately. Check for lateral movement. Do not block without L2 approval.";
  }
  if (score >= 40 || riskLevel === "suspicious") {
    return "Monitor closely. Correlate with other alerts from this source. Low urgency escalation.";
  }
  if (riskLevel === "low") {
    return "Log for baseline analysis. No immediate action required.";
  }
  return "No immediate action required.";
}
