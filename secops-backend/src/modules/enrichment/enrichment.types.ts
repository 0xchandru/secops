export interface MITRETechnique {
  technique_id: string;
  technique: string;
  tactic: string;
  confidence: string;
}

export interface ThreatLensLookupResponse {
  source?: string;
  ioc?: { value: string; type: string; id?: number };
  scan_id?: number;
  score: number;
  risk_level: string;
  confidence: string;
  breakdown: Record<string, number>;
  mitre: MITRETechnique[];
  results: Record<string, any>;
  errors?: string[];
  query_time_ms?: number;
  tags?: string[];
}

export interface AlertEnrichmentResult {
  iocValue: string;
  iocType: string;
  extractedFrom: string | null;
  confidence: string | null;
  threatScore: number | null;
  riskLevel: string | null;
  iocConfidence: string | null;
  breakdown: Record<string, number> | null;
  mitreMappings: MITRETechnique[] | null;
  sourceResults: Record<string, any> | null;
  recommendedAction: string | null;
  tags: string[] | null;
  queriedAt: Date | string | null;
  queryTimeMs: number | null;
  fromCache: boolean;
}
