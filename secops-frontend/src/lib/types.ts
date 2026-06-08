export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type AlertStatus = 'new' | 'investigating' | 'escalated' | 'resolved' | 'false_positive';

export interface LogEntry {
  id: string;
  timestamp: Date;
  source: string;
  severity: Severity;
  eventType: string;
  category: string;
  action: string;
  outcome: string;
  sourceIp: string;
  destIp: string;
  srcPort: number | null;
  dstPort: number | null;
  protocol: string;
  hostname: string;
  user?: string;
  targetUsername?: string;
  logonType?: string;
  message: string;
  rawLog: string;
  parsed: Record<string, any>;
  tags: string[];
  // Network
  direction?: string;
  bytesIn?: number;
  bytesOut?: number;
  // HTTP
  httpMethod?: string;
  httpUrl?: string;
  httpStatusCode?: number;
  httpUserAgent?: string;
  // DNS
  dnsQuery?: string;
  dnsResponseCode?: string;
  // File
  fileName?: string;
  filePath?: string;
  fileHash?: string;
  // Registry
  registryKey?: string;
  registryValue?: string;
  // Process
  processName?: string;
  processId?: number;
  processCommandLine?: string;
  parentProcessId?: string;
  // Vendor
  vendorName?: string;
  vendorProduct?: string;
  deviceAction?: string;
  // Geo
  geoCountry?: string;
  geoCity?: string;
  geoCountryDst?: string;
  geoCityDst?: string;
  // Risk
  riskScore?: number;
  assetCriticality?: string;
  ruleMatched?: string;
  alertId?: string;
}

export interface Alert {
  id: string;
  title: string;
  severity: Severity;
  status: AlertStatus;
  assignee?: string;
  createdAt: Date;
  updatedAt: Date;
  mitreIds: string[];
  mitreTactics: string[];
  ruleId: string;
  ruleName: string;
  affectedAssets: string[];
  relatedEventIds: string[];
  description: string;
  timeline: {
    id: string;
    timestamp: Date;
    action: string;
    type?: string;
    user?: string;
    note?: string;
    targetUser?: string;
    targetRole?: string;
    previousStatus?: string;
    newStatus?: string;
    isOverride?: boolean;
    metadata?: Record<string, any>;
  }[];
  aiSummary: string;
  enrichmentStatus?: string | null;
  enrichmentCompletedAt?: string | null;
  maxIocScore?: number | null;
  maxIocRiskLevel?: string | null;
}

export interface DetectionRule {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  enabled: boolean;
  conditions: any[];
  yaml: string;
  mitreIds: string[];
  mitreTactics: string[];
  createdAt: Date;
  updatedAt: Date;
  author: string;
  triggerCount: number;
}

export interface MitreTactic {
  id: string;
  name: string;
  techniques: MitreTechnique[];
}

export interface MitreTechnique {
  id: string;
  name: string;
  covered: boolean;
  alertCount: number;
}
