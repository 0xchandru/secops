export interface NormalizedEvent {
  id?: string;
  timestamp: Date;
  parsedTimestamp?: Date;
  ingestedAt?: Date;
  sourceType: string;
  sourceHost: string;
  category: string;
  action: string;
  outcome?: string;
  severity: string;

  // User context
  userName?: string;
  userDomain?: string;
  userId?: string;
  targetUserName?: string;
  logonType?: number;

  // Process context
  processName?: string;
  processId?: number;
  processCommandLine?: string;
  parentProcessName?: string;
  parentProcessId?: number;

  // Network context
  srcIp?: string;
  srcPort?: number;
  dstIp?: string;
  dstPort?: number;
  protocol?: string;
  bytesIn?: number;
  bytesOut?: number;
  direction?: string;
  packetCount?: number;
  networkInterface?: string;

  // HTTP context
  httpMethod?: string;
  httpUrl?: string;
  httpStatusCode?: number;
  httpUserAgent?: string;
  httpReferrer?: string;

  // DNS context
  dnsQuery?: string;
  dnsResponseCode?: string;
  dnsRecordType?: string;

  // File context
  fileName?: string;
  filePath?: string;
  fileHash?: string;

  // Registry context
  registryKey?: string;
  registryValue?: string;

  // Vendor context
  vendorName?: string;
  vendorProduct?: string;
  deviceAction?: string;
  deviceEventClassId?: string;

  // Syslog context
  facility?: number;
  facilityName?: string;
  severityCode?: number;

  // Enrichment
  geoCountry?: string;
  geoCity?: string;
  geoCountryDst?: string;
  geoCityDst?: string;
  assetCriticality?: string;
  assetTags?: string[];
  riskScore?: number;

  // Metadata
  tags?: string[];
  rawLog?: string;
  message?: string;
  eventType?: string;
  [key: string]: any;
}

export interface MitreMapping {
  tactic: string;
  techniqueId: string;
  techniqueName: string;
  subtechniqueId?: string;
  subtechniqueName?: string;
}

export interface ThresholdConfig {
  field: string;
  count: number;
  timeframe: string;
}

export interface SequenceStep {
  match: Record<string, any>;
  filter?: Record<string, any>;
}

export interface SequenceConfig {
  steps: SequenceStep[];
  timeframe: string;
  byField?: string; // group correlation by this field (e.g., srcIp)
}

export interface AlertConfig {
  titleTemplate: string;
  contextFields?: string[];
}

export interface DetectionRule {
  id: string;
  name: string;
  description: string;
  author?: string;
  severity: "critical" | "high" | "medium" | "low";
  type: "simple" | "threshold" | "sequence";
  enabled: boolean;
  match: Record<string, any>;
  filter?: Record<string, any>;
  threshold?: ThresholdConfig;
  sequence?: SequenceConfig;
  maxAlertsPerHour?: number;
  dedupWindow?: string; // e.g., "1h" — windowed dedup instead of permanent
  mitre?: MitreMapping;
  alert: AlertConfig;
  tags?: string[];
}

export interface TriggeredAlert {
  ruleId: string;
  ruleName: string;
  title: string;
  description?: string;
  severity: string;
  severityScore: number;
  mitreTactic?: string;
  mitreTechniqueId?: string;
  mitreTechniqueName?: string;
  mitreSubtechniqueId?: string;
  sourceHost?: string;
  triggerEventId?: string;
  triggerTimestamp: Date;
  context: Record<string, any>;
  tags?: string[];
  dedupKey?: string;
  sourceIp?: string;
  destIp?: string;
  hostname?: string;
}
