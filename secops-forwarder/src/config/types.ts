export interface MonitorStanza {
  path: string;
  sourcetype: string;
  index: string;
  host?: string;
  followTail?: boolean;
  disabled?: boolean;
  ignoreOlderThan?: string;
  whitelistRegex?: string;
  blacklistRegex?: string;
  lineBreaker?: string;
}

export interface OutputsConfig {
  server: string;
  token: string;
  batchSize: number;
  flushIntervalMs: number;
  maxRetries: number;
  retryBaseMs: number;
  heartbeatIntervalMs: number;
  forwarderName: string;
}

export interface PropsStanza {
  sourcetype: string;
  timePrefix?: string;
  timeFormat?: string;
  lineBreaker?: string;
  shouldLinemerge?: boolean;
  maxLineLength?: number;
  transforms?: string[];
}

export interface TransformStanza {
  name: string;
  regex: string;
  format?: string;
  writeMeta?: boolean;
  defaultValue?: string;
}

export interface ForwarderConfig {
  monitors: MonitorStanza[];
  outputs: OutputsConfig;
  props: Map<string, PropsStanza>;
  transforms: Map<string, TransformStanza>;
}
