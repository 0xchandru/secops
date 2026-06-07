export interface ParsedEvent {
  // --- Core identification ---
  sourceType: string;           // e.g. "syslog", "windows_eventlog", "firewall", "cef"
  sourceHost: string;           // originating hostname
  category: string;             // e.g. "authentication", "process", "firewall", "file"
  action: string;               // e.g. "login_success", "process_create", "connection_blocked"
  outcome?: string;             // "success" | "failure" | undefined
  severity: string;             // "critical" | "high" | "medium" | "low" | "info"
  eventType?: string;           // readable event label (e.g. "EventID-4625", "syslog")
  message?: string;
  rawLog?: string;

  // --- Timestamp ---
  parsedTimestamp?: Date;       // timestamp extracted from the log itself (not ingest time)

  // --- Syslog / facility ---
  facility?: number;            // RFC3164 facility code
  facilityName?: string;        // e.g. "auth", "kern", "daemon", "local0"
  severityCode?: number;        // RFC3164 severity code (0-7)

  // --- User context ---
  userName?: string;
  userDomain?: string;
  userId?: string;
  targetUserName?: string;      // for su/sudo target, RDP target, etc.
  logonType?: number;           // Windows logon type (2=interactive, 3=network, 10=RDP)

  // --- Process context ---
  processName?: string;
  processId?: number;
  processCommandLine?: string;
  parentProcessName?: string;
  parentProcessId?: number;

  // --- Network context ---
  srcIp?: string;
  srcPort?: number;
  dstIp?: string;
  dstPort?: number;
  protocol?: string;
  bytesIn?: number;
  bytesOut?: number;
  packetCount?: number;
  direction?: string;           // "inbound" | "outbound" | "internal"
  networkInterface?: string;

  // --- HTTP context ---
  httpMethod?: string;
  httpUrl?: string;
  httpStatusCode?: number;
  httpUserAgent?: string;
  httpReferrer?: string;

  // --- DNS context ---
  dnsQuery?: string;
  dnsResponseCode?: string;
  dnsRecordType?: string;

  // --- File context ---
  fileName?: string;
  filePath?: string;
  fileHash?: string;            // SHA256 or MD5

  // --- Registry context (Windows) ---
  registryKey?: string;
  registryValue?: string;

  // --- Vendor / device context ---
  vendorName?: string;
  vendorProduct?: string;
  deviceAction?: string;
  deviceEventClassId?: string;

  // --- Tags ---
  tags?: string[];              // e.g. ["brute-force", "ssh", "external"]
}
