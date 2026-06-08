import { pgTable, text, uuid, timestamp, jsonb, integer, index, real } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const rawLogsTable = pgTable("raw_logs", {
  id: uuid("id").primaryKey().defaultRandom(),
  source: text("source").notNull(),
  severity: text("severity").notNull().default("info"),
  eventType: text("event_type"),
  category: text("category"),
  action: text("action"),
  outcome: text("outcome"),

  // Splunk-compatible fields
  sourcetype: text("sourcetype"),
  indexName: text("index_name").default("main"),
  linecount: integer("linecount"),

  // Network
  sourceIp: text("source_ip"),
  destIp: text("dest_ip"),
  srcPort: integer("src_port"),
  dstPort: integer("dst_port"),
  protocol: text("protocol"),
  bytesIn: integer("bytes_in"),
  bytesOut: integer("bytes_out"),
  direction: text("direction"),

  // Host
  hostname: text("hostname"),
  sourceHost: text("source_host"),

  // User context
  username: text("username"),
  targetUsername: text("target_username"),
  logonType: integer("logon_type"),
  userId: text("user_id"),
  userDomain: text("user_domain"),

  // Process context
  processName: text("process_name"),
  processId: integer("process_id"),
  processCommandLine: text("process_command_line"),
  parentProcessName: text("parent_process_name"),
  parentProcessId: integer("parent_process_id"),

  // HTTP context
  httpMethod: text("http_method"),
  httpUrl: text("http_url"),
  httpStatusCode: integer("http_status_code"),
  httpUserAgent: text("http_user_agent"),

  // DNS context
  dnsQuery: text("dns_query"),
  dnsResponseCode: text("dns_response_code"),
  dnsRecordType: text("dns_record_type"),

  // File context
  fileName: text("file_name"),
  filePath: text("file_path"),
  fileHash: text("file_hash"),

  // Registry
  registryKey: text("registry_key"),
  registryValue: text("registry_value"),

  // Vendor / device
  vendorName: text("vendor_name"),
  vendorProduct: text("vendor_product"),
  deviceAction: text("device_action"),
  deviceEventClassId: text("device_event_class_id"),

  // Syslog-specific
  facility: integer("facility"),
  facilityName: text("facility_name"),
  severityCode: integer("severity_code"),

  // Enrichment
  geoCountry: text("geo_country"),
  geoCity: text("geo_city"),
  geoCountryDst: text("geo_country_dst"),
  geoCityDst: text("geo_city_dst"),
  assetCriticality: text("asset_criticality"),
  riskScore: real("risk_score"),

  // Tags (text array stored as jsonb)
  tags: jsonb("tags").$type<string[]>(),

  message: text("message"),
  rawData: jsonb("raw_data"),
  parsedTimestamp: timestamp("parsed_timestamp"),
  processed: text("processed").notNull().default("false"),
  detectionRunAt: timestamp("detection_run_at"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
}, (table) => [
  index("idx_raw_logs_created_at").on(table.createdAt),
  index("idx_raw_logs_severity").on(table.severity),
  index("idx_raw_logs_category").on(table.category),
  index("idx_raw_logs_source").on(table.source),
  index("idx_raw_logs_source_ip").on(table.sourceIp),
  index("idx_raw_logs_dest_ip").on(table.destIp),
  index("idx_raw_logs_hostname").on(table.hostname),
  index("idx_raw_logs_username").on(table.username),
  index("idx_raw_logs_event_type").on(table.eventType),
  index("idx_raw_logs_action").on(table.action),
  index("idx_raw_logs_processed").on(table.processed),
  index("idx_raw_logs_sourcetype").on(table.sourcetype),
]);

export const insertRawLogSchema = createInsertSchema(rawLogsTable).omit({
  id: true,
  processed: true,
  detectionRunAt: true,
  createdAt: true,
});

export type RawLog = typeof rawLogsTable.$inferSelect;
export type InsertRawLog = z.infer<typeof insertRawLogSchema>;
