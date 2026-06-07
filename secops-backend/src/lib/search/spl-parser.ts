/**
 * SPL-like Search Parser for SecOps Console
 *
 * Supports:
 *   field=value          exact match
 *   field="quoted val"   exact match with spaces
 *   field!=value         not equal
 *   field>N  field>=N    numeric greater-than
 *   field<N  field<=N    numeric less-than
 *   field=*             field is not null / not empty
 *   keyword             free-text search (ilike across message, rawLog)
 *   source=syslog severity=high srcIp="10.0.0.1"
 *   NOT field=value     negation
 *   AND / OR            boolean (AND is implicit between terms)
 *   | where ...         pipe filters (future)
 *   | stats count by field  (future — returns instructions)
 *
 * Maps to Drizzle SQL conditions on rawLogsTable.
 */

import { rawLogsTable } from "../../db/schema/logs";
import { eq, ne, gt, gte, lt, lte, ilike, and, or, not, isNotNull, sql, type SQL } from "drizzle-orm";

// Fields that map directly to a column
const FIELD_COLUMN_MAP: Record<string, any> = {
  source: rawLogsTable.source,
  severity: rawLogsTable.severity,
  eventtype: rawLogsTable.eventType,
  event_type: rawLogsTable.eventType,
  category: rawLogsTable.category,
  action: rawLogsTable.action,
  outcome: rawLogsTable.outcome,
  sourceip: rawLogsTable.sourceIp,
  source_ip: rawLogsTable.sourceIp,
  srcip: rawLogsTable.sourceIp,
  src_ip: rawLogsTable.sourceIp,
  destip: rawLogsTable.destIp,
  dest_ip: rawLogsTable.destIp,
  dstip: rawLogsTable.destIp,
  dst_ip: rawLogsTable.destIp,
  srcport: rawLogsTable.srcPort,
  dstport: rawLogsTable.dstPort,
  protocol: rawLogsTable.protocol,
  hostname: rawLogsTable.hostname,
  sourcehost: rawLogsTable.sourceHost,
  username: rawLogsTable.username,
  user: rawLogsTable.username,
  processname: rawLogsTable.processName,
  process: rawLogsTable.processName,
  message: rawLogsTable.message,
  direction: rawLogsTable.direction,
  httpmethod: rawLogsTable.httpMethod,
  http_method: rawLogsTable.httpMethod,
  httpurl: rawLogsTable.httpUrl,
  httpstatuscode: rawLogsTable.httpStatusCode,
  httpuseragent: rawLogsTable.httpUserAgent,
  dnsquery: rawLogsTable.dnsQuery,
  dns_query: rawLogsTable.dnsQuery,
  filename: rawLogsTable.fileName,
  filepath: rawLogsTable.filePath,
  filehash: rawLogsTable.fileHash,
  registrykey: rawLogsTable.registryKey,
  vendorname: rawLogsTable.vendorName,
  vendorproduct: rawLogsTable.vendorProduct,
  deviceaction: rawLogsTable.deviceAction,
  facilityname: rawLogsTable.facilityName,
  geocountry: rawLogsTable.geoCountry,
  geocity: rawLogsTable.geoCity,
  assetcriticality: rawLogsTable.assetCriticality,
  riskscore: rawLogsTable.riskScore,
  processed: rawLogsTable.processed,
  targetusername: rawLogsTable.targetUsername,
  logontype: rawLogsTable.logonType,
};

// Numeric columns — use numeric comparison operators
const NUMERIC_COLUMNS = new Set([
  "srcport", "dstport", "bytesin", "bytesout",
  "httpstatuscode", "riskscore", "processid", "logontype",
  "facility", "severitycode",
]);

interface ParsedToken {
  type: "field_op" | "keyword" | "NOT" | "OR" | "AND" | "pipe";
  field?: string;
  op?: string;
  value?: string;
  keyword?: string;
  pipeCmd?: string;
}

/**
 * Tokenize an SPL-like query string.
 */
function tokenize(query: string): ParsedToken[] {
  const tokens: ParsedToken[] = [];
  let i = 0;
  const len = query.length;

  while (i < len) {
    // Skip whitespace
    while (i < len && query[i] === " ") i++;
    if (i >= len) break;

    // Pipe command — everything after | is passed through
    if (query[i] === "|") {
      tokens.push({ type: "pipe", pipeCmd: query.slice(i + 1).trim() });
      break;
    }

    // Boolean operators
    if (query.slice(i, i + 4).toUpperCase() === "NOT " || query.slice(i, i + 4).toUpperCase() === "NOT\t") {
      tokens.push({ type: "NOT" });
      i += 4;
      continue;
    }
    if (query.slice(i, i + 3).toUpperCase() === "OR " || query.slice(i, i + 3).toUpperCase() === "OR\t") {
      tokens.push({ type: "OR" });
      i += 3;
      continue;
    }
    if (query.slice(i, i + 4).toUpperCase() === "AND " || query.slice(i, i + 4).toUpperCase() === "AND\t") {
      tokens.push({ type: "AND" });
      i += 4;
      continue;
    }

    // field operator value: field!=value, field>=value, field<=value, field>value, field<value, field=value
    const fieldOpMatch = query.slice(i).match(/^(\w+)(!=|>=|<=|>|<|=)("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\S+)/);
    if (fieldOpMatch) {
      const field = fieldOpMatch[1].toLowerCase();
      const op = fieldOpMatch[2];
      let value = fieldOpMatch[3];
      // Strip quotes
      if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
        value = value.slice(1, -1);
      }
      tokens.push({ type: "field_op", field, op, value });
      i += fieldOpMatch[0].length;
      continue;
    }

    // Quoted keyword
    if (query[i] === '"' || query[i] === "'") {
      const quote = query[i];
      let j = i + 1;
      while (j < len && query[j] !== quote) j++;
      const kw = query.slice(i + 1, j);
      tokens.push({ type: "keyword", keyword: kw });
      i = j + 1;
      continue;
    }

    // Bare keyword (until next space or pipe)
    let j = i;
    while (j < len && query[j] !== " " && query[j] !== "|") j++;
    const word = query.slice(i, j);
    if (word.toUpperCase() === "OR") tokens.push({ type: "OR" });
    else if (word.toUpperCase() === "AND") tokens.push({ type: "AND" });
    else if (word.toUpperCase() === "NOT") tokens.push({ type: "NOT" });
    else tokens.push({ type: "keyword", keyword: word });
    i = j;
  }

  return tokens;
}

/**
 * Convert a single field-op-value token to a Drizzle SQL condition.
 */
function tokenToCondition(token: ParsedToken): SQL | null {
  if (token.type === "keyword" && token.keyword) {
    const pattern = `%${token.keyword}%`;
    return sql`(${rawLogsTable.message} ilike ${pattern} OR ${rawLogsTable.sourceIp} ilike ${pattern} OR ${rawLogsTable.username} ilike ${pattern} OR ${rawLogsTable.eventType} ilike ${pattern} OR ${rawLogsTable.hostname} ilike ${pattern} OR ${rawLogsTable.action} ilike ${pattern})`;
  }

  if (token.type !== "field_op" || !token.field || !token.op) return null;

  const col = FIELD_COLUMN_MAP[token.field];
  if (!col) {
    // Unknown field — search raw_data jsonb
    const pattern = `%${token.value}%`;
    return sql`${rawLogsTable.rawData}::text ilike ${pattern}`;
  }

  const val = token.value!;
  const isNumericCol = NUMERIC_COLUMNS.has(token.field);

  // Wildcard exists check
  if (val === "*") {
    return isNotNull(col);
  }

  switch (token.op) {
    case "=":
      if (val.includes("*")) {
        // Wildcard match → ilike
        const likePattern = val.replace(/\*/g, "%");
        return ilike(col, likePattern);
      }
      if (isNumericCol) return eq(col, Number(val));
      return eq(col, val);
    case "!=":
      if (isNumericCol) return ne(col, Number(val));
      return ne(col, val);
    case ">":
      return gt(col, Number(val));
    case ">=":
      return gte(col, Number(val));
    case "<":
      return lt(col, Number(val));
    case "<=":
      return lte(col, Number(val));
    default:
      return null;
  }
}

export interface SearchResult {
  conditions: SQL | undefined;
  pipe?: string;
}

/**
 * Parse an SPL-like query string into Drizzle SQL conditions.
 */
export function parseSplQuery(query: string): SearchResult {
  const trimmed = query.trim();
  if (!trimmed) return { conditions: undefined };

  const tokens = tokenize(trimmed);
  if (tokens.length === 0) return { conditions: undefined };

  // Collect pipe commands
  let pipeCmd: string | undefined;
  const filterTokens = tokens.filter((t) => {
    if (t.type === "pipe") {
      pipeCmd = t.pipeCmd;
      return false;
    }
    return true;
  });

  // Build conditions with boolean logic
  const groups: SQL[][] = [[]]; // array of OR-groups of AND-conditions
  let negate = false;

  for (const token of filterTokens) {
    if (token.type === "NOT") {
      negate = true;
      continue;
    }
    if (token.type === "OR") {
      groups.push([]); // start new OR group
      continue;
    }
    if (token.type === "AND") {
      // AND is implicit between tokens, so just continue
      continue;
    }

    const cond = tokenToCondition(token);
    if (cond) {
      const finalCond = negate ? not(cond) : cond;
      groups[groups.length - 1].push(finalCond);
    }
    negate = false;
  }

  // Combine: AND within each group, OR between groups
  const orParts: SQL[] = [];
  for (const group of groups) {
    if (group.length === 0) continue;
    if (group.length === 1) orParts.push(group[0]);
    else orParts.push(and(...group)!);
  }

  let conditions: SQL | undefined;
  if (orParts.length === 0) conditions = undefined;
  else if (orParts.length === 1) conditions = orParts[0];
  else conditions = or(...orParts);

  return { conditions, pipe: pipeCmd };
}
