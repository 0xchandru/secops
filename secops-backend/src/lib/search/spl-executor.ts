/**
 * SPL Pipe Executor for SecOps Console
 *
 * Executes SPL pipe commands on an in-memory array of log rows.
 * Supports: stats, eval, rex, rename, dedup, head, tail, sort, fields, table, where, search
 *
 * Usage:
 *   const results = executeSplPipes(rows, "stats count by source | sort -count | head 10");
 */

export type SplRow = Record<string, unknown>;

/**
 * Split a pipe string into individual commands, respecting quoted strings.
 */
function splitPipes(pipeString: string): string[] {
  const parts: string[] = [];
  let current = "";
  let inQuote = false;
  let quoteChar = "";

  for (let i = 0; i < pipeString.length; i++) {
    const c = pipeString[i];
    if (inQuote) {
      current += c;
      if (c === quoteChar) inQuote = false;
    } else if (c === '"' || c === "'") {
      inQuote = true;
      quoteChar = c;
      current += c;
    } else if (c === "|") {
      if (current.trim()) parts.push(current.trim());
      current = "";
    } else {
      current += c;
    }
  }
  if (current.trim()) parts.push(current.trim());
  return parts.filter(Boolean);
}

/**
 * Execute a chain of SPL pipe commands on an array of rows.
 */
export function executeSplPipes(rows: SplRow[], pipeString: string): SplRow[] {
  if (!pipeString?.trim()) return rows;
  const pipes = splitPipes(pipeString);
  let result = rows;
  for (const pipe of pipes) {
    result = executeSinglePipe(result, pipe.trim());
    if (result.length === 0 && pipe.trim().toLowerCase().startsWith("stats")) break;
  }
  return result;
}

function getVal(row: SplRow, field: string): unknown {
  if (field in row) return row[field];
  // Try camelCase → snake_case variants
  const snake = field.replace(/([A-Z])/g, "_$1").toLowerCase();
  if (snake in row) return row[snake];
  const camel = field.replace(/_([a-z])/g, (_, c) => c.toUpperCase());
  if (camel in row) return row[camel];
  return undefined;
}

function toNum(v: unknown): number {
  if (typeof v === "number") return v;
  if (v === null || v === undefined) return NaN;
  const n = Number(v);
  return n;
}

function toStr(v: unknown): string {
  if (v === null || v === undefined) return "";
  return String(v);
}

function executeSinglePipe(rows: SplRow[], pipe: string): SplRow[] {
  const lower = pipe.toLowerCase();
  const firstWord = lower.split(/\s+/)[0];

  switch (firstWord) {
    case "head": return execHead(rows, pipe);
    case "tail": return execTail(rows, pipe);
    case "stats": return execStats(rows, pipe);
    case "eval": return execEval(rows, pipe);
    case "rex": return execRex(rows, pipe);
    case "rename": return execRename(rows, pipe);
    case "dedup": return execDedup(rows, pipe);
    case "sort": return execSort(rows, pipe);
    case "fields": return execFields(rows, pipe);
    case "table": return execTable(rows, pipe);
    case "where": return execWhere(rows, pipe);
    case "search": return execSearch(rows, pipe);
    case "reverse": return [...rows].reverse();
    case "streamstats": return rows; // not implemented, passthrough
    default: return rows;
  }
}

// ─── head / tail ──────────────────────────────────────────────────────────────

function execHead(rows: SplRow[], pipe: string): SplRow[] {
  const m = /^head\s+(\d+)$/i.exec(pipe.trim());
  const n = m ? parseInt(m[1]) : 10;
  return rows.slice(0, n);
}

function execTail(rows: SplRow[], pipe: string): SplRow[] {
  const m = /^tail\s+(\d+)$/i.exec(pipe.trim());
  const n = m ? parseInt(m[1]) : 10;
  return rows.slice(-n);
}

// ─── dedup ────────────────────────────────────────────────────────────────────

function execDedup(rows: SplRow[], pipe: string): SplRow[] {
  const spec = pipe.replace(/^dedup\s+/i, "").trim();
  const fields = spec.split(/[\s,]+/).filter(Boolean);
  if (fields.length === 0) return rows;
  const seen = new Set<string>();
  return rows.filter(row => {
    const key = fields.map(f => toStr(getVal(row, f))).join("|§|");
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// ─── sort ─────────────────────────────────────────────────────────────────────

function execSort(rows: SplRow[], pipe: string): SplRow[] {
  const spec = pipe.replace(/^sort\s+/i, "").trim();
  // Handle "sort 20 -field" (with limit)
  let limit = 0;
  let sortSpec = spec;
  const limitMatch = /^(\d+)\s+/.exec(spec);
  if (limitMatch) {
    limit = parseInt(limitMatch[1]);
    sortSpec = spec.slice(limitMatch[0].length);
  }

  const parts = sortSpec.split(/[\s,]+/).filter(Boolean);
  const sorted = [...rows].sort((a, b) => {
    for (const part of parts) {
      const dir = part.startsWith("-") ? -1 : 1;
      const field = part.replace(/^[+-]/, "");
      const av = getVal(a, field);
      const bv = getVal(b, field);
      if (av === bv) continue;
      if (av === null || av === undefined) return dir;
      if (bv === null || bv === undefined) return -dir;
      const na = toNum(av), nb = toNum(bv);
      if (!isNaN(na) && !isNaN(nb)) return (na - nb) * dir;
      return toStr(av).localeCompare(toStr(bv)) * dir;
    }
    return 0;
  });
  return limit > 0 ? sorted.slice(0, limit) : sorted;
}

// ─── rename ───────────────────────────────────────────────────────────────────

function execRename(rows: SplRow[], pipe: string): SplRow[] {
  const spec = pipe.replace(/^rename\s+/i, "").trim();
  const renames: { from: string; to: string }[] = [];
  for (const part of spec.split(",")) {
    const m = part.trim().match(/^(\S+)\s+(?:AS|as)\s+(\S+)$/);
    if (m) renames.push({ from: m[1], to: m[2] });
  }
  if (renames.length === 0) return rows;
  return rows.map(row => {
    const nr = { ...row };
    for (const { from, to } of renames) {
      if (from in nr) {
        nr[to] = nr[from];
        delete nr[from];
      }
    }
    return nr;
  });
}

// ─── fields ───────────────────────────────────────────────────────────────────

function execFields(rows: SplRow[], pipe: string): SplRow[] {
  const spec = pipe.replace(/^fields\s+/i, "").trim();
  const parts = spec.split(/[\s,]+/).filter(Boolean);
  const removes = parts.filter(p => p.startsWith("-")).map(p => p.slice(1));
  const keeps = parts.filter(p => !p.startsWith("-")).map(p => p.replace(/^\+/, ""));

  if (removes.length > 0 && keeps.length === 0) {
    return rows.map(row => {
      const nr = { ...row };
      for (const f of removes) delete nr[f];
      return nr;
    });
  }
  if (keeps.length > 0) {
    return rows.map(row => Object.fromEntries(keeps.map(f => [f, getVal(row, f)])));
  }
  return rows;
}

// ─── table ────────────────────────────────────────────────────────────────────

function execTable(rows: SplRow[], pipe: string): SplRow[] {
  const spec = pipe.replace(/^table\s+/i, "").trim();
  if (!spec) return rows;
  const fields = spec.split(/[\s,]+/).filter(Boolean);
  return rows.map(row => Object.fromEntries(fields.map(f => [f, getVal(row, f)])));
}

// ─── rex ──────────────────────────────────────────────────────────────────────

function execRex(rows: SplRow[], pipe: string): SplRow[] {
  // rex field=message "(?<ip>\d+\.\d+\.\d+\.\d+)"
  // rex "(?<ip>\d+\.\d+\.\d+\.\d+)"  (defaults to _raw/message)
  const fieldMatch = /field=(\w+)\s+/i.exec(pipe);
  const sourceField = fieldMatch ? fieldMatch[1] : "message";

  // Extract quoted regex
  const quoteMatch = /["'](.+)["']/.exec(pipe);
  if (!quoteMatch) return rows;

  let pattern: RegExp;
  try {
    pattern = new RegExp(quoteMatch[1]);
  } catch {
    return rows;
  }

  return rows.map(row => {
    const val = toStr(getVal(row, sourceField));
    const m = pattern.exec(val);
    if (!m || !m.groups) return row;
    return { ...row, ...m.groups };
  });
}

// ─── eval ─────────────────────────────────────────────────────────────────────

function execEval(rows: SplRow[], pipe: string): SplRow[] {
  // eval field=expression
  // expressions: field1+field2, if(cond,a,b), lower(f), upper(f), len(f), coalesce(a,b), now(), tostring(f), tonumber(f)
  const spec = pipe.replace(/^eval\s+/i, "").trim();
  const eqIdx = spec.indexOf("=");
  if (eqIdx < 0) return rows;
  const targetField = spec.slice(0, eqIdx).trim();
  const exprStr = spec.slice(eqIdx + 1).trim();

  return rows.map(row => {
    try {
      const val = evalExpression(exprStr, row);
      return { ...row, [targetField]: val };
    } catch {
      return row;
    }
  });
}

function evalExpression(expr: string, row: SplRow): unknown {
  const e = expr.trim();

  // String literal
  if ((e.startsWith('"') && e.endsWith('"')) || (e.startsWith("'") && e.endsWith("'"))) {
    return e.slice(1, -1);
  }

  // Numeric literal
  if (/^-?\d+(\.\d+)?$/.test(e)) return Number(e);

  // Functions
  if (/^if\s*\(/i.test(e)) return evalIf(e, row);
  if (/^coalesce\s*\(/i.test(e)) return evalCoalesce(e, row);
  if (/^lower\s*\(/i.test(e)) return toStr(evalArg(e, row)).toLowerCase();
  if (/^upper\s*\(/i.test(e)) return toStr(evalArg(e, row)).toUpperCase();
  if (/^len\s*\(/i.test(e)) return toStr(evalArg(e, row)).length;
  if (/^trim\s*\(/i.test(e)) return toStr(evalArg(e, row)).trim();
  if (/^tostring\s*\(/i.test(e)) return toStr(evalArg(e, row));
  if (/^tonumber\s*\(/i.test(e)) return toNum(evalArg(e, row));
  if (/^now\s*\(\)/i.test(e)) return Date.now();
  if (/^round\s*\(/i.test(e)) {
    const args = extractArgs(e);
    const n = toNum(evalExpression(args[0] ?? "", row));
    const decimals = args[1] ? parseInt(args[1]) : 0;
    return Math.round(n * Math.pow(10, decimals)) / Math.pow(10, decimals);
  }
  if (/^substr\s*\(/i.test(e)) {
    const args = extractArgs(e);
    const s = toStr(evalExpression(args[0] ?? "", row));
    const start = args[1] ? parseInt(args[1]) - 1 : 0; // SPL is 1-indexed
    const len = args[2] ? parseInt(args[2]) : undefined;
    return len !== undefined ? s.substr(start, len) : s.substr(start);
  }
  if (/^replace\s*\(/i.test(e)) {
    const args = extractArgs(e);
    const s = toStr(evalExpression(args[0] ?? "", row));
    const pattern = args[1] ? args[1].replace(/^["']|["']$/g, "") : "";
    const repl = args[2] ? args[2].replace(/^["']|["']$/g, "") : "";
    try { return s.replace(new RegExp(pattern, "g"), repl); } catch { return s; }
  }

  // Arithmetic: simple a+b, a-b, a*b, a/b, a.b (string concat with .)
  const arithMatch = /^(.+?)\s*([+\-*/.])\s*(.+)$/.exec(e);
  if (arithMatch) {
    const left = evalExpression(arithMatch[1].trim(), row);
    const op = arithMatch[2];
    const right = evalExpression(arithMatch[3].trim(), row);
    if (op === ".") return toStr(left) + toStr(right);
    const nl = toNum(left), nr = toNum(right);
    if (op === "+") return nl + nr;
    if (op === "-") return nl - nr;
    if (op === "*") return nl * nr;
    if (op === "/") return nr !== 0 ? nl / nr : null;
  }

  // Field reference
  const val = getVal(row, e);
  return val !== undefined ? val : e;
}

function evalArg(funcExpr: string, row: SplRow): unknown {
  const m = /\((.+)\)/.exec(funcExpr);
  if (!m) return undefined;
  return evalExpression(m[1].trim(), row);
}

function extractArgs(funcExpr: string): string[] {
  const m = /\((.+)\)/.exec(funcExpr);
  if (!m) return [];
  return splitArgs(m[1]);
}

function splitArgs(s: string): string[] {
  const args: string[] = [];
  let current = "";
  let depth = 0;
  let inQ = false;
  let qChar = "";
  for (const c of s) {
    if (inQ) { current += c; if (c === qChar) inQ = false; continue; }
    if (c === '"' || c === "'") { inQ = true; qChar = c; current += c; continue; }
    if (c === "(") { depth++; current += c; continue; }
    if (c === ")") { depth--; current += c; continue; }
    if (c === "," && depth === 0) { args.push(current.trim()); current = ""; continue; }
    current += c;
  }
  if (current.trim()) args.push(current.trim());
  return args;
}

function evalIf(expr: string, row: SplRow): unknown {
  const args = extractArgs(expr);
  if (args.length < 2) return null;
  const cond = evalCondition(args[0], row);
  return cond ? evalExpression(args[1], row) : (args[2] ? evalExpression(args[2], row) : null);
}

function evalCoalesce(expr: string, row: SplRow): unknown {
  const args = extractArgs(expr);
  for (const arg of args) {
    const v = evalExpression(arg, row);
    if (v !== null && v !== undefined && v !== "") return v;
  }
  return null;
}

function evalCondition(cond: string, row: SplRow): boolean {
  const c = cond.trim();
  // field=value, field!=value, field>value, field<value, field>=value, field<=value
  const m = /^(.+?)\s*(!=|>=|<=|=|>|<)\s*(.+)$/.exec(c);
  if (m) {
    const left = evalExpression(m[1].trim(), row);
    const op = m[2];
    const right = evalExpression(m[3].trim(), row);
    const nl = toNum(left), nr = toNum(right);
    const useNum = !isNaN(nl) && !isNaN(nr);
    if (op === "=" || op === "==") return useNum ? nl === nr : toStr(left) === toStr(right);
    if (op === "!=") return useNum ? nl !== nr : toStr(left) !== toStr(right);
    if (op === ">") return useNum ? nl > nr : toStr(left) > toStr(right);
    if (op === "<") return useNum ? nl < nr : toStr(left) < toStr(right);
    if (op === ">=") return useNum ? nl >= nr : toStr(left) >= toStr(right);
    if (op === "<=") return useNum ? nl <= nr : toStr(left) <= toStr(right);
  }
  // Boolean field check
  const v = evalExpression(c, row);
  return !!v && v !== "false" && v !== "0";
}

// ─── where ────────────────────────────────────────────────────────────────────

function execWhere(rows: SplRow[], pipe: string): SplRow[] {
  const cond = pipe.replace(/^where\s+/i, "").trim();
  return rows.filter(row => {
    try { return evalCondition(cond, row); } catch { return true; }
  });
}

// ─── search ───────────────────────────────────────────────────────────────────

function execSearch(rows: SplRow[], pipe: string): SplRow[] {
  const term = pipe.replace(/^search\s+/i, "").trim().toLowerCase();
  if (!term) return rows;
  return rows.filter(row =>
    Object.values(row).some(v => toStr(v).toLowerCase().includes(term))
  );
}

// ─── stats ────────────────────────────────────────────────────────────────────

type AggFn = "count" | "dc" | "avg" | "sum" | "min" | "max" | "list" | "values" | "first" | "last";

interface AggSpec {
  fn: AggFn;
  field: string | null;
  alias: string;
}

function parseAggSpecs(s: string): AggSpec[] {
  const specs: AggSpec[] = [];
  // Match: count, count(field), avg(field) as alias, dc(field)
  const re = /(\w+)\(([^)]*)\)(?:\s+as\s+(\w+))?|(\bcount\b)(?:\s+as\s+(\w+))?/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(s)) !== null) {
    if (m[4]) {
      // bare count
      specs.push({ fn: "count", field: null, alias: m[5] ?? "count" });
    } else {
      const fn = m[1].toLowerCase() as AggFn;
      const field = m[2].trim() || null;
      const alias = m[3] ?? (field ? `${fn}(${field})` : fn);
      specs.push({ fn, field, alias });
    }
  }
  if (specs.length === 0) {
    specs.push({ fn: "count", field: null, alias: "count" });
  }
  return specs;
}

function execStats(rows: SplRow[], pipe: string): SplRow[] {
  // stats [agg(field) as alias]... [by field1, field2]
  const lower = pipe.toLowerCase();
  const byIdx = lower.lastIndexOf(" by ");
  let aggPart: string;
  let byFields: string[] = [];

  if (byIdx >= 0) {
    aggPart = pipe.slice(6, byIdx).trim(); // skip "stats "
    byFields = pipe.slice(byIdx + 4).trim().split(/[\s,]+/).filter(Boolean);
  } else {
    aggPart = pipe.slice(6).trim(); // skip "stats "
  }

  const aggSpecs = parseAggSpecs(aggPart || "count");

  // Group rows
  type Group = { rows: SplRow[]; key: Record<string, unknown> };
  const groups = new Map<string, Group>();

  for (const row of rows) {
    const keyObj: Record<string, unknown> = {};
    for (const f of byFields) keyObj[f] = getVal(row, f) ?? "";
    const keyStr = JSON.stringify(keyObj);
    if (!groups.has(keyStr)) groups.set(keyStr, { rows: [], key: keyObj });
    groups.get(keyStr)!.rows.push(row);
  }

  if (groups.size === 0 && rows.length === 0) {
    // empty result
    const result: SplRow = {};
    for (const spec of aggSpecs) result[spec.alias] = 0;
    return [result];
  }

  const results: SplRow[] = [];
  for (const { rows: grpRows, key } of groups.values()) {
    const result: SplRow = { ...key };
    for (const spec of aggSpecs) {
      result[spec.alias] = computeAgg(grpRows, spec);
    }
    results.push(result);
  }

  return results;
}

function computeAgg(rows: SplRow[], spec: AggSpec): unknown {
  const { fn, field } = spec;

  if (fn === "count") {
    if (!field) return rows.length;
    return rows.filter(r => getVal(r, field) != null && getVal(r, field) !== "").length;
  }

  if (fn === "dc") {
    if (!field) return rows.length;
    return new Set(rows.map(r => toStr(getVal(r, field)))).size;
  }

  if (fn === "list" || fn === "values") {
    if (!field) return [];
    const vals = rows.map(r => getVal(r, field)).filter(v => v != null);
    return fn === "values" ? [...new Set(vals.map(toStr))] : vals;
  }

  if (fn === "first") {
    return field && rows.length > 0 ? getVal(rows[0], field) : null;
  }

  if (fn === "last") {
    return field && rows.length > 0 ? getVal(rows[rows.length - 1], field) : null;
  }

  // Numeric aggregations
  if (!field) return null;
  const nums = rows.map(r => toNum(getVal(r, field))).filter(n => !isNaN(n));
  if (nums.length === 0) return null;

  if (fn === "sum") return nums.reduce((a, b) => a + b, 0);
  if (fn === "avg") return nums.reduce((a, b) => a + b, 0) / nums.length;
  if (fn === "min") return Math.min(...nums);
  if (fn === "max") return Math.max(...nums);

  return null;
}

export { splitPipes, executeSinglePipe };
