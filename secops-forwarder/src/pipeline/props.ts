import type { PropsStanza } from "../config/types.js";

export interface ParsedLine {
  raw: string;
  timestamp?: Date;
  fields: Record<string, string>;
}

const COMMON_TS_PATTERNS: Array<{ re: RegExp; parse: (m: RegExpMatchArray) => Date | null }> = [
  {
    re: /^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)/,
    parse: (m) => { try { return new Date(m[1]); } catch { return null; } },
  },
  {
    re: /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/,
    parse: (m) => {
      try {
        const d = new Date(`${m[1]} ${new Date().getFullYear()}`);
        return isNaN(d.getTime()) ? null : d;
      } catch { return null; }
    },
  },
  {
    re: /(\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})/,
    parse: (m) => {
      try {
        const raw = m[1].replace(/(\d{2})\/(\w{3})\/(\d{4}):(\d{2}:\d{2}:\d{2}) ([+-]\d{4})/, "$3-$2-$1T$4$5");
        return new Date(raw);
      } catch { return null; }
    },
  },
  {
    re: /(\d{10,13})/,
    parse: (m) => {
      const n = Number(m[1]);
      const ts = n > 1e12 ? n : n * 1000;
      return new Date(ts);
    },
  },
];

export function applyProps(line: string, props?: PropsStanza): ParsedLine {
  const result: ParsedLine = { raw: line, fields: {} };

  let timestamp: Date | null = null;

  if (props?.timePrefix) {
    const prefixRe = new RegExp(props.timePrefix);
    const m = line.match(prefixRe);
    if (m && m.index !== undefined) {
      const afterPrefix = line.slice(m.index + m[0].length).trim();
      if (props.timeFormat) {
        try {
          const d = new Date(afterPrefix.split(/\s+/).slice(0, 6).join(" "));
          if (!isNaN(d.getTime())) timestamp = d;
        } catch {}
      } else {
        for (const pattern of COMMON_TS_PATTERNS) {
          const tm = afterPrefix.match(pattern.re);
          if (tm) { timestamp = pattern.parse(tm); if (timestamp) break; }
        }
      }
    }
  }

  if (!timestamp) {
    for (const pattern of COMMON_TS_PATTERNS) {
      const m = line.match(pattern.re);
      if (m) { timestamp = pattern.parse(m); if (timestamp) break; }
    }
  }

  if (timestamp && !isNaN(timestamp.getTime())) {
    result.timestamp = timestamp;
  }

  if (props?.maxLineLength && line.length > props.maxLineLength) {
    result.raw = line.slice(0, props.maxLineLength);
  }

  return result;
}
