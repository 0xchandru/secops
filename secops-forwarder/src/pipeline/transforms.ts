import type { TransformStanza } from "../config/types.js";
import type { ParsedLine } from "./props.js";

export function applyTransforms(
  parsed: ParsedLine,
  transformNames: string[],
  transforms: Map<string, TransformStanza>,
): ParsedLine {
  const result = { ...parsed, fields: { ...parsed.fields } };

  for (const name of transformNames) {
    const transform = transforms.get(name);
    if (!transform || !transform.regex) continue;

    let re: RegExp;
    try {
      re = new RegExp(transform.regex);
    } catch {
      continue;
    }

    const match = result.raw.match(re);
    if (!match) {
      if (transform.defaultValue !== undefined) {
        result.fields[name] = transform.defaultValue;
      }
      continue;
    }

    if (transform.format) {
      const formatted = transform.format.replace(/\$(\d+)/g, (_, n) => match[Number(n)] ?? "");
      const pairs = formatted.split(/\s+/);
      for (const pair of pairs) {
        const colonIdx = pair.indexOf("::");
        if (colonIdx !== -1) {
          const key = pair.slice(0, colonIdx);
          const value = pair.slice(colonIdx + 2);
          result.fields[key] = value;
        }
      }
    } else if (match[1] !== undefined) {
      result.fields[name] = match[1];
    }

    if (transform.writeMeta && match[0]) {
      result.fields[`__transform_${name}`] = match[0];
    }
  }

  return result;
}

export function buildEvent(
  parsed: ParsedLine,
  meta: { sourcetype: string; index: string; host: string; source: string },
): Record<string, unknown> {
  return {
    message: parsed.raw,
    sourcetype: meta.sourcetype,
    index: meta.index,
    host: meta.host,
    source: meta.source,
    hostname: meta.host,
    parsedTimestamp: parsed.timestamp?.toISOString() ?? undefined,
    ...Object.fromEntries(Object.entries(parsed.fields)),
    rawData: { _raw: parsed.raw, ...parsed.fields },
  };
}
