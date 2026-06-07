import type { ParsedEvent } from "./types";

export interface ParserPlugin {
  name: string;
  sourceTypes: string[];
  priority: number;
  canParse(raw: string): boolean;
  parse(raw: string, sourceHost: string): ParsedEvent | null;
}

const registry: ParserPlugin[] = [];

export function registerParser(plugin: ParserPlugin): void {
  registry.push(plugin);
  registry.sort((a, b) => a.priority - b.priority);
}

export function getRegisteredParsers(): readonly ParserPlugin[] {
  return registry;
}

export function parseLogViaRegistry(
  raw: string,
  sourceType: string,
  sourceHost: string,
  fallback: (raw: string, sourceHost: string, sourceType: string) => ParsedEvent,
): ParsedEvent | null {
  // 1. Exact sourceType match
  for (const p of registry) {
    if (p.sourceTypes.includes(sourceType)) {
      const result = p.parse(raw, sourceHost);
      if (result) return result;
    }
  }
  // 2. Auto-detection via canParse()
  for (const p of registry) {
    if (p.canParse(raw)) {
      const result = p.parse(raw, sourceHost);
      if (result) return result;
    }
  }
  // 3. Fallback to generic
  return fallback(raw, sourceHost, sourceType);
}
