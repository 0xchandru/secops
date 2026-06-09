import yaml from "js-yaml";
import crypto from "crypto";
import { db, rulesTable } from "../../db";
import { eq } from "drizzle-orm";
import type { DetectionRule, NormalizedEvent, TriggeredAlert, ThresholdConfig, SequenceConfig, SequenceStep, RuleExceptions } from "./types";

interface ThresholdState {
  timeframeSecs: number;
  buckets: Map<string, Date[]>;
}

interface SequenceState {
  timeframeSecs: number;
  byField?: string;
  steps: SequenceStep[];
  progress: Map<string, Array<{ step: number; ts: Date }>>;
}

interface RateLimitState {
  maxPerHour: number;
  timestamps: Date[];
}

class DetectionEngine {
  private rules: DetectionRule[] = [];
  private thresholdStates: Map<string, ThresholdState> = new Map();
  private sequenceStates: Map<string, SequenceState> = new Map();
  private rateLimits: Map<string, RateLimitState> = new Map();
  private dedupWindows: Map<string, Map<string, Date>> = new Map();
  private lastLoaded: Date = new Date(0);

  private rulesByCategory: Map<string, DetectionRule[]> = new Map();
  private rulesBySourceType: Map<string, DetectionRule[]> = new Map();
  private universalRules: DetectionRule[] = [];

  private buildIndex(): void {
    this.rulesByCategory.clear();
    this.rulesBySourceType.clear();
    this.universalRules = [];

    for (const rule of this.rules) {
      let indexed = false;
      const match = rule.match ?? {};

      if (match.category && typeof match.category === "string") {
        const cat = match.category.toLowerCase();
        const list = this.rulesByCategory.get(cat) ?? [];
        list.push(rule);
        this.rulesByCategory.set(cat, list);
        indexed = true;
      }
      if (match.sourceType && typeof match.sourceType === "string") {
        const st = match.sourceType.toLowerCase();
        const list = this.rulesBySourceType.get(st) ?? [];
        list.push(rule);
        this.rulesBySourceType.set(st, list);
        indexed = true;
      }

      if (!indexed) {
        this.universalRules.push(rule);
      }
    }
  }

  getCandidateRules(event: NormalizedEvent): DetectionRule[] {
    const candidates = new Set<DetectionRule>();

    for (const r of this.universalRules) candidates.add(r);

    if (event.category) {
      const catRules = this.rulesByCategory.get(event.category.toLowerCase());
      if (catRules) for (const r of catRules) candidates.add(r);
    }

    if (event.sourceType) {
      const stRules = this.rulesBySourceType.get(event.sourceType.toLowerCase());
      if (stRules) for (const r of stRules) candidates.add(r);
    }

    return Array.from(candidates);
  }

  async loadRulesFromDb(): Promise<void> {
    const rows = await db.select().from(rulesTable).where(eq(rulesTable.enabled, true));
    this.rules = [];
    for (const row of rows) {
      if (!row.yamlContent) continue;
      try {
        const parsed = yaml.load(row.yamlContent) as any;
        const rule: DetectionRule = {
          id: row.id,
          name: parsed.name ?? row.name,
          description: parsed.description ?? row.description ?? "",
          author: parsed.author,
          severity: parsed.severity ?? row.severity ?? "medium",
          type: parsed.type ?? "simple",
          enabled: row.enabled,
          match: parsed.match ?? {},
          filter: parsed.filter,
          threshold: parsed.threshold,
          sequence: parsed.sequence ? {
            steps: (parsed.sequence.steps ?? []).map((s: any) => ({ match: s.match ?? {}, filter: s.filter })),
            timeframe: parsed.sequence.timeframe ?? "5m",
            byField: parsed.sequence.by_field,
          } : undefined,
          riskSumConfig: parsed.risk_sum ? {
            field: parsed.risk_sum.field,
            sumThreshold: parsed.risk_sum.sum_threshold ?? 200,
            timeframe: parsed.risk_sum.timeframe ?? "1h",
          } : undefined,
          anomalyConfig: parsed.anomaly ? {
            stddevMultiplier: parsed.anomaly.stddev_multiplier ?? 3,
            baselineField: parsed.anomaly.baseline_field,
          } : undefined,
          maxAlertsPerHour: parsed.max_alerts_per_hour ?? parsed.maxAlertsPerHour,
          dedupWindow: parsed.dedup_window ?? parsed.dedupWindow,
          mitre: parsed.mitre ? {
            tactic: parsed.mitre.tactic,
            techniqueId: parsed.mitre.technique_id,
            techniqueName: parsed.mitre.technique_name,
            subtechniqueId: parsed.mitre.subtechnique_id,
            subtechniqueName: parsed.mitre.subtechnique_name,
          } : undefined,
          alert: {
            titleTemplate: parsed.alert?.title_template ?? row.name,
            contextFields: parsed.alert?.context_fields ?? [],
          },
          tags: parsed.tags ?? row.tags ?? [],
          exceptions: this.parseExceptions(parsed.exceptions ?? row.exceptions),
        };
        this.rules.push(rule);

        if (rule.type === "threshold" && rule.threshold) {
          const tfSecs = parseTimeframe(rule.threshold.timeframe);
          if (!this.thresholdStates.has(rule.id)) {
            this.thresholdStates.set(rule.id, { timeframeSecs: tfSecs, buckets: new Map() });
          }
        }

        if (rule.type === "sequence" && rule.sequence) {
          const tfSecs = parseTimeframe(rule.sequence.timeframe);
          if (!this.sequenceStates.has(rule.id)) {
            this.sequenceStates.set(rule.id, {
              timeframeSecs: tfSecs,
              byField: rule.sequence.byField,
              steps: rule.sequence.steps,
              progress: new Map(),
            });
          }
        }

        if (rule.maxAlertsPerHour) {
          if (!this.rateLimits.has(rule.id)) {
            this.rateLimits.set(rule.id, { maxPerHour: rule.maxAlertsPerHour, timestamps: [] });
          }
        }
      } catch (err) {
        // skip bad YAML
      }
    }
    this.rules.sort((a, b) => {
      const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
      return (order[a.severity] ?? 4) - (order[b.severity] ?? 4);
    });
    this.buildIndex();
    this.lastLoaded = new Date();
  }

  private parseExceptions(raw: any): RuleExceptions | undefined {
    if (!raw || typeof raw !== "object") return undefined;
    const ex: RuleExceptions = {};
    if (Array.isArray(raw.ips)) ex.ips = raw.ips.map(String);
    if (Array.isArray(raw.cidrs)) ex.cidrs = raw.cidrs.map(String);
    if (Array.isArray(raw.hostnames)) ex.hostnames = raw.hostnames.map(String);
    if (Array.isArray(raw.usernames)) ex.usernames = raw.usernames.map(String);
    return Object.keys(ex).length > 0 ? ex : undefined;
  }

  /** Check if an event matches an exceptions list — returns true if the event should be suppressed */
  private isExcepted(event: NormalizedEvent, exceptions?: RuleExceptions): boolean {
    if (!exceptions) return false;

    if (exceptions.ips?.length) {
      const ip = event.srcIp ?? event.dstIp ?? "";
      if (exceptions.ips.some(x => x === ip)) return true;
    }

    if (exceptions.cidrs?.length) {
      const ip = event.srcIp ?? "";
      if (ip && exceptions.cidrs.some(c => isIpInCidr(ip, c))) return true;
    }

    if (exceptions.hostnames?.length) {
      const host = (event.sourceHost ?? "").toLowerCase();
      if (exceptions.hostnames.some(h => h.toLowerCase() === host)) return true;
    }

    if (exceptions.usernames?.length) {
      const user = (event.userName ?? "").toLowerCase();
      if (user && exceptions.usernames.some(u => u.toLowerCase() === user)) return true;
    }

    return false;
  }

  evaluate(event: NormalizedEvent): TriggeredAlert[] {
    const alerts: TriggeredAlert[] = [];
    const candidates = this.getCandidateRules(event);
    for (const rule of candidates) {
      if (!rule.enabled) continue;

      if (rule.maxAlertsPerHour && this.isRateLimited(rule.id)) continue;

      // Check exceptions/suppression list
      if (this.isExcepted(event, rule.exceptions)) continue;

      if (rule.type === "simple") {
        if (!this.matches(event, rule.match)) continue;
        if (rule.filter && this.matches(event, rule.filter)) continue;

        const dedupKey = computeDedupKey(rule.id, {});
        if (rule.dedupWindow && this.isWindowedDuplicate(rule.id, dedupKey, rule.dedupWindow)) continue;

        const alert = this.createAlert(rule, event, {});
        this.recordRateLimit(rule.id);
        alerts.push(alert);

      } else if (rule.type === "threshold" && rule.threshold) {
        if (!this.matches(event, rule.match)) continue;
        if (rule.filter && this.matches(event, rule.filter)) continue;

        const state = this.thresholdStates.get(rule.id);
        if (!state) continue;
        const keyValue = event[rule.threshold.field];
        if (keyValue == null) continue;
        const groupKey = String(keyValue);
        const [triggered, count] = this.addAndCheck(state, groupKey, event.timestamp, rule.threshold.count);
        if (triggered) {
          const extra: Record<string, any> = { count };
          extra[rule.threshold.field] = groupKey;

          const dedupKey = computeDedupKey(rule.id, extra);
          if (rule.dedupWindow && this.isWindowedDuplicate(rule.id, dedupKey, rule.dedupWindow)) {
            this.clearKey(state, groupKey);
            continue;
          }

          const alert = this.createAlert(rule, event, extra);
          this.recordRateLimit(rule.id);
          alerts.push(alert);
          this.clearKey(state, groupKey);
        }

      } else if (rule.type === "sequence" && rule.sequence) {
        const seqState = this.sequenceStates.get(rule.id);
        if (!seqState) continue;

        const groupKey = seqState.byField ? String(event[seqState.byField] ?? "global") : "global";
        const progress = seqState.progress.get(groupKey) ?? [];
        const now = event.timestamp;
        const cutoff = new Date(now.getTime() - seqState.timeframeSecs * 1000);

        const validProgress = progress.filter((p) => p.ts > cutoff);

        for (let stepIdx = 0; stepIdx < seqState.steps.length; stepIdx++) {
          const step = seqState.steps[stepIdx];
          if (!this.matches(event, step.match)) continue;
          if (step.filter && this.matches(event, step.filter)) continue;

          if (stepIdx === 0) {
            validProgress.push({ step: 0, ts: now });
          } else {
            const prevCompleted = validProgress.some((p) => p.step === stepIdx - 1);
            if (prevCompleted) {
              validProgress.push({ step: stepIdx, ts: now });
            }
          }

          if (stepIdx === seqState.steps.length - 1) {
            const allStepsPresent = Array.from({ length: seqState.steps.length }, (_, i) => i)
              .every((i) => validProgress.some((p) => p.step === i));
            if (allStepsPresent) {
              const extra: Record<string, any> = {
                sequenceSteps: seqState.steps.length,
                groupKey,
              };

              const dedupKey = computeDedupKey(rule.id, extra);
              if (rule.dedupWindow && this.isWindowedDuplicate(rule.id, dedupKey, rule.dedupWindow)) continue;

              const alert = this.createAlert(rule, event, extra);
              this.recordRateLimit(rule.id);
              alerts.push(alert);
              seqState.progress.set(groupKey, []);
              break;
            }
          }
        }

        seqState.progress.set(groupKey, validProgress);
      }
      // risk_score_sum and anomaly are handled by the scheduler, not the per-event engine
    }
    return alerts;
  }

  /**
   * Test a rule YAML against an array of sample events without persisting.
   */
  testRule(yamlContent: string, events: NormalizedEvent[]): TriggeredAlert[] {
    let parsed: any;
    try {
      parsed = yaml.load(yamlContent) as any;
    } catch {
      return [];
    }

    const rule: DetectionRule = {
      id: "test-rule",
      name: parsed.name ?? "Test Rule",
      description: parsed.description ?? "",
      severity: parsed.severity ?? "medium",
      type: parsed.type ?? "simple",
      enabled: true,
      match: parsed.match ?? {},
      filter: parsed.filter,
      threshold: parsed.threshold,
      sequence: parsed.sequence,
      exceptions: this.parseExceptions(parsed.exceptions),
      alert: {
        titleTemplate: parsed.alert?.title_template ?? parsed.name ?? "Test Alert",
        contextFields: parsed.alert?.context_fields ?? [],
      },
      tags: parsed.tags ?? [],
    };

    const results: TriggeredAlert[] = [];
    for (const event of events) {
      if (this.isExcepted(event, rule.exceptions)) continue;

      if (rule.type === "simple") {
        if (this.matches(event, rule.match)) {
          if (!rule.filter || !this.matches(event, rule.filter)) {
            results.push(this.createAlert(rule, event, {}));
          }
        }
      } else if (rule.type === "threshold" && rule.threshold) {
        // For test mode: count occurrences and return one result if threshold met
        if (this.matches(event, rule.match)) {
          if (!rule.filter || !this.matches(event, rule.filter)) {
            results.push(this.createAlert(rule, event, {}));
          }
        }
      }
    }
    return results;
  }

  private matches(event: NormalizedEvent, conditions: Record<string, any>): boolean {
    for (const [key, expected] of Object.entries(conditions)) {
      const parts = key.split("|");
      const fieldName = parts[0];
      const modifiers = parts.slice(1);

      const actual = event[fieldName];

      if (modifiers[0] === "exists") {
        const shouldExist = expected === true || expected === "true";
        if (shouldExist && actual == null) return false;
        if (!shouldExist && actual != null) return false;
        continue;
      }

      const isNegated = modifiers[0] === "not";
      const effectiveModifiers = isNegated ? modifiers.slice(1) : modifiers;

      if (actual == null) return false;
      const actualStr = String(actual).toLowerCase();

      let matched = false;

      if (effectiveModifiers.length === 0) {
        if (Array.isArray(expected)) {
          matched = expected.some(v => String(v).toLowerCase() === actualStr);
        } else {
          matched = actualStr === String(expected).toLowerCase();
        }
      } else if (effectiveModifiers[0] === "contains" && effectiveModifiers[1] === "any") {
        const list = Array.isArray(expected) ? expected : [expected];
        matched = list.some(v => actualStr.includes(String(v).toLowerCase()));
      } else if (effectiveModifiers[0] === "contains") {
        if (Array.isArray(expected)) {
          matched = expected.some(v => actualStr.includes(String(v).toLowerCase()));
        } else {
          matched = actualStr.includes(String(expected).toLowerCase());
        }
      } else if (effectiveModifiers[0] === "endswith") {
        matched = actualStr.endsWith(String(expected).toLowerCase());
      } else if (effectiveModifiers[0] === "startswith") {
        matched = actualStr.startsWith(String(expected).toLowerCase());
      } else if (effectiveModifiers[0] === "re") {
        const regex = new RegExp(String(expected), "i");
        matched = regex.test(String(actual));
      } else if (effectiveModifiers[0] === "gt") {
        matched = Number(actual) > Number(expected);
      } else if (effectiveModifiers[0] === "gte") {
        matched = Number(actual) >= Number(expected);
      } else if (effectiveModifiers[0] === "lt") {
        matched = Number(actual) < Number(expected);
      } else if (effectiveModifiers[0] === "lte") {
        matched = Number(actual) <= Number(expected);
      } else if (effectiveModifiers[0] === "cidr") {
        const cidrs = Array.isArray(expected) ? expected : [expected];
        matched = cidrs.some(c => isIpInCidr(String(actual), String(c)));
      } else {
        matched = actualStr === String(expected).toLowerCase();
      }

      if (isNegated ? matched : !matched) return false;
    }
    return true;
  }

  private createAlert(rule: DetectionRule, event: NormalizedEvent, extra: Record<string, any>): TriggeredAlert {
    const context: Record<string, any> = {};
    for (const field of (rule.alert.contextFields ?? [])) {
      context[field] = event[field];
    }
    Object.assign(context, extra);

    const templateVars: Record<string, any> = { ...flattenEvent(event), ...extra };
    const title = rule.alert.titleTemplate.replace(/\{(\w+)\}/g, (_, k) => String(templateVars[k] ?? `{${k}}`));

    const severityScore = this.computeSeverityScore(rule, event);
    const dedupKey = computeDedupKey(rule.id, extra);

    return {
      ruleId: rule.id,
      ruleName: rule.name,
      title,
      description: rule.description,
      severity: rule.severity,
      severityScore,
      mitreTactic: rule.mitre?.tactic,
      mitreTechniqueId: rule.mitre?.techniqueId,
      mitreTechniqueName: rule.mitre?.techniqueName,
      mitreSubtechniqueId: rule.mitre?.subtechniqueId,
      sourceHost: event.sourceHost,
      triggerEventId: event.id,
      triggerTimestamp: event.timestamp,
      context,
      tags: rule.tags ?? [],
      dedupKey,
      sourceIp: event.srcIp,
      destIp: event.dstIp,
      hostname: event.sourceHost,
    };
  }

  private computeSeverityScore(rule: DetectionRule, event: NormalizedEvent): number {
    const base: Record<string, number> = { critical: 90, high: 70, medium: 45, low: 20 };
    let score = base[rule.severity] ?? 30;
    if (event.assetCriticality === "high") score = Math.min(100, score + 15);
    else if (event.assetCriticality === "medium") score = Math.min(100, score + 5);
    if (event.userName && ["administrator", "admin", "root"].includes(event.userName.toLowerCase())) {
      score = Math.min(100, score + 10);
    }
    if (event.geoCountry && event.geoCountry !== "US") score = Math.min(100, score + 5);
    return score;
  }

  private addAndCheck(state: ThresholdState, key: string, ts: Date, threshold: number): [boolean, number] {
    const cutoff = new Date(ts.getTime() - state.timeframeSecs * 1000);
    const existing = (state.buckets.get(key) ?? []).filter(t => t > cutoff);
    existing.push(ts);
    state.buckets.set(key, existing);
    return [existing.length >= threshold, existing.length];
  }

  private clearKey(state: ThresholdState, key: string): void {
    state.buckets.delete(key);
  }

  private isRateLimited(ruleId: string): boolean {
    const state = this.rateLimits.get(ruleId);
    if (!state) return false;
    const oneHourAgo = new Date(Date.now() - 3600_000);
    state.timestamps = state.timestamps.filter((t) => t > oneHourAgo);
    return state.timestamps.length >= state.maxPerHour;
  }

  private recordRateLimit(ruleId: string): void {
    const state = this.rateLimits.get(ruleId);
    if (!state) return;
    state.timestamps.push(new Date());
  }

  private isWindowedDuplicate(ruleId: string, dedupKey: string, window: string): boolean {
    const windowSecs = parseTimeframe(window);
    let map = this.dedupWindows.get(ruleId);
    if (!map) {
      map = new Map();
      this.dedupWindows.set(ruleId, map);
    }
    const lastSeen = map.get(dedupKey);
    const now = new Date();
    if (lastSeen && now.getTime() - lastSeen.getTime() < windowSecs * 1000) {
      return true;
    }
    map.set(dedupKey, now);

    if (map.size > 1000) {
      const cutoff = new Date(now.getTime() - windowSecs * 1000);
      for (const [k, v] of map) {
        if (v < cutoff) map.delete(k);
      }
    }
    return false;
  }

  getRules(): DetectionRule[] {
    return this.rules;
  }
}

function isIpInCidr(ip: string, cidr: string): boolean {
  const [subnet, bitsStr] = cidr.split("/");
  if (!bitsStr) return ip === cidr;
  const bits = parseInt(bitsStr, 10);
  if (bits < 0 || bits > 32) return false;

  const ipNum = ipToInt(ip);
  const subnetNum = ipToInt(subnet);
  if (ipNum === null || subnetNum === null) return false;

  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipNum & mask) === (subnetNum & mask);
}

function ipToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let result = 0;
  for (const part of parts) {
    const n = parseInt(part, 10);
    if (isNaN(n) || n < 0 || n > 255) return null;
    result = (result << 8) | n;
  }
  return result >>> 0;
}

function parseTimeframe(tf: string): number {
  const match = tf.match(/^(\d+)([smhd])$/);
  if (!match) return 300;
  const n = parseInt(match[1]);
  const units: Record<string, number> = { s: 1, m: 60, h: 3600, d: 86400 };
  return n * (units[match[2]] ?? 60);
}

function flattenEvent(event: NormalizedEvent): Record<string, any> {
  return {
    ...event,
    source_host: event.sourceHost,
    source_type: event.sourceType,
    category: event.category,
    action: event.action,
    user_name: event.userName,
    src_ip: event.srcIp,
    dst_ip: event.dstIp,
    process_name: event.processName,
    process_command_line: event.processCommandLine,
    parent_process_name: event.parentProcessName,
    geo_country: event.geoCountry,
  };
}

function computeDedupKey(ruleId: string, extra: Record<string, any>): string {
  const str = ruleId + JSON.stringify(Object.entries(extra).sort());
  return crypto.createHash("sha256").update(str).digest("hex").slice(0, 32);
}

export { isIpInCidr, parseTimeframe };
export const detectionEngine = new DetectionEngine();
