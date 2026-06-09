import nodemailer from "nodemailer";
import { db, systemSettingsTable } from "../db";
import { eq } from "drizzle-orm";
import { decrypt } from "./crypto-utils";
import { logger } from "./logger";

/* ── Settings helpers ───────────────────────────────────────────────────── */

async function getSetting(key: string): Promise<string | null> {
  const row = await db
    .select()
    .from(systemSettingsTable)
    .where(eq(systemSettingsTable.key, key))
    .limit(1);
  if (!row[0]) return null;
  return row[0].encrypted ? decrypt(row[0].value) : row[0].value;
}

export async function getEmailConfig(): Promise<{
  enabled: boolean; host: string; port: number;
  username: string; password: string; from: string;
} | null> {
  const enabled = await getSetting("notifications.email.enabled");
  if (enabled !== "true") return null;
  const host = (await getSetting("notifications.email.host")) ?? "";
  const port = parseInt((await getSetting("notifications.email.port")) ?? "587");
  const username = (await getSetting("notifications.email.username")) ?? "";
  const password = (await getSetting("notifications.email.password")) ?? "";
  const from = (await getSetting("notifications.email.from")) ?? username;
  if (!host || !username) return null;
  return { enabled: true, host, port, username, password, from };
}

export async function getSlackConfig(): Promise<{
  enabled: boolean; webhookUrl: string;
} | null> {
  const enabled = await getSetting("notifications.slack.enabled");
  if (enabled !== "true") return null;
  const webhookUrl = (await getSetting("notifications.slack.webhookUrl")) ?? "";
  if (!webhookUrl) return null;
  return { enabled: true, webhookUrl };
}

export async function getThreatLensConfig(): Promise<{
  url: string; apiKey: string;
} | null> {
  const url = (await getSetting("integrations.threatlens.url")) ?? process.env["THREATLENS_API_URL"] ?? "";
  const apiKey = (await getSetting("integrations.threatlens.apiKey")) ?? process.env["THREATLENS_API_KEY"] ?? "";
  if (!url) return null;
  return { url, apiKey };
}

/* ── Email Transport ────────────────────────────────────────────────────── */

export async function sendEmail(opts: {
  to: string;
  subject: string;
  html: string;
  text?: string;
}): Promise<{ success: boolean; error?: string }> {
  try {
    const cfg = await getEmailConfig();
    if (!cfg) return { success: false, error: "Email notifications are not configured or disabled" };

    const transporter = nodemailer.createTransport({
      host: cfg.host,
      port: cfg.port,
      secure: cfg.port === 465,
      auth: cfg.username ? { user: cfg.username, pass: cfg.password } : undefined,
      connectionTimeout: 8000,
      greetingTimeout: 5000,
    });

    await transporter.sendMail({
      from: cfg.from,
      to: opts.to,
      subject: opts.subject,
      html: opts.html,
      text: opts.text ?? opts.html.replace(/<[^>]+>/g, ""),
    });

    return { success: true };
  } catch (err: any) {
    logger.warn({ err: err.message }, "Email send failed");
    return { success: false, error: err.message };
  }
}

/* ── Slack Transport ────────────────────────────────────────────────────── */

export async function sendSlack(opts: {
  text: string;
  blocks?: unknown[];
}): Promise<{ success: boolean; error?: string }> {
  try {
    const cfg = await getSlackConfig();
    if (!cfg) return { success: false, error: "Slack notifications are not configured or disabled" };

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);

    const resp = await fetch(cfg.webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: opts.text, blocks: opts.blocks }),
      signal: controller.signal,
    }).finally(() => clearTimeout(timer));

    if (!resp.ok) {
      const body = await resp.text().catch(() => "");
      return { success: false, error: `Slack responded ${resp.status}: ${body}` };
    }

    return { success: true };
  } catch (err: any) {
    logger.warn({ err: err.message }, "Slack send failed");
    return { success: false, error: err.message };
  }
}

/* ── Alert Notifications ────────────────────────────────────────────────── */

export async function notifyAlertCreated(alert: {
  id: string; alertCode?: string | null; title: string;
  severity: string; source?: string | null; mitreTactic?: string | null;
}): Promise<void> {
  const isHigh = ["critical", "high"].includes(alert.severity.toLowerCase());
  if (!isHigh) return;

  const appUrl = process.env["APP_URL"] ?? process.env["REPLIT_DEV_DOMAIN"] ?? "http://localhost:5000";
  const link = `${appUrl}/alerts/${alert.id}`;
  const sevEmoji = alert.severity === "critical" ? "🔴" : "🟠";
  const tactic = alert.mitreTactic ? ` | ${alert.mitreTactic}` : "";
  const code = alert.alertCode ?? alert.id.slice(0, 8);

  // Slack notification
  await sendSlack({
    text: `${sevEmoji} *[${alert.severity.toUpperCase()}]* New Alert: ${alert.title}`,
    blocks: [
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: `${sevEmoji} *New ${alert.severity.toUpperCase()} Alert*\n*${alert.title}*`,
        },
      },
      {
        type: "section",
        fields: [
          { type: "mrkdwn", text: `*Severity:*\n${alert.severity.toUpperCase()}` },
          { type: "mrkdwn", text: `*Alert Code:*\n${code}` },
          { type: "mrkdwn", text: `*Source:*\n${alert.source ?? "unknown"}` },
          ...(alert.mitreTactic ? [{ type: "mrkdwn", text: `*MITRE Tactic:*\n${alert.mitreTactic}` }] : []),
        ],
      },
      {
        type: "actions",
        elements: [
          {
            type: "button",
            text: { type: "plain_text", text: "Investigate Alert" },
            url: link,
            style: "danger",
          },
        ],
      },
    ],
  }).catch(() => {});

  // Email notification: look up admin/soc_manager emails to notify
  try {
    const { db: database, usersTable } = await import("../db");
    const { inArray } = await import("drizzle-orm");
    const admins = await database
      .select({ email: usersTable.email })
      .from(usersTable)
      .where(inArray(usersTable.role as any, ["admin", "soc_manager"]));

    for (const { email } of admins) {
      await sendEmail({
        to: email,
        subject: `${sevEmoji} [${alert.severity.toUpperCase()}] SecOps Alert: ${alert.title}`,
        html: `
          <div style="font-family:sans-serif;max-width:600px;">
            <h2 style="color:${alert.severity === "critical" ? "#ef4444" : "#f97316"}">
              ${sevEmoji} ${alert.severity.toUpperCase()} Alert Triggered
            </h2>
            <p><strong>${alert.title}</strong></p>
            <table style="border-collapse:collapse;width:100%">
              <tr><td style="padding:6px 0;color:#666">Alert Code</td><td><code>${code}</code></td></tr>
              <tr><td style="padding:6px 0;color:#666">Severity</td><td>${alert.severity.toUpperCase()}</td></tr>
              <tr><td style="padding:6px 0;color:#666">Source</td><td>${alert.source ?? "unknown"}</td></tr>
              ${tactic ? `<tr><td style="padding:6px 0;color:#666">MITRE Tactic</td><td>${tactic.replace(" | ", "")}</td></tr>` : ""}
            </table>
            <p style="margin-top:16px">
              <a href="${link}" style="background:#3b82f6;color:#fff;padding:10px 20px;text-decoration:none;border-radius:6px;">
                View Alert
              </a>
            </p>
          </div>`,
      }).catch(() => {});
    }
  } catch {
    // non-fatal
  }
}

export async function notifyAlertAssigned(opts: {
  alertId: string; alertCode?: string | null; title: string;
  severity: string; assigneeEmail: string; assigneeName: string;
}): Promise<void> {
  const appUrl = process.env["APP_URL"] ?? process.env["REPLIT_DEV_DOMAIN"] ?? "http://localhost:5000";
  const link = `${appUrl}/alerts/${opts.alertId}`;

  await sendEmail({
    to: opts.assigneeEmail,
    subject: `📋 Alert Assigned to You: ${opts.title}`,
    html: `
      <div style="font-family:sans-serif;max-width:600px;">
        <h2 style="color:#3b82f6">📋 Alert Assigned to You</h2>
        <p>Hi ${opts.assigneeName},</p>
        <p>The following alert has been assigned to you:</p>
        <p><strong>${opts.title}</strong></p>
        <table style="border-collapse:collapse;width:100%">
          <tr><td style="padding:6px 0;color:#666">Alert Code</td><td><code>${opts.alertCode ?? opts.alertId.slice(0, 8)}</code></td></tr>
          <tr><td style="padding:6px 0;color:#666">Severity</td><td>${opts.severity.toUpperCase()}</td></tr>
        </table>
        <p style="margin-top:16px">
          <a href="${link}" style="background:#3b82f6;color:#fff;padding:10px 20px;text-decoration:none;border-radius:6px;">
            Investigate Alert
          </a>
        </p>
      </div>`,
  }).catch(() => {});
}
