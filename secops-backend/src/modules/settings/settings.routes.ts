import { Router } from "express";
import type { Request, Response } from "express";
import { requireAuth } from "../../middlewares/auth.middleware";
import { can } from "../../middlewares/rbac.middleware";
import { db, systemSettingsTable } from "../../db";
import { eq } from "drizzle-orm";
import { sendEmail, sendSlack, getEmailConfig, getSlackConfig, getThreatLensConfig } from "../../lib/notification-service";
import nodemailer from "nodemailer";

const router = Router();

// Sensitive values are stored ONLY in process.env (Replit secrets store),
// never in the database. The PATCH endpoint sets process.env at runtime —
// changes persist for the current server session. For permanent storage,
// set the corresponding Replit Secret: SMTP_PASSWORD, SLACK_WEBHOOK_URL,
// THREATLENS_API_KEY.

const SENSITIVE_ENV_MAP: Record<string, string> = {
  "notifications.email.password": "SMTP_PASSWORD",
  "notifications.slack.webhookUrl": "SLACK_WEBHOOK_URL",
  "integrations.threatlens.apiKey": "THREATLENS_API_KEY",
};

const DB_KEYS = new Set([
  "notifications.email.enabled",
  "notifications.email.host",
  "notifications.email.port",
  "notifications.email.username",
  "notifications.email.from",
  "notifications.slack.enabled",
  "integrations.threatlens.url",
]);

const ALL_ALLOWED = new Set([...DB_KEYS, ...Object.keys(SENSITIVE_ENV_MAP)]);

async function upsertSetting(key: string, value: string, updatedBy: string): Promise<void> {
  const existing = await db
    .select({ key: systemSettingsTable.key })
    .from(systemSettingsTable)
    .where(eq(systemSettingsTable.key, key))
    .limit(1);

  if (existing.length > 0) {
    await db
      .update(systemSettingsTable)
      .set({ value, encrypted: false, updatedAt: new Date(), updatedBy })
      .where(eq(systemSettingsTable.key, key));
  } else {
    await db.insert(systemSettingsTable).values({ key, value, encrypted: false, updatedBy });
  }
}

async function readDbSetting(key: string): Promise<string | null> {
  const row = await db
    .select()
    .from(systemSettingsTable)
    .where(eq(systemSettingsTable.key, key))
    .limit(1);
  return row[0]?.value ?? null;
}

// GET /api/settings/system — returns DB settings + env-var status for secrets
router.get("/settings/system", requireAuth, can("users:manage"), async (_req: Request, res: Response) => {
  const rows = await db.select().from(systemSettingsTable);
  const settings: Record<string, string> = {};

  for (const row of rows) {
    if (!DB_KEYS.has(row.key)) continue;
    settings[row.key] = row.value;
  }

  // For sensitive keys, return whether the env var is currently set (not the value)
  for (const [settingKey, envVar] of Object.entries(SENSITIVE_ENV_MAP)) {
    settings[settingKey] = process.env[envVar] ? "••••••••" : "";
  }

  res.json({ settings });
});

// PATCH /api/settings/system — saves non-sensitive to DB; sensitive to process.env
router.patch("/settings/system", requireAuth, can("users:manage"), async (req: Request, res: Response) => {
  const updates = req.body as Record<string, string>;
  const userId = req.user!.userId;

  for (const [key, value] of Object.entries(updates)) {
    if (!ALL_ALLOWED.has(key)) continue;
    if (typeof value !== "string") continue;

    const envVar = SENSITIVE_ENV_MAP[key];
    if (envVar) {
      // Skip unchanged sentinel values
      if (value === "••••••••" || value === "") continue;
      // Store in process.env (session-scoped — also configure as Replit Secret for persistence)
      process.env[envVar] = value;
    } else {
      await upsertSetting(key, value, userId);
    }
  }

  res.json({ ok: true });
});

// POST /api/settings/notifications/test-email
router.post("/settings/notifications/test-email", requireAuth, can("users:manage"), async (req: Request, res: Response) => {
  const { to } = req.body as { to?: string };
  const cfg = await getEmailConfig();

  if (!cfg) {
    res.status(400).json({ error: "Email is not configured. Enable it and save SMTP settings first." });
    return;
  }

  const recipient = to ?? cfg.from;
  if (!recipient) {
    res.status(400).json({ error: "No recipient address available. Set the From Address field." });
    return;
  }

  // Verify SMTP connection first
  try {
    const transporter = nodemailer.createTransport({
      host: cfg.host,
      port: cfg.port,
      secure: cfg.port === 465,
      auth: cfg.username ? { user: cfg.username, pass: cfg.password } : undefined,
      connectionTimeout: 8000,
    });
    await transporter.verify();
  } catch (err: any) {
    res.status(502).json({ error: `SMTP connection failed: ${err.message}` });
    return;
  }

  const result = await sendEmail({
    to: recipient,
    subject: "✅ SecOps Console — Email Test",
    html: `
      <div style="font-family:sans-serif;max-width:500px;">
        <h2 style="color:#3b82f6">✅ Email Notifications Working</h2>
        <p>This is a test message from your SecOps Console instance.</p>
        <p>Your email notification channel is configured correctly and can deliver alerts.</p>
        <hr style="border:none;border-top:1px solid #e5e7eb;margin:16px 0"/>
        <p style="font-size:12px;color:#9ca3af">Sent from SecOps Console · ${new Date().toLocaleString()}</p>
      </div>`,
  });

  if (!result.success) {
    res.status(502).json({ error: result.error ?? "Failed to send test email" });
    return;
  }

  res.json({ ok: true, message: `Test email sent to ${recipient}` });
});

// POST /api/settings/notifications/test-slack
router.post("/settings/notifications/test-slack", requireAuth, can("users:manage"), async (_req: Request, res: Response) => {
  const cfg = await getSlackConfig();
  if (!cfg) {
    res.status(400).json({ error: "Slack is not configured. Enable it and set the webhook URL first." });
    return;
  }

  const result = await sendSlack({
    text: "✅ SecOps Console — Slack test message",
    blocks: [
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: "✅ *SecOps Console — Slack Notifications Working*\nYour Slack webhook is configured correctly. Alert notifications will be delivered here.",
        },
      },
      {
        type: "context",
        elements: [{ type: "mrkdwn", text: `Sent at ${new Date().toLocaleString()}` }],
      },
    ],
  });

  if (!result.success) {
    res.status(502).json({ error: result.error ?? "Failed to send Slack test message" });
    return;
  }

  res.json({ ok: true, message: "Test message sent to Slack" });
});

// GET /api/settings/integrations/threatlens — ThreatLens config status
router.get("/settings/integrations/threatlens", requireAuth, can("users:manage"), async (_req: Request, res: Response) => {
  const url = await readDbSetting("integrations.threatlens.url");
  const hasKey = !!process.env["THREATLENS_API_KEY"];
  res.json({ url: url ?? "", apiKeySet: hasKey });
});

// POST /api/settings/integrations/threatlens/test
router.post("/settings/integrations/threatlens/test", requireAuth, can("users:manage"), async (_req: Request, res: Response) => {
  const cfg = await getThreatLensConfig();
  if (!cfg) {
    res.status(400).json({ error: "ThreatLens URL is not configured." });
    return;
  }

  const start = Date.now();
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    const resp = await fetch(`${cfg.url.replace(/\/$/, "")}/api/v1/health`, {
      signal: controller.signal,
      headers: cfg.apiKey ? { Authorization: `Bearer ${cfg.apiKey}` } : {},
    }).finally(() => clearTimeout(timer));

    const latencyMs = Date.now() - start;
    if (!resp.ok) {
      res.status(502).json({ error: `ThreatLens responded ${resp.status}`, latencyMs });
      return;
    }

    const body = await resp.json().catch(() => ({}));
    res.json({ ok: true, latencyMs, body });
  } catch (err: any) {
    const latencyMs = Date.now() - start;
    res.status(502).json({ error: err.message ?? "Connection failed", latencyMs });
  }
});

export default router;
