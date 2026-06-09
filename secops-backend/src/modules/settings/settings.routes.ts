import { Router } from "express";
import type { Request, Response } from "express";
import { requireAuth } from "../../middlewares/auth.middleware";
import { can } from "../../middlewares/rbac.middleware";
import { db, systemSettingsTable } from "../../db";
import { eq } from "drizzle-orm";
import { encrypt, decrypt } from "../../lib/crypto-utils";
import { sendEmail, sendSlack, getEmailConfig, getSlackConfig, getThreatLensConfig } from "../../lib/notification-service";
import nodemailer from "nodemailer";

const router = Router();

const SENSITIVE_KEYS = new Set([
  "notifications.email.password",
  "notifications.slack.webhookUrl",
  "integrations.threatlens.apiKey",
]);

const ALLOWED_KEYS = new Set([
  "notifications.email.enabled",
  "notifications.email.host",
  "notifications.email.port",
  "notifications.email.username",
  "notifications.email.password",
  "notifications.email.from",
  "notifications.slack.enabled",
  "notifications.slack.webhookUrl",
  "integrations.threatlens.url",
  "integrations.threatlens.apiKey",
]);

async function upsertSetting(key: string, value: string, updatedBy: string): Promise<void> {
  const isSensitive = SENSITIVE_KEYS.has(key);
  const storedValue = isSensitive ? encrypt(value) : value;

  const existing = await db
    .select({ key: systemSettingsTable.key })
    .from(systemSettingsTable)
    .where(eq(systemSettingsTable.key, key))
    .limit(1);

  if (existing.length > 0) {
    await db
      .update(systemSettingsTable)
      .set({ value: storedValue, encrypted: isSensitive, updatedAt: new Date(), updatedBy })
      .where(eq(systemSettingsTable.key, key));
  } else {
    await db.insert(systemSettingsTable).values({
      key,
      value: storedValue,
      encrypted: isSensitive,
      updatedBy,
    });
  }
}

async function readSetting(key: string): Promise<string | null> {
  const row = await db
    .select()
    .from(systemSettingsTable)
    .where(eq(systemSettingsTable.key, key))
    .limit(1);
  if (!row[0]) return null;
  return row[0].encrypted ? decrypt(row[0].value) : row[0].value;
}

// GET /api/settings/system — read all system settings (admin only)
// Sensitive values returned as masked placeholder (not the real value)
router.get("/settings/system", requireAuth, can("users:manage"), async (_req: Request, res: Response) => {
  const rows = await db.select().from(systemSettingsTable);
  const settings: Record<string, string | boolean | number> = {};

  for (const row of rows) {
    if (!ALLOWED_KEYS.has(row.key)) continue;
    if (SENSITIVE_KEYS.has(row.key)) {
      // Return a flag so UI knows whether it's set, not the actual value
      const val = decrypt(row.value);
      settings[row.key] = val ? "••••••••" : "";
    } else {
      settings[row.key] = row.value;
    }
  }

  res.json({ settings });
});

// PATCH /api/settings/system — update system settings (admin only)
router.patch("/settings/system", requireAuth, can("users:manage"), async (req: Request, res: Response) => {
  const updates = req.body as Record<string, string>;
  const userId = req.user!.userId;

  for (const [key, value] of Object.entries(updates)) {
    if (!ALLOWED_KEYS.has(key)) continue;
    if (typeof value !== "string") continue;
    // Skip sentinel mask value — means "unchanged"
    if (value === "••••••••") continue;
    await upsertSetting(key, value, userId);
  }

  res.json({ ok: true });
});

// POST /api/settings/notifications/test-email — send a test email
router.post("/settings/notifications/test-email", requireAuth, can("users:manage"), async (req: Request, res: Response) => {
  const { to } = req.body as { to?: string };
  const cfg = await getEmailConfig();

  if (!cfg) {
    res.status(400).json({ error: "Email is not configured. Please save SMTP settings first." });
    return;
  }

  const recipient = to ?? cfg.from;
  if (!recipient) {
    res.status(400).json({ error: "No recipient email address available" });
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

// POST /api/settings/notifications/test-slack — send a test Slack message
router.post("/settings/notifications/test-slack", requireAuth, can("users:manage"), async (_req: Request, res: Response) => {
  const cfg = await getSlackConfig();

  if (!cfg) {
    res.status(400).json({ error: "Slack is not configured. Please save the webhook URL first." });
    return;
  }

  const result = await sendSlack({
    text: "✅ SecOps Console — Slack test message",
    blocks: [
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: "✅ *SecOps Console — Slack Notifications Working*\nYour Slack webhook is configured correctly. You will now receive alert notifications here.",
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

// GET /api/settings/integrations/threatlens — read ThreatLens config status
router.get("/settings/integrations/threatlens", requireAuth, can("users:manage"), async (_req: Request, res: Response) => {
  const url = await readSetting("integrations.threatlens.url");
  const hasKey = !!(await readSetting("integrations.threatlens.apiKey"));

  res.json({
    url: url ?? "",
    apiKeySet: hasKey,
  });
});

// POST /api/settings/integrations/threatlens/test — test ThreatLens connectivity
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
