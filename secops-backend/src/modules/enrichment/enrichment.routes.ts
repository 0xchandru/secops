import { Router } from "express";
import { eq } from "drizzle-orm";
import { requireAuth } from "../../middlewares/auth.middleware.js";
import { requireRole } from "../../middlewares/rbac.middleware.js";
import {
  enrichAlertIocs,
  getAlertEnrichments,
  enrichSingleIoc,
} from "./enrichment.service.js";
import { logger } from "../../lib/logger.js";
import { isThreatLensHealthy } from "../../lib/threatlens-client.js";
import { db } from "../../db/index.js";
import { alertIocEnrichmentsTable } from "../../db/schema/enrichment.js";

const router = Router();

// POST /api/enrichment/ioc — enrich a single IOC (cache-first)
router.post("/enrichment/ioc", requireAuth, async (req, res) => {
  const { value } = req.body;
  if (!value || typeof value !== "string") {
    res.status(400).json({ error: "value is required" });
    return;
  }
  try {
    const result = await enrichSingleIoc(value.trim());
    if (!result) {
      res.status(502).json({ error: "ThreatLens unavailable or no data for this IOC" });
      return;
    }
    res.json(result);
  } catch (err: any) {
    logger.error({ err }, "IOC enrichment error");
    res.status(500).json({ error: "Internal error" });
  }
});

// GET /api/enrichment/ioc/:value — fetch cached enrichment for a single IOC
router.get("/enrichment/ioc/:value", requireAuth, async (req, res) => {
  const value = req.params["value"] as string;
  try {
    const result = await enrichSingleIoc(decodeURIComponent(value));
    res.json(result ?? { iocValue: value, riskLevel: "unknown", threatScore: null });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/enrichment/alert/:alertId — trigger enrichment for an alert
router.post("/enrichment/alert/:alertId", requireAuth, async (req, res) => {
  const alertId = req.params["alertId"] as string;
  try {
    res.json({ status: "enrichment_triggered", alertId });
    setImmediate(() => enrichAlertIocs(alertId).catch(err =>
      logger.warn({ alertId, err: err.message }, "Background enrichment failed")
    ));
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/enrichment/alert/:alertId — fetch enrichment results for an alert
router.get("/enrichment/alert/:alertId", requireAuth, async (req, res) => {
  const alertId = req.params["alertId"] as string;
  try {
    const results = await getAlertEnrichments(alertId);
    res.json({ enrichments: results, count: results.length });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/enrichment/alert/:alertId/cache — force re-enrich (L2+ only)
router.delete(
  "/enrichment/alert/:alertId/cache",
  requireAuth,
  requireRole("soc_l2", "soc_manager", "admin"),
  async (req, res) => {
    const alertId = req.params["alertId"] as string;
    try {
      await db.delete(alertIocEnrichmentsTable).where(eq(alertIocEnrichmentsTable.alertId, alertId));
      res.json({ status: "cache_cleared", alertId });
      setImmediate(() => enrichAlertIocs(alertId).catch(() => {}));
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  }
);

// GET /api/enrichment/health — ThreatLens health check
router.get("/enrichment/health", requireAuth, async (_req, res) => {
  const healthy = await isThreatLensHealthy();
  res.json({ threatlens: healthy ? "online" : "offline", timestamp: new Date().toISOString() });
});

export default router;
