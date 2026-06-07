import { Router } from "express";
import { requireAuth } from "../../middlewares/auth.middleware";
import { requireAuthWithContext } from "../../middlewares/auth.middleware";
import { can } from "../../middlewares/rbac.middleware";
import { listAlerts, getAlert, updateStatus, assignAlert, clearAssignment, escalateAlert, addNote, bulkUpdate, getRelatedEvents, investigate, getActions, executeAction } from "./alerts.controller";

const router = Router();

// ─── New unified action endpoints (DB-driven RBAC) ───────────────────────────
router.get("/alerts/:id/actions",          requireAuthWithContext, getActions);
router.post("/alerts/:id/actions/:action", requireAuthWithContext, executeAction);

// ─── Legacy endpoints (kept for backward compat) ────────────────────────────
router.get("/alerts",                       requireAuth, can("alerts:view"),   listAlerts);
router.get("/alerts/:id",                   requireAuth, can("alerts:view"),   getAlert);
router.post("/alerts/:id/investigate",      requireAuth, can("alerts:triage"), investigate);
router.patch("/alerts/:id/status",          requireAuth, can("alerts:triage"), updateStatus);
router.patch("/alerts/:id/assign",          requireAuth, can("alerts:assign"), assignAlert);
router.delete("/alerts/:id/assign",         requireAuth, can("alerts:assign"), clearAssignment);
router.post("/alerts/:id/escalate",         requireAuth, can("alerts:close"),  escalateAlert);
router.post("/alerts/:id/timeline",         requireAuth, can("alerts:note"),   addNote);
router.get("/alerts/:id/related-events",    requireAuth, can("alerts:view"),   getRelatedEvents);
router.post("/alerts/bulk-update",          requireAuth, can("alerts:triage"), bulkUpdate);

export default router;
