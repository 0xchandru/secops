import { Router } from "express";
import { requireAuth } from "../../middlewares/auth.middleware";
import { can } from "../../middlewares/rbac.middleware";
import { listRules, getRule, createRule, updateRule, deleteRule, toggleRule, testRule, getRuleStats } from "./rules.controller";

const router = Router();

router.get("/rules",           requireAuth, can("rules:view"),   listRules);
router.get("/rules/:id",       requireAuth, can("rules:view"),   getRule);
router.get("/rules/:id/stats", requireAuth, can("rules:view"),   getRuleStats);
router.post("/rules",          requireAuth, can("rules:write"),  createRule);
router.post("/rules/test",     requireAuth, can("rules:write"),  testRule);
router.patch("/rules/:id",     requireAuth, can("rules:write"),  updateRule);
router.delete("/rules/:id",    requireAuth, can("rules:delete"), deleteRule);
router.patch("/rules/:id/toggle", requireAuth, can("rules:toggle"), toggleRule);

export default router;
