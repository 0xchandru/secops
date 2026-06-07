import { Router } from "express";
import { requireAuth } from "../../middlewares/auth.middleware";
import { can } from "../../middlewares/rbac.middleware";
import { getStats } from "./dashboard.controller";

const router = Router();

router.get("/dashboard/stats", requireAuth, can("alerts:view"), getStats);

export default router;
