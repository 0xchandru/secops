import { Router } from "express";
import { requireAuth } from "../../middlewares/auth.middleware";
import { lookup, enrich } from "./threatlens.controller";

const router = Router();

router.post("/threatlens/lookup", requireAuth, lookup);
router.get("/threatlens/enrich/:value", requireAuth, enrich);

export default router;
