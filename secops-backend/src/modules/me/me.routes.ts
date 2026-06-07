import { Router } from "express";
import { requireAuth } from "../../middlewares/auth.middleware";
import * as ctrl from "./me.controller";

const router = Router();

router.get("/me", requireAuth, ctrl.getProfile);
router.patch("/me", requireAuth, ctrl.updateProfile);
router.post("/me/password", requireAuth, ctrl.changePassword);
router.get("/me/settings", requireAuth, ctrl.getSettings);
router.patch("/me/settings", requireAuth, ctrl.updateSettings);
router.get("/me/api-keys", requireAuth, ctrl.listApiKeys);
router.post("/me/api-keys", requireAuth, ctrl.createApiKey);
router.delete("/me/api-keys/:keyId", requireAuth, ctrl.deleteApiKey);

export default router;
