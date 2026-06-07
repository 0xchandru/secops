import { Router } from "express";
import rateLimit from "express-rate-limit";
import { loginHandler, refreshHandler, logoutHandler, meHandler } from "./auth.controller";
import { requireAuth } from "../../middlewares/auth.middleware";

const router = Router();

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  message: { error: "Too many login attempts. Try again in 15 minutes." },
  standardHeaders: true,
  legacyHeaders: false,
});

router.post("/auth/login", loginLimiter, loginHandler);
router.post("/auth/refresh", refreshHandler);
router.post("/auth/logout", requireAuth, logoutHandler);
router.get("/auth/me", requireAuth, meHandler);

export default router;
