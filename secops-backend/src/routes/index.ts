import { Router, type IRouter } from "express";
import healthRouter from "./health";
import authRoutes from "../modules/auth/auth.routes";
import meRoutes from "../modules/me/me.routes";
import usersRoutes from "../modules/users/users.routes";
import alertsRoutes from "../modules/alerts/alerts.routes";
import rulesRoutes from "../modules/rules/rules.routes";
import auditRoutes from "../modules/audit/audit.routes";
import ingestRoutes from "../modules/ingest/ingest.routes";
import dashboardRoutes from "../modules/dashboard/dashboard.routes";
import assetsRoutes from "../modules/assets/assets.routes";
import notificationsRoutes from "../modules/notifications/notifications.routes";
import rolesRoutes from "../modules/roles/roles.routes";
import threatlensRoutes from "../modules/threatlens/threatlens.routes";

const router: IRouter = Router();

router.use(healthRouter);
router.use(authRoutes);
router.use(meRoutes);
router.use(usersRoutes);
router.use(alertsRoutes);
router.use(rulesRoutes);
router.use(rolesRoutes);
router.use(auditRoutes);
router.use(ingestRoutes);
router.use(dashboardRoutes);
router.use(assetsRoutes);
router.use(notificationsRoutes);
router.use(threatlensRoutes);

export default router;
