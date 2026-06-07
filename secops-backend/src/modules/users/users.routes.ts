import { Router } from "express";
import { requireAuth } from "../../middlewares/auth.middleware";
import { requireAuthWithContext } from "../../middlewares/auth.middleware";
import { requireRole, can } from "../../middlewares/rbac.middleware";
import { requirePermission } from "../../middlewares/permission-gate.middleware";
import {
  listUsers, getUser, createUser, updateUser, resetPassword, getEscalationTargets,
  getUserRoles, assignUserRole, removeUserRole, setUserRoles,
} from "./users.controller";

const router = Router();

router.get("/users/escalation-targets", requireAuth, can("alerts:triage"), getEscalationTargets);

// Legacy routes (old RBAC)
router.get("/users", requireAuth, requireRole("admin"), listUsers);
router.get("/users/:id", requireAuth, requireRole("admin"), getUser);
router.post("/users", requireAuth, requireRole("admin"), createUser);
router.patch("/users/:id", requireAuth, requireRole("admin"), updateUser);
router.post("/users/:id/reset-password", requireAuth, requireRole("admin"), resetPassword);

// DB-driven role assignment routes
router.get("/users/:id/roles",            requireAuthWithContext, requirePermission("users:manage"), getUserRoles);
router.post("/users/:id/roles",           requireAuthWithContext, requirePermission("users:manage"), assignUserRole);
router.put("/users/:id/roles",            requireAuthWithContext, requirePermission("users:manage"), setUserRoles);
router.delete("/users/:id/roles/:roleId", requireAuthWithContext, requirePermission("users:manage"), removeUserRole);

export default router;
