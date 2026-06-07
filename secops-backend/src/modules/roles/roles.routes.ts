import { Router } from "express";
import { requireAuthWithContext } from "../../middlewares/auth.middleware";
import { requirePermission } from "../../middlewares/permission-gate.middleware";
import {
  listRoles, getRole, createRole, updateRole, deleteRole,
  setPermissions, listPermissions, seedHandler,
} from "./roles.controller";

const router = Router();

// Permissions catalog (any authenticated user can list)
router.get("/permissions", requireAuthWithContext, listPermissions);

// Roles CRUD (requires users:manage)
router.get("/roles",                       requireAuthWithContext, requirePermission("users:manage"), listRoles);
router.get("/roles/:id",                   requireAuthWithContext, requirePermission("users:manage"), getRole);
router.post("/roles",                      requireAuthWithContext, requirePermission("users:manage"), createRole);
router.patch("/roles/:id",                 requireAuthWithContext, requirePermission("users:manage"), updateRole);
router.delete("/roles/:id",                requireAuthWithContext, requirePermission("users:manage"), deleteRole);
router.put("/roles/:id/permissions",       requireAuthWithContext, requirePermission("users:manage"), setPermissions);

// Seed (admin only via users:manage)
router.post("/roles/seed",                 requireAuthWithContext, requirePermission("users:manage"), seedHandler);

export default router;
