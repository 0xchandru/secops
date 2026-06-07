import type { Request, Response, NextFunction } from "express";
import { verifyAccessToken, type JwtPayload } from "../lib/jwt";
import { permissionEngine, type UserContext } from "../lib/permission-engine";

declare global {
  namespace Express {
    interface Request {
      /** JWT payload — always set after requireAuth. */
      user?: JwtPayload;
      /** Hydrated user context with DB-driven roles/permissions. Set by requireAuthWithContext. */
      userContext?: UserContext;
    }
  }
}

/**
 * Basic auth middleware — verifies JWT and attaches payload to req.user.
 * Kept for backward compatibility with existing routes.
 */
export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    res.status(401).json({ error: "Missing or invalid authorization header" });
    return;
  }
  const token = authHeader.slice(7);
  try {
    const payload = verifyAccessToken(token);
    req.user = payload;
    next();
  } catch {
    res.status(401).json({ error: "Invalid or expired token" });
  }
}

/**
 * Enhanced auth middleware — verifies JWT, then hydrates full UserContext
 * from PermissionEngine (DB → Redis cache → req.userContext).
 * Use this for routes that need DB-driven permission checks.
 */
export function requireAuthWithContext(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    res.status(401).json({ error: "Missing or invalid authorization header" });
    return;
  }
  const token = authHeader.slice(7);
  try {
    const payload = verifyAccessToken(token);
    req.user = payload;

    // Hydrate full context from DB/Redis
    permissionEngine
      .resolveUserContext(payload.userId)
      .then((ctx) => {
        if (!ctx) {
          res.status(403).json({ error: "User has no assigned roles" });
          return;
        }
        req.userContext = ctx;
        next();
      })
      .catch(() => {
        res.status(500).json({ error: "Failed to resolve user context" });
      });
  } catch {
    res.status(401).json({ error: "Invalid or expired token" });
  }
}
