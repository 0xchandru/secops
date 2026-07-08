import type { Request, Response, NextFunction } from "express";
import { verifyAccessToken, type JwtPayload } from "../lib/jwt";
import { permissionEngine, type UserContext } from "../lib/permission-engine";
import { db, apiKeysTable } from "../db";
import { eq } from "drizzle-orm";
import bcrypt from "bcryptjs";

declare global {
  namespace Express {
    interface Request {
      /** JWT payload — always set after requireAuth. */
      user?: JwtPayload;
      /** Hydrated user context with DB-driven roles/permissions. Set by requireAuthWithContext. */
      userContext?: UserContext;
      /** API key scopes — set by requireAuthOrApiKey when an API key is used. */
      apiKeyScopes?: string[];
    }
  }
}

/**
 * Dual-mode auth middleware for forwarder endpoints.
 * Accepts either a JWT (session auth) or a prefixed API key (sk_...).
 * API keys are looked up by prefix, then bcrypt-compared for security.
 */
export async function requireAuthOrApiKey(req: Request, res: Response, next: NextFunction): Promise<void> {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    res.status(401).json({ error: "Missing or invalid authorization header" });
    return;
  }
  const token = authHeader.slice(7);

  // 1. Try JWT first (JWTs always contain exactly 2 dots)
  if (token.split(".").length === 3) {
    try {
      const payload = verifyAccessToken(token);
      req.user = payload;
      next();
      return;
    } catch {
      // Not a valid JWT, fall through
    }
  }

  // 2. Try API key: format sk_<hex> with prefix lookup + bcrypt verify
  if (token.startsWith("sk_") && token.length > 10) {
    const prefix = token.slice(0, 10);
    try {
      const candidates = await db
        .select()
        .from(apiKeysTable)
        .where(eq(apiKeysTable.keyPrefix, prefix));

      for (const candidate of candidates) {
        const matches = await bcrypt.compare(token, candidate.keyHash);
        if (matches) {
          db.update(apiKeysTable)
            .set({ lastUsedAt: new Date() })
            .where(eq(apiKeysTable.id, candidate.id))
            .catch(() => {});
          req.user = {
            userId: candidate.userId,
            email: "",
            username: "api-key",
            role: "viewer",
          } as JwtPayload;
          req.apiKeyScopes = candidate.scopes ?? [];
          next();
          return;
        }
      }
    } catch {
      // DB lookup failed; fall through to reject
    }
  }

  res.status(401).json({ error: "Invalid or expired token" });
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
