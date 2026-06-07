import jwt from "jsonwebtoken";
import type { UserRole } from "../db";

const ACCESS_SECRET = process.env["JWT_SECRET"]!;
const REFRESH_SECRET = process.env["JWT_REFRESH_SECRET"]!;
const ACCESS_EXPIRES = "15m";
const REFRESH_EXPIRES = "7d";

/** Legacy single-role payload — kept for backward compatibility. */
export interface JwtPayload {
  userId: string;
  username: string;
  email: string;
  /** @deprecated Use `roles` / `primaryRole` instead. */
  role: UserRole;
  displayName?: string | null;
  /** All role names the user holds. */
  roles?: string[];
  /** The user's primary role name. */
  primaryRole?: string;
  /** Effective priority (lowest = highest authority). */
  effectivePriority?: number;
  /** All merged permission codes. */
  permissions?: string[];
}

export function signAccessToken(payload: JwtPayload): string {
  return jwt.sign(payload, ACCESS_SECRET, { expiresIn: ACCESS_EXPIRES });
}

export function signRefreshToken(payload: JwtPayload): string {
  return jwt.sign(payload, REFRESH_SECRET, { expiresIn: REFRESH_EXPIRES });
}

export function verifyAccessToken(token: string): JwtPayload {
  return jwt.verify(token, ACCESS_SECRET) as JwtPayload;
}

export function verifyRefreshToken(token: string): JwtPayload {
  return jwt.verify(token, REFRESH_SECRET) as JwtPayload;
}
