import { create } from "zustand";
import { persist } from "zustand/middleware";
import { authApi, type AuthUser } from "../lib/api";

export type Permission =
  | "alerts:view"
  | "alerts:triage"
  | "alerts:assign"
  | "alerts:close"
  | "alerts:note"
  | "rules:view"
  | "rules:toggle"
  | "rules:write"
  | "rules:delete"
  | "rules:test"
  | "ingest:write"
  | "ingest:pending"
  | "users:manage"
  | "audit:view"
  | "reports:view";

type UserRole = AuthUser["role"];

/**
 * @deprecated Kept as fallback for users whose backend hasn't seeded DB roles yet.
 * Once DB-driven roles are active, permissions come from the backend via login/me.
 */
const ROLE_PERMISSIONS_FALLBACK: Record<UserRole, Permission[]> = {
  admin: [
    "alerts:view", "alerts:triage", "alerts:assign", "alerts:close", "alerts:note",
    "rules:view", "rules:toggle", "rules:write", "rules:delete", "rules:test",
    "ingest:write", "ingest:pending",
    "users:manage",
    "audit:view",
    "reports:view",
  ],
  soc_manager: [
    "alerts:view", "alerts:triage", "alerts:assign", "alerts:close", "alerts:note",
    "rules:view",
    "ingest:write", "ingest:pending",
    "audit:view",
    "reports:view",
  ],
  detection_engineer: [
    "alerts:view", "alerts:note",
    "rules:view", "rules:toggle", "rules:write", "rules:delete", "rules:test",
    "ingest:write", "ingest:pending",
    "reports:view",
  ],
  soc_l2: [
    "alerts:view", "alerts:triage", "alerts:assign", "alerts:close", "alerts:note",
    "rules:view", "rules:toggle", "rules:write", "rules:test",
    "ingest:write", "ingest:pending",
    "reports:view",
  ],
  soc_l1: [
    "alerts:view", "alerts:triage", "alerts:note",
    "rules:view",
    "reports:view",
  ],
  viewer: [
    "alerts:view",
    "rules:view",
    "reports:view",
  ],
};

interface AuthState {
  user: AuthUser | null;
  permissions: Permission[];
  isAuthenticated: boolean;
  isInitialized: boolean;
  isLoading: boolean;
  login: (identifier: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  restoreSession: () => Promise<void>;
  hasRole: (...roles: UserRole[]) => boolean;
  can: (permission: Permission) => boolean;
}

/** Extract permissions from the API user response, falling back to legacy role map */
function resolvePermissions(user: AuthUser): Permission[] {
  // If backend provides permissions array (DB-driven RBAC), use it
  if (user.permissions && Array.isArray(user.permissions) && user.permissions.length > 0) {
    return user.permissions as Permission[];
  }
  // Fallback: derive from legacy single role
  return ROLE_PERMISSIONS_FALLBACK[user.role] ?? [];
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      user: null,
      permissions: [],
      isAuthenticated: false,
      isInitialized: false,
      isLoading: false,

      login: async (identifier, password) => {
        set({ isLoading: true });
        try {
          const { data } = await authApi.login(identifier, password);
          localStorage.setItem("access_token", data.accessToken);
          localStorage.setItem("refresh_token", data.refreshToken);
          const permissions = resolvePermissions(data.user);
          set({ user: data.user, permissions, isAuthenticated: true, isInitialized: true, isLoading: false });
        } catch (err: any) {
          set({ isLoading: false });
          throw err;
        }
      },

      logout: async () => {
        try {
          await authApi.logout();
        } catch {}
        localStorage.removeItem("access_token");
        localStorage.removeItem("refresh_token");
        set({ user: null, permissions: [], isAuthenticated: false });
      },

      restoreSession: async () => {
        const token = localStorage.getItem("access_token");
        if (!token) {
          set({ isInitialized: true });
          return;
        }
        try {
          const { data } = await authApi.me();
          const permissions = resolvePermissions(data.user);
          set({ user: data.user, permissions, isAuthenticated: true, isInitialized: true });
        } catch {
          localStorage.removeItem("access_token");
          localStorage.removeItem("refresh_token");
          set({ user: null, permissions: [], isAuthenticated: false, isInitialized: true });
        }
      },

      hasRole: (...roles) => {
        const user = get().user;
        if (!user) return false;
        // Check against DB-driven roles array if available, else legacy single role
        if (user.roles && Array.isArray(user.roles)) {
          return roles.some(r => user.roles!.includes(r));
        }
        return roles.includes(user.role);
      },

      can: (permission) => {
        return get().permissions.includes(permission);
      },
    }),
    {
      name: "secops-auth",
      partialize: (state) => ({
        user: state.user,
        permissions: state.permissions,
        isAuthenticated: state.isAuthenticated,
      }),
    }
  )
);
