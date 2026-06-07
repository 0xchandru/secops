import { useState, useEffect, useRef } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Users, Plus, RefreshCw, UserCheck, Key, Edit2, Lock, Search, X, ArrowUpDown, Shield, ChevronRight, AlertTriangle, Eye, Loader2 } from "lucide-react";
import { usersApi, type ApiUser } from "@/lib/api";
import { useAuthStore } from "@/store/authStore";
import { useToast } from "@/hooks/use-toast";
import { ROLE_COLORS, ROLE_LABELS, ROLE_HIERARCHY, ROLE_DESCRIPTIONS, ALL_ROLES_ORDERED } from "@/lib/constants";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";

const STATUS_COLORS: Record<string, string> = {
  active: "text-green-400",
  inactive: "text-muted-foreground",
  locked: "text-destructive",
};

type SortField = "username" | "role" | "status" | "lastLoginAt" | "createdAt";
type SortDir = "asc" | "desc";

export default function UserManagementPage() {
  const [showCreate, setShowCreate] = useState(false);
  const [editUser, setEditUser] = useState<ApiUser | null>(null);
  const [resetUser, setResetUser] = useState<ApiUser | null>(null);
  const [activeMenu, setActiveMenu] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [roleFilter, setRoleFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [sort, setSort] = useState<{ field: SortField; dir: SortDir }>({ field: "createdAt", dir: "desc" });
  const { toast } = useToast();
  const { user: authUser } = useAuthStore();
  const queryClient = useQueryClient();
  const myLevel = ROLE_HIERARCHY[authUser?.role ?? "viewer"] ?? 1;
  const menuRef = useRef<HTMLDivElement>(null);

  // Close menu on click outside
  useEffect(() => {
    if (!activeMenu) return;
    const handler = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setActiveMenu(null);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [activeMenu]);

  const { data: users = [], isLoading, isError } = useQuery({
    queryKey: ["users", search, roleFilter, statusFilter],
    queryFn: async () => {
      const params: Record<string, string> = {};
      if (search) params.search = search;
      if (roleFilter) params.role = roleFilter;
      if (statusFilter) params.status = statusFilter;
      const { data } = await usersApi.list(params);
      return data.users;
    },
  });

  const toggleStatusMutation = useMutation({
    mutationFn: async ({ id, newStatus }: { id: string; newStatus: string }) => {
      await usersApi.update(id, { status: newStatus as any });
      return newStatus;
    },
    onSuccess: (_, { id, newStatus }) => {
      queryClient.setQueryData<ApiUser[]>(["users", search, roleFilter, statusFilter], prev =>
        prev?.map(u => u.id === id ? { ...u, status: newStatus } : u)
      );
      toast({ title: `User ${newStatus === "active" ? "activated" : "deactivated"}` });
    },
    onError: () => toast({ title: "Failed to update user", variant: "destructive" }),
  });

  const handleStatusToggle = (user: ApiUser) => {
    const newStatus = user.status === "active" ? "inactive" : "active";
    toggleStatusMutation.mutate({ id: user.id, newStatus });
    setActiveMenu(null);
  };

  const toggleSort = (field: SortField) => {
    setSort(prev => prev.field === field ? { field, dir: prev.dir === "asc" ? "desc" : "asc" } : { field, dir: "asc" });
  };

  const sorted = [...users].sort((a, b) => {
    const dir = sort.dir === "asc" ? 1 : -1;
    if (sort.field === "role") return dir * ((ROLE_HIERARCHY[a.role] ?? 0) - (ROLE_HIERARCHY[b.role] ?? 0));
    const av = (a as any)[sort.field] ?? "";
    const bv = (b as any)[sort.field] ?? "";
    return dir * String(av).localeCompare(String(bv));
  });

  // Role distribution for stats
  const roleCounts = ALL_ROLES_ORDERED.reduce<Record<string, number>>((acc, r) => {
    acc[r.value] = users.filter(u => u.role === r.value).length;
    return acc;
  }, {});

  const SortHeader = ({ field, children }: { field: SortField; children: React.ReactNode }) => (
    <th
      className="text-left px-4 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider cursor-pointer select-none hover:text-foreground transition-colors"
      onClick={() => toggleSort(field)}
    >
      <span className="inline-flex items-center gap-1">
        {children}
        <ArrowUpDown className={`w-3 h-3 ${sort.field === field ? "text-primary" : "opacity-40"}`} />
      </span>
    </th>
  );

  const canManageUser = (user: ApiUser) =>
    (ROLE_HIERARCHY[authUser?.role ?? ""] ?? 0) > (ROLE_HIERARCHY[user.role] ?? 0) || authUser?.userId === user.id;

  return (
    <>
      <div className="space-y-6 max-w-360 mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-primary/10 rounded-lg border border-primary/20">
              <Users className="w-6 h-6 text-primary" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-foreground">User Management</h1>
              <p className="text-sm text-muted-foreground">Manage analyst accounts and role assignments</p>
            </div>
          </div>
          <div className="flex gap-3">
            <button onClick={() => queryClient.invalidateQueries({ queryKey: ["users"] })} className="flex items-center gap-2 px-4 py-2 bg-secondary border border-border rounded-lg text-sm hover:bg-secondary/80 transition-colors">
              <RefreshCw className="w-4 h-4" />
              Refresh
            </button>
            <button onClick={() => setShowCreate(true)} className="flex items-center gap-2 px-4 py-2 bg-primary rounded-lg text-sm text-white font-medium hover:bg-primary/90 transition-colors">
              <Plus className="w-4 h-4" />
              Add User
            </button>
          </div>
        </div>

        {/* Stats — overview + role distribution */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {[
            { label: "Total Users", value: users.length, color: "text-foreground", icon: Users },
            { label: "Active", value: users.filter(u => u.status === "active").length, color: "text-green-400", icon: UserCheck },
            { label: "Inactive", value: users.filter(u => u.status === "inactive").length, color: "text-muted-foreground", icon: Eye },
            { label: "Locked", value: users.filter(u => u.status === "locked").length, color: "text-destructive", icon: Lock },
          ].map(({ label, value, color, icon: Icon }) => (
            <div key={label} className="bg-card border border-border rounded-xl p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-muted-foreground font-medium uppercase tracking-wider">{label}</span>
                <Icon className={`w-4 h-4 ${color}`} />
              </div>
              <p className={`text-2xl font-bold ${color}`}>{value}</p>
            </div>
          ))}
        </div>

        {/* Role Hierarchy Breakdown */}
        <div className="bg-card border border-border rounded-xl p-4">
          <div className="flex items-center gap-2 mb-3">
            <Shield className="w-4 h-4 text-primary" />
            <span className="text-sm font-semibold text-foreground">Role Distribution</span>
          </div>
          <div className="flex flex-wrap gap-2">
            {ALL_ROLES_ORDERED.map((r) => (
              <button
                key={r.value}
                onClick={() => setRoleFilter(roleFilter === r.value ? "" : r.value)}
                className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-medium transition-all ${
                  roleFilter === r.value
                    ? `${ROLE_COLORS[r.value]} ring-2 ring-primary/20`
                    : `${ROLE_COLORS[r.value]} opacity-70 hover:opacity-100`
                }`}
              >
                <span>{ROLE_LABELS[r.value]}</span>
                <span className="font-bold">{roleCounts[r.value] ?? 0}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Filters */}
        <div className="flex items-center gap-3">
          <div className="relative flex-1 max-w-sm">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <input
              type="text"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search by name, username, or email…"
              className="w-full pl-9 pr-8 py-2 bg-input border border-border rounded-lg text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/50"
            />
            {search && (
              <button aria-label="Clear search" onClick={() => setSearch("")} className="absolute right-2 top-1/2 -translate-y-1/2 p-0.5 text-muted-foreground hover:text-foreground">
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>
          <select
            aria-label="Filter by role"
            value={roleFilter}
            onChange={e => setRoleFilter(e.target.value)}
            className="bg-input border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary/50"
          >
            <option value="">All Roles</option>
            {ALL_ROLES_ORDERED.map(r => <option key={r.value} value={r.value}>{ROLE_LABELS[r.value]}</option>)}
          </select>
          <select
            aria-label="Filter by status"
            value={statusFilter}
            onChange={e => setStatusFilter(e.target.value)}
            className="bg-input border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary/50"
          >
            <option value="">All Status</option>
            <option value="active">Active</option>
            <option value="inactive">Inactive</option>
            <option value="locked">Locked</option>
          </select>
          {(search || roleFilter || statusFilter) && (
            <button onClick={() => { setSearch(""); setRoleFilter(""); setStatusFilter(""); }} className="text-xs text-muted-foreground hover:text-foreground underline">
              Clear filters
            </button>
          )}
        </div>

        {/* Table */}
        <div className="bg-card border border-border rounded-xl overflow-hidden shadow-lg shadow-black/10">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-secondary/30">
                  <SortHeader field="username">User</SortHeader>
                  <SortHeader field="role">Role</SortHeader>
                  <SortHeader field="status">Status</SortHeader>
                  <SortHeader field="lastLoginAt">Last Login</SortHeader>
                  <SortHeader field="createdAt">Created</SortHeader>
                  <th className="px-4 py-3 text-right text-xs font-semibold text-muted-foreground uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody>
                {isLoading ? (
                  <tr><td colSpan={6} className="text-center py-16">
                    <div className="flex items-center justify-center gap-3 text-muted-foreground">
                      <Loader2 className="w-5 h-5 animate-spin text-primary" /> Loading users…
                    </div>
                  </td></tr>
                ) : isError ? (
                  <tr><td colSpan={6} className="text-center py-16">
                    <div className="flex flex-col items-center gap-3">
                      <div className="w-12 h-12 rounded-full bg-destructive/10 flex items-center justify-center">
                        <AlertTriangle className="w-6 h-6 text-destructive" />
                      </div>
                      <p className="text-muted-foreground text-sm">Failed to load users</p>
                      <button onClick={() => queryClient.invalidateQueries({ queryKey: ["users"] })} className="text-sm text-primary hover:underline font-medium">Try again</button>
                    </div>
                  </td></tr>
                ) : sorted.length === 0 ? (
                  <tr><td colSpan={6} className="text-center py-16">
                    <div className="flex flex-col items-center gap-3">
                      <div className="w-12 h-12 rounded-full bg-secondary flex items-center justify-center">
                        <Users className="w-6 h-6 text-muted-foreground/30" />
                      </div>
                      <p className="text-sm text-muted-foreground">No users match the current filters</p>
                    </div>
                  </td></tr>
                ) : sorted.map(user => {
                  const manageable = canManageUser(user);
                  return (
                    <tr key={user.id} className="border-b border-border/50 hover:bg-secondary/20 transition-colors group">
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-3">
                          <div className="w-9 h-9 rounded-full bg-primary/15 flex items-center justify-center border border-primary/20 shrink-0">
                            <span className="text-xs font-bold text-primary">
                              {(user.displayName ?? user.username).split(" ").map(p => p[0]).join("").slice(0, 2).toUpperCase()}
                            </span>
                          </div>
                          <div className="min-w-0">
                            <p className="font-medium text-foreground truncate">{user.displayName ?? user.username}</p>
                            <p className="text-xs text-muted-foreground truncate">{user.email}</p>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex flex-col gap-1">
                          <span className={`text-xs px-2 py-1 rounded border w-fit ${ROLE_COLORS[user.role]}`}>
                            {ROLE_LABELS[user.role]}
                          </span>
                          <span className="text-[10px] text-muted-foreground/60 max-w-36 truncate">
                            Level {ROLE_HIERARCHY[user.role] ?? 0}
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1.5">
                          <span className={`w-2 h-2 rounded-full ${user.status === "active" ? "bg-green-400" : user.status === "locked" ? "bg-destructive" : "bg-muted"}`} />
                          <span className={`capitalize ${STATUS_COLORS[user.status]}`}>{user.status}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-muted-foreground text-xs">
                        {user.lastLoginAt ? new Date(user.lastLoginAt).toLocaleString() : "Never"}
                      </td>
                      <td className="px-4 py-3 text-muted-foreground text-xs">
                        {new Date(user.createdAt).toLocaleDateString()}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center justify-end gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                          {manageable ? (
                            <>
                              <button
                                onClick={() => setEditUser(user)}
                                title="Edit Role"
                                className="p-1.5 text-amber-400 hover:bg-amber-400/10 rounded-lg transition-colors"
                              >
                                <Edit2 className="w-3.5 h-3.5" />
                              </button>
                              <button
                                onClick={() => setResetUser(user)}
                                title="Reset Password"
                                className="p-1.5 text-primary hover:bg-primary/10 rounded-lg transition-colors"
                              >
                                <Key className="w-3.5 h-3.5" />
                              </button>
                              <button
                                onClick={() => handleStatusToggle(user)}
                                title={user.status === "active" ? "Deactivate" : "Activate"}
                                className={`p-1.5 rounded-lg transition-colors ${
                                  user.status === "active"
                                    ? "text-red-400 hover:bg-red-400/10"
                                    : "text-green-400 hover:bg-green-400/10"
                                }`}
                              >
                                {user.status === "active" ? <Lock className="w-3.5 h-3.5" /> : <UserCheck className="w-3.5 h-3.5" />}
                              </button>
                            </>
                          ) : (
                            <span className="text-[10px] text-muted-foreground/50 italic">Higher role</span>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {/* Footer */}
          <div className="px-4 py-3 border-t border-border bg-secondary/20 text-xs text-muted-foreground flex items-center justify-between">
            <span>Showing <span className="text-foreground font-medium">{sorted.length}</span> of <span className="text-foreground font-medium">{users.length}</span> users</span>
            <span className="text-primary flex items-center gap-1.5">
              <Shield className="w-3 h-3" /> Your role: {ROLE_LABELS[authUser?.role ?? "viewer"]} (Level {myLevel})
            </span>
          </div>
        </div>
      </div>

      <CreateUserDialog myLevel={myLevel} open={showCreate} onOpenChange={setShowCreate} onCreated={() => { queryClient.invalidateQueries({ queryKey: ["users"] }); setShowCreate(false); }} />
      <EditRoleDialog myLevel={myLevel} user={editUser} onOpenChange={open => { if (!open) setEditUser(null); }} onUpdated={() => { queryClient.invalidateQueries({ queryKey: ["users"] }); setEditUser(null); }} />
      <ResetPasswordDialog user={resetUser} onOpenChange={open => { if (!open) setResetUser(null); }} />
    </>
  );
}

function CreateUserDialog({ myLevel, open, onOpenChange, onCreated }: { myLevel: number; open: boolean; onOpenChange: (open: boolean) => void; onCreated: () => void }) {
  const [form, setForm] = useState({ username: "", email: "", password: "", role: "soc_l1", displayName: "" });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { toast } = useToast();
  const allowedRoles = ALL_ROLES_ORDERED.filter(r => r.level <= myLevel);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      await usersApi.create(form);
      toast({ title: "User created successfully" });
      setForm({ username: "", email: "", password: "", role: "soc_l1", displayName: "" });
      onCreated();
    } catch (err: any) {
      setError(err?.response?.data?.error ?? "Failed to create user");
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2"><Plus className="w-5 h-5 text-primary" /> Create New User</DialogTitle>
          <DialogDescription>Add a new analyst or operator account to the SOC platform.</DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          {error && <p className="text-sm text-destructive bg-destructive/10 border border-destructive/30 rounded px-3 py-2">{error}</p>}
          <div className="grid grid-cols-2 gap-4">
            <Field label="Display Name" value={form.displayName} onChange={v => setForm(f => ({ ...f, displayName: v }))} placeholder="Alice Analyst" />
            <Field label="Username" value={form.username} onChange={v => setForm(f => ({ ...f, username: v }))} placeholder="alice" required />
          </div>
          <Field label="Email" value={form.email} onChange={v => setForm(f => ({ ...f, email: v }))} placeholder="alice@secops.local" type="email" required />
          <Field label="Password" value={form.password} onChange={v => setForm(f => ({ ...f, password: v }))} placeholder="Min. 8 characters" type="password" required />
          <div>
            <label className="text-sm font-medium text-foreground block mb-1.5">Role</label>
            <div className="space-y-2">
              {allowedRoles.map(r => {
                const isSelected = form.role === r.value;
                return (
                  <button
                    key={r.value}
                    type="button"
                    onClick={() => setForm(f => ({ ...f, role: r.value }))}
                    className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg border text-left transition-all ${
                      isSelected
                        ? 'border-primary/50 bg-primary/5 ring-1 ring-primary/20'
                        : 'border-border hover:border-border/80 hover:bg-secondary/40'
                    }`}
                  >
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className={`text-xs px-2 py-0.5 rounded border ${ROLE_COLORS[r.value]}`}>{ROLE_LABELS[r.value]}</span>
                        <span className="text-[10px] text-muted-foreground/60">Level {r.level}</span>
                      </div>
                      <p className="text-[11px] text-muted-foreground mt-1 truncate">{ROLE_DESCRIPTIONS[r.value]}</p>
                    </div>
                    <div className={`w-4 h-4 rounded-full border-2 flex items-center justify-center shrink-0 ${
                      isSelected ? 'border-primary' : 'border-muted-foreground/30'
                    }`}>
                      {isSelected && <div className="w-2 h-2 rounded-full bg-primary" />}
                    </div>
                  </button>
                );
              })}
            </div>
            {allowedRoles.length < ALL_ROLES_ORDERED.length && (
              <p className="text-xs text-muted-foreground mt-2 flex items-center gap-1">
                <Shield className="w-3 h-3" /> You can only assign roles at or below your level ({myLevel})
              </p>
            )}
          </div>
          <DialogFooter>
            <button type="button" onClick={() => onOpenChange(false)} className="px-4 py-2 bg-secondary border border-border rounded-lg text-sm hover:bg-secondary/80">Cancel</button>
            <button type="submit" disabled={loading} className="px-4 py-2 bg-primary rounded-lg text-sm text-white font-medium hover:bg-primary/90 disabled:opacity-60">
              {loading ? "Creating…" : "Create User"}
            </button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function EditRoleDialog({ myLevel, user, onOpenChange, onUpdated }: { myLevel: number; user: ApiUser | null; onOpenChange: (open: boolean) => void; onUpdated: () => void }) {
  const [role, setRole] = useState(user?.role ?? "");
  const [loading, setLoading] = useState(false);
  const { toast } = useToast();
  const allowedRoles = ALL_ROLES_ORDERED.filter(r => r.level <= myLevel);

  // Keep role in sync when user changes
  useEffect(() => { if (user) setRole(user.role); }, [user]);

  const handleSave = async () => {
    if (!user) return;
    setLoading(true);
    try {
      await usersApi.update(user.id, { role: role as any });
      toast({ title: "Role updated" });
      onUpdated();
    } catch (err: any) {
      toast({ title: err?.response?.data?.error ?? "Failed to update role", variant: "destructive" });
    } finally {
      setLoading(false);
    }
  };

  const currentLevel = user ? (ROLE_HIERARCHY[user.role] ?? 0) : 0;
  const newLevel = ROLE_HIERARCHY[role] ?? 0;
  const isPromotion = newLevel > currentLevel;
  const isDemotion = newLevel < currentLevel;

  return (
    <Dialog open={!!user} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2"><Edit2 className="w-5 h-5 text-amber-400" /> Edit Role</DialogTitle>
          <DialogDescription>{user?.displayName ?? user?.username}</DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          {/* Current role */}
          {user && (
            <div className="flex items-center gap-3 p-3 bg-secondary/40 rounded-lg border border-border">
              <span className="text-xs text-muted-foreground">Current:</span>
              <span className={`text-xs px-2 py-1 rounded border ${ROLE_COLORS[user.role]}`}>{ROLE_LABELS[user.role]}</span>
              {role !== user.role && (
                <>
                  <ChevronRight className="w-4 h-4 text-muted-foreground" />
                  <span className="text-xs text-muted-foreground">New:</span>
                  <span className={`text-xs px-2 py-1 rounded border ${ROLE_COLORS[role]}`}>{ROLE_LABELS[role]}</span>
                </>
              )}
            </div>
          )}

          {/* Role selector */}
          <div className="space-y-2">
            {allowedRoles.map(r => {
              const isSelected = role === r.value;
              const isCurrent = user?.role === r.value;
              return (
                <button
                  key={r.value}
                  type="button"
                  onClick={() => setRole(r.value)}
                  className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg border text-left transition-all ${
                    isSelected
                      ? 'border-primary/50 bg-primary/5 ring-1 ring-primary/20'
                      : 'border-border hover:border-border/80 hover:bg-secondary/40'
                  }`}
                >
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className={`text-xs px-2 py-0.5 rounded border ${ROLE_COLORS[r.value]}`}>{ROLE_LABELS[r.value]}</span>
                      <span className="text-[10px] text-muted-foreground/60">Level {r.level}</span>
                      {isCurrent && <span className="text-[10px] text-primary font-medium">(current)</span>}
                    </div>
                    <p className="text-[11px] text-muted-foreground mt-1 truncate">{ROLE_DESCRIPTIONS[r.value]}</p>
                  </div>
                  <div className={`w-4 h-4 rounded-full border-2 flex items-center justify-center shrink-0 ${
                    isSelected ? 'border-primary' : 'border-muted-foreground/30'
                  }`}>
                    {isSelected && <div className="w-2 h-2 rounded-full bg-primary" />}
                  </div>
                </button>
              );
            })}
          </div>

          {/* Promotion / Demotion warning */}
          {role !== (user?.role ?? "") && (
            <div className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-xs ${
              isPromotion
                ? 'bg-amber-500/5 border-amber-500/20 text-amber-400'
                : isDemotion
                  ? 'bg-red-500/5 border-red-500/20 text-red-400'
                  : ''
            }`}>
              <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
              {isPromotion ? 'This will grant additional privileges.' : 'This will reduce user privileges.'}
            </div>
          )}

          <DialogFooter>
            <button onClick={() => onOpenChange(false)} className="px-4 py-2 bg-secondary border border-border rounded-lg text-sm">Cancel</button>
            <button onClick={handleSave} disabled={loading || role === (user?.role ?? "")} className="px-4 py-2 bg-primary rounded-lg text-sm text-white font-medium hover:bg-primary/90 disabled:opacity-60">
              {loading ? "Saving…" : "Save Role"}
            </button>
          </DialogFooter>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function ResetPasswordDialog({ user, onOpenChange }: { user: ApiUser | null; onOpenChange: (open: boolean) => void }) {
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const { toast } = useToast();

  // Reset password field when dialog opens
  useEffect(() => { setPassword(""); }, [user]);

  const handleReset = async () => {
    if (!user) return;
    if (password.length < 8) { toast({ title: "Password must be at least 8 characters", variant: "destructive" }); return; }
    setLoading(true);
    try {
      await usersApi.resetPassword(user.id, password);
      toast({ title: "Password reset successfully" });
      onOpenChange(false);
    } catch {
      toast({ title: "Failed to reset password", variant: "destructive" });
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open={!!user} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2"><Key className="w-5 h-5 text-primary" /> Reset Password</DialogTitle>
          <DialogDescription>{user?.displayName ?? user?.username}</DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-amber-500/5 border border-amber-500/20 text-xs text-amber-400">
            <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
            The user will need to use this new password on their next login.
          </div>
          <Field label="New Password" value={password} onChange={setPassword} placeholder="Min. 8 characters" type="password" />
          {password.length > 0 && password.length < 8 && (
            <p className="text-xs text-destructive">Password must be at least 8 characters</p>
          )}
          <DialogFooter>
            <button onClick={() => onOpenChange(false)} className="px-4 py-2 bg-secondary border border-border rounded-lg text-sm">Cancel</button>
            <button onClick={handleReset} disabled={loading || password.length < 8} className="px-4 py-2 bg-primary rounded-lg text-sm text-white font-medium hover:bg-primary/90 disabled:opacity-60">
              {loading ? "Resetting…" : "Reset Password"}
            </button>
          </DialogFooter>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function Field({ label, value, onChange, placeholder, type = "text", required }: {
  label: string; value: string; onChange: (v: string) => void;
  placeholder?: string; type?: string; required?: boolean;
}) {
  return (
    <div>
      <label className="text-sm font-medium text-foreground block mb-1.5">{label}</label>
      <input
        type={type}
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        required={required}
        className="w-full bg-background border border-border rounded-lg px-3 py-2.5 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/50"
      />
    </div>
  );
}
