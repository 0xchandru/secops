export const ROLE_LABELS: Record<string, string> = {
  admin: 'Admin',
  soc_manager: 'SOC Manager',
  detection_engineer: 'Det. Engineer',
  soc_l2: 'SOC L2',
  soc_l1: 'SOC L1',
  viewer: 'Viewer',
};

export const ROLE_COLORS: Record<string, string> = {
  admin: 'bg-red-500/15 text-red-400 border-red-500/30',
  soc_manager: 'bg-purple-500/15 text-purple-400 border-purple-500/30',
  detection_engineer: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  soc_l2: 'bg-primary/15 text-primary border-primary/30',
  soc_l1: 'bg-green-500/15 text-green-400 border-green-500/30',
  viewer: 'bg-muted text-muted-foreground border-border',
};

export const ROLE_HIERARCHY: Record<string, number> = {
  admin: 6, soc_manager: 5, detection_engineer: 4, soc_l2: 3, soc_l1: 2, viewer: 1,
};

export const ROLE_DESCRIPTIONS: Record<string, string> = {
  admin: 'Full system access including user management and configuration',
  soc_manager: 'Team oversight, escalation handling, and report access',
  detection_engineer: 'Rule creation, tuning, and detection pipeline management',
  soc_l2: 'Advanced investigation, triage, and escalation capabilities',
  soc_l1: 'Initial triage, basic investigation, and alert handling',
  viewer: 'Read-only access to dashboards and alerts',
};

/** Ordered list of all roles from highest to lowest */
export const ALL_ROLES_ORDERED = [
  { value: 'admin', label: 'Admin', level: 6 },
  { value: 'soc_manager', label: 'SOC Manager', level: 5 },
  { value: 'detection_engineer', label: 'Det. Engineer', level: 4 },
  { value: 'soc_l2', label: 'SOC L2', level: 3 },
  { value: 'soc_l1', label: 'SOC L1', level: 2 },
  { value: 'viewer', label: 'Viewer', level: 1 },
] as const;

/** Get the next higher role for escalation */
export function getNextHigherRole(currentRole: string): string | null {
  const currentLevel = ROLE_HIERARCHY[currentRole] ?? 0;
  const sorted = ALL_ROLES_ORDERED.filter(r => r.level > currentLevel).sort((a, b) => a.level - b.level);
  return sorted[0]?.value ?? null;
}

/** Get roles at or above a given level */
export function getRolesAtOrAbove(level: number): string[] {
  return ALL_ROLES_ORDERED.filter(r => r.level >= level).map(r => r.value);
}

/** Get roles strictly above a given role */
export function getRolesAbove(role: string): string[] {
  const level = ROLE_HIERARCHY[role] ?? 0;
  return ALL_ROLES_ORDERED.filter(r => r.level > level).map(r => r.value);
}
