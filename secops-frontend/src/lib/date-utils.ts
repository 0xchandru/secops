import { format, isValid, formatDistanceToNow } from 'date-fns';

// IST is UTC+5:30 = 330 minutes
const IST_OFFSET_MS = 330 * 60 * 1000;

/**
 * Convert a date to IST by adjusting for the timezone offset.
 * This ensures consistent IST display regardless of the user's local timezone.
 */
function toIST(date: Date): Date {
  // Get the UTC time, then add IST offset
  const utcMs = date.getTime() + date.getTimezoneOffset() * 60 * 1000;
  return new Date(utcMs + IST_OFFSET_MS);
}

/**
 * Safely format a date in IST timezone.
 */
export function safeFormat(date: Date | string | number | null | undefined, fmt: string, fallback = '—'): string {
  try {
    const d = date instanceof Date ? date : date != null ? new Date(date) : null;
    if (!d || !isValid(d)) return fallback;
    return format(toIST(d), fmt);
  } catch { return fallback; }
}

/**
 * Relative time ago string (e.g., "3 minutes ago").
 * Uses the original date (relative time is timezone-agnostic).
 */
export function timeAgo(date: Date | string | number | null | undefined): string {
  try {
    const d = date instanceof Date ? date : date != null ? new Date(date) : null;
    if (!d || !isValid(d)) return '—';
    return formatDistanceToNow(d, { addSuffix: true });
  } catch { return '—'; }
}

/**
 * Format a date as full IST string with timezone label.
 */
export function formatIST(date: Date | string | number | null | undefined, fmt = 'dd MMM yyyy, HH:mm:ss'): string {
  return safeFormat(date, fmt) + ' IST';
}
