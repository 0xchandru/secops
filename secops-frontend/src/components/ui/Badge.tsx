import React from 'react';
import { Severity, AlertStatus } from '@/lib/types';

interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  children: React.ReactNode;
}

export function Badge({ children, className = '', ...props }: BadgeProps) {
  return (
    <span 
      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${className}`}
      {...props}
    >
      {children}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  const styles = {
    critical: 'text-red-500 bg-red-500/10 border-red-500/20',
    high: 'text-orange-500 bg-orange-500/10 border-orange-500/20',
    medium: 'text-yellow-500 bg-yellow-500/10 border-yellow-500/20',
    low: 'text-green-500 bg-green-500/10 border-green-500/20',
    info: 'text-indigo-400 bg-indigo-400/10 border-indigo-400/20',
  };

  return (
    <Badge className={styles[severity]}>
      {severity.toUpperCase()}
    </Badge>
  );
}

export function StatusBadge({ status }: { status: AlertStatus }) {
  const styles: Record<AlertStatus, string> = {
    new: 'text-blue-400 bg-blue-400/10 border-blue-400/20',
    investigating: 'text-amber-400 bg-amber-400/10 border-amber-400/20',
    escalated: 'text-red-400 bg-red-400/10 border-red-400/20',
    resolved: 'text-emerald-400 bg-emerald-400/10 border-emerald-400/20',
    false_positive: 'text-gray-400 bg-gray-400/10 border-gray-400/20',
  };

  return (
    <Badge className={styles[status]}>
      {status.replace('_', ' ').toUpperCase()}
    </Badge>
  );
}
