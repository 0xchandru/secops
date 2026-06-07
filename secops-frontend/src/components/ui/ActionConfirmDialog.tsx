import React, { useState, useCallback } from 'react';
import {
  AlertDialog,
  AlertDialogContent,
  AlertDialogHeader,
  AlertDialogFooter,
  AlertDialogTitle,
  AlertDialogDescription,
  AlertDialogCancel,
} from '@/components/ui/alert-dialog';
import { Loader2, AlertTriangle, ShieldAlert, Info } from 'lucide-react';

export type ConfirmVariant = 'warn' | 'destructive' | 'info';

interface ActionConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  variant?: ConfirmVariant;
  title: string;
  description: string;
  /** e.g. "3 alerts" or alert title — shown below description */
  entities?: string;
  confirmLabel?: string;
  cancelLabel?: string;
  requireComment?: boolean;
  commentPlaceholder?: string;
  commentMinLength?: number;
  isPending?: boolean;
  onConfirm: (comment?: string) => void;
  /** Extra content rendered between description and comment area */
  children?: React.ReactNode;
  /** External override to disable confirm (e.g. no target selected) */
  confirmDisabled?: boolean;
}

const VARIANT_STYLES: Record<ConfirmVariant, { icon: React.ElementType; accent: string; btnClass: string }> = {
  warn: {
    icon: AlertTriangle,
    accent: 'text-amber-400',
    btnClass: 'bg-amber-600 hover:bg-amber-700 text-white',
  },
  destructive: {
    icon: ShieldAlert,
    accent: 'text-destructive',
    btnClass: 'bg-destructive hover:bg-destructive/90 text-destructive-foreground',
  },
  info: {
    icon: Info,
    accent: 'text-primary',
    btnClass: 'bg-primary hover:bg-primary/90 text-primary-foreground',
  },
};

export default function ActionConfirmDialog({
  open,
  onOpenChange,
  variant = 'warn',
  title,
  description,
  entities,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  requireComment = false,
  commentPlaceholder = 'Provide a reason…',
  commentMinLength = 10,
  isPending = false,
  onConfirm,
  children,
  confirmDisabled = false,
}: ActionConfirmDialogProps) {
  const [comment, setComment] = useState('');
  const { icon: Icon, accent, btnClass } = VARIANT_STYLES[variant];

  const canConfirm = !confirmDisabled && (!requireComment || comment.trim().length >= commentMinLength);

  const handleConfirm = useCallback(() => {
    if (!canConfirm) return;
    onConfirm(requireComment ? comment.trim() : undefined);
    setComment('');
  }, [canConfirm, comment, onConfirm, requireComment]);

  const handleOpenChange = useCallback((next: boolean) => {
    if (!next) setComment('');
    onOpenChange(next);
  }, [onOpenChange]);

  return (
    <AlertDialog open={open} onOpenChange={handleOpenChange}>
      <AlertDialogContent className="max-w-md">
        <AlertDialogHeader>
          <AlertDialogTitle className="flex items-center gap-2">
            <Icon className={`w-5 h-5 ${accent}`} />
            {title}
          </AlertDialogTitle>
          <AlertDialogDescription>
            {description}
            {entities && (
              <span className="block mt-2 font-medium text-foreground text-sm">{entities}</span>
            )}
          </AlertDialogDescription>
        </AlertDialogHeader>

        {children}

        {requireComment && (
          <div className="mt-2">
            <textarea
              value={comment}
              onChange={e => setComment(e.target.value)}
              placeholder={commentPlaceholder}
              className="w-full bg-input border border-border rounded-lg p-3 text-sm text-foreground focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-all h-24 resize-none"
              maxLength={500}
              disabled={isPending}
            />
            <div className="flex justify-between text-xs text-muted-foreground mt-1">
              <span>
                {comment.trim().length < commentMinLength
                  ? `Min ${commentMinLength} characters required`
                  : '\u00A0'}
              </span>
              <span>{comment.length}/500</span>
            </div>
          </div>
        )}

        <AlertDialogFooter>
          <AlertDialogCancel disabled={isPending}>{cancelLabel}</AlertDialogCancel>
          <button
            onClick={handleConfirm}
            disabled={!canConfirm || isPending}
            className={`inline-flex items-center justify-center gap-2 rounded-md px-4 py-2 text-sm font-medium transition-colors disabled:opacity-50 disabled:pointer-events-none ${btnClass}`}
          >
            {isPending && <Loader2 className="w-4 h-4 animate-spin" />}
            {confirmLabel}
          </button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
