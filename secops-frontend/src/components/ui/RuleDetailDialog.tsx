import React from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Shield } from 'lucide-react';
import RuleWidget from '@/components/widgets/RuleWidget';

interface RuleDetailDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  ruleId: string;
  ruleName?: string;
}

export default function RuleDetailDialog({ open, onOpenChange, ruleId, ruleName }: RuleDetailDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md p-0 overflow-hidden gap-0">
        <DialogHeader className="px-5 pt-5 pb-3">
          <DialogTitle className="flex items-center gap-2 text-sm">
            <Shield className="w-4 h-4 text-purple-400" />
            Detection Rule {ruleName && <span className="text-muted-foreground font-normal truncate">— {ruleName}</span>}
          </DialogTitle>
        </DialogHeader>
        <div className="px-5 pb-5">
          <RuleWidget ruleId={ruleId} ruleName={ruleName} />
        </div>
      </DialogContent>
    </Dialog>
  );
}
