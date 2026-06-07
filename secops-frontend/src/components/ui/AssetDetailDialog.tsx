import React from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Server } from 'lucide-react';
import AssetWidget from '@/components/widgets/AssetWidget';

interface AssetDetailDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  hostname?: string;
  ip?: string;
}

export default function AssetDetailDialog({ open, onOpenChange, hostname, ip }: AssetDetailDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md p-0 overflow-hidden gap-0">
        <DialogHeader className="px-5 pt-5 pb-3">
          <DialogTitle className="flex items-center gap-2 text-sm">
            <Server className="w-4 h-4 text-primary" />
            Asset Details — <span className="font-mono text-primary">{hostname || ip}</span>
          </DialogTitle>
        </DialogHeader>
        <div className="px-5 pb-5">
          <AssetWidget hostname={hostname} ip={ip} />
        </div>
      </DialogContent>
    </Dialog>
  );
}
