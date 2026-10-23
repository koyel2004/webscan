import React from 'react';
import { ScanStatus, CheckStatus } from '../../types';
import { CheckCircle2, Clock, AlertTriangle, XCircle, Ban, PlayCircle } from 'lucide-react';

interface StatusBadgeProps {
  status: ScanStatus | CheckStatus;
  size?: 'sm' | 'md';
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, size = 'md' }) => {
  const sizeClasses = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-xs font-medium';

  switch (status) {
    case 'COMPLETED':
    case 'PASSED':
      return (
        <span className={`inline-flex items-center gap-1.5 rounded-md border border-emerald-500/30 bg-emerald-950/30 text-emerald-400 ${sizeClasses}`}>
          <CheckCircle2 className="w-3.5 h-3.5" />
          {status === 'PASSED' ? 'Passed' : 'Completed'}
        </span>
      );
    case 'RUNNING':
      return (
        <span className={`inline-flex items-center gap-1.5 rounded-md border border-sky-500/30 bg-sky-950/30 text-sky-400 ${sizeClasses}`}>
          <span className="w-2 h-2 rounded-full bg-sky-400 animate-ping" />
          Running
        </span>
      );
    case 'PENDING':
      return (
        <span className={`inline-flex items-center gap-1.5 rounded-md border border-slate-600/30 bg-slate-800/40 text-slate-300 ${sizeClasses}`}>
          <Clock className="w-3.5 h-3.5" />
          Pending
        </span>
      );
    case 'FINDINGS_DETECTED':
      return (
        <span className={`inline-flex items-center gap-1.5 rounded-md border border-amber-500/30 bg-amber-950/30 text-amber-400 ${sizeClasses}`}>
          <AlertTriangle className="w-3.5 h-3.5" />
          Findings Detected
        </span>
      );
    case 'INCONCLUSIVE':
      return (
        <span className={`inline-flex items-center gap-1.5 rounded-md border border-slate-600/30 bg-slate-800/40 text-slate-400 ${sizeClasses}`}>
          <Clock className="w-3.5 h-3.5" />
          Inconclusive
        </span>
      );
    case 'FAILED':
    case 'ERROR':
      return (
        <span className={`inline-flex items-center gap-1.5 rounded-md border border-red-500/30 bg-red-950/30 text-red-400 ${sizeClasses}`}>
          <XCircle className="w-3.5 h-3.5" />
          {status === 'ERROR' ? 'Error' : 'Failed'}
        </span>
      );
    case 'CANCELLED':
    case 'SKIPPED':
      return (
        <span className={`inline-flex items-center gap-1.5 rounded-md border border-slate-700 bg-slate-900/60 text-slate-400 ${sizeClasses}`}>
          <Ban className="w-3.5 h-3.5" />
          {status === 'SKIPPED' ? 'Skipped' : 'Cancelled'}
        </span>
      );
    default:
      return (
        <span className={`inline-flex items-center gap-1 rounded-md border border-slate-700 bg-slate-800 text-slate-300 ${sizeClasses}`}>
          {status}
        </span>
      );
  }
};
