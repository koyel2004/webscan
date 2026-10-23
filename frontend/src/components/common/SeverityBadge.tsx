import React from 'react';
import { SeverityLevel } from '../../types';

interface SeverityBadgeProps {
  severity: SeverityLevel;
  className?: string;
  size?: 'sm' | 'md';
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, className = '', size = 'md' }) => {
  const sizeClasses = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-xs font-semibold';

  const severityStyles: Record<SeverityLevel, { bg: string; text: string; border: string }> = {
    CRITICAL: {
      bg: 'bg-red-950/40',
      text: 'text-red-400',
      border: 'border-red-500/40',
    },
    HIGH: {
      bg: 'bg-orange-950/40',
      text: 'text-orange-400',
      border: 'border-orange-500/40',
    },
    MEDIUM: {
      bg: 'bg-amber-950/40',
      text: 'text-amber-400',
      border: 'border-amber-500/40',
    },
    LOW: {
      bg: 'bg-blue-950/40',
      text: 'text-blue-400',
      border: 'border-blue-500/40',
    },
    INFORMATIONAL: {
      bg: 'bg-slate-800/60',
      text: 'text-slate-300',
      border: 'border-slate-600/40',
    },
  };

  const current = severityStyles[severity] || severityStyles.INFORMATIONAL;

  return (
    <span
      className={`inline-flex items-center rounded-full border ${current.bg} ${current.text} ${current.border} ${sizeClasses} ${className}`}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-current mr-1.5 opacity-80" />
      {severity}
    </span>
  );
};
