import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

type StatusType = 'online' | 'offline' | 'pending' | 'success' | 'danger' | 'warning';

interface StatusBadgeProps {
  status: StatusType;
  text: string;
  className?: string;
  dot?: boolean;
}

const statusStyles: Record<StatusType, string> = {
  online: 'text-[#00ffaa] bg-[rgba(0,255,170,0.1)]',
  offline: 'text-[#ff3366] bg-[rgba(255,51,102,0.1)]',
  pending: 'text-[#ffd700] bg-[rgba(255,215,0,0.1)]',
  success: 'text-[#00ffaa] bg-[rgba(0,255,170,0.1)]',
  danger: 'text-[#ff3366] bg-[rgba(255,51,102,0.1)]',
  warning: 'text-[#ffd700] bg-[rgba(255,215,0,0.1)]',
};

const dotStyles: Record<StatusType, string> = {
  online: 'status-dot-online',
  offline: 'status-dot-offline',
  pending: 'status-dot-pending',
  success: 'status-dot-online',
  danger: 'status-dot-offline',
  warning: 'status-dot-pending',
};

export default function StatusBadge({
  status,
  text,
  className,
  dot = true,
}: StatusBadgeProps) {
  const baseClass = 'inline-flex items-center px-3 py-1 rounded-full text-sm font-medium';
  const statusClass = statusStyles[status];

  const mergedClassName = twMerge(clsx(baseClass, statusClass, className));

  return (
    <span className={mergedClassName}>
      {dot && <span className={dotStyles[status]}></span>}
      {text}
    </span>
  );
}
