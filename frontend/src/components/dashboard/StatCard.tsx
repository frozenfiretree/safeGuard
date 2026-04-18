import { LucideIcon } from 'lucide-react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

interface StatCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  trend?: {
    value: number;
    isPositive: boolean;
  };
  className?: string;
  onClick?: () => void;
}

export default function StatCard({
  title,
  value,
  icon: Icon,
  trend,
  className,
  onClick,
}: StatCardProps) {
  const baseClass = 'glass-panel p-6 relative overflow-hidden transition-all duration-300';
  const hoverClass = onClick ? 'cursor-pointer hover:scale-105 hover:border-[#00f0ff]' : '';

  const mergedClassName = twMerge(clsx(baseClass, hoverClass, className));

  return (
    <div className={mergedClassName} onClick={onClick}>
      {/* Background Glow */}
      <div className="absolute -right-6 -bottom-6 w-24 h-24 bg-[rgba(0,240,255,0.1)] rounded-full blur-xl"></div>

      {/* Icon */}
      <div className="flex items-start justify-between mb-4">
        <div className="p-3 bg-gradient-to-br from-[rgba(0,240,255,0.2)] to-transparent rounded-lg">
          <Icon size={24} className="text-[#00f0ff]" />
        </div>
        {trend && (
          <div
            className={clsx(
              'flex items-center gap-1 text-sm font-medium',
              trend.isPositive ? 'text-[#00ffaa]' : 'text-[#ff3366]'
            )}
          >
            <span>{trend.isPositive ? '+' : ''}{trend.value}%</span>
            <span className="text-[#648db3]">vs 上周</span>
          </div>
        )}
      </div>

      {/* Value */}
      <div className="text-3xl font-bold text-white mb-1 glow-text">
        {typeof value === 'number' ? value.toLocaleString() : value}
      </div>

      {/* Title */}
      <div className="text-sm text-[#648db3]">{title}</div>
    </div>
  );
}
