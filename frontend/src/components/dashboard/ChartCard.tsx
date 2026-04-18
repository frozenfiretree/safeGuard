import { ReactNode } from 'react';

interface ChartCardProps {
  title: string;
  children: ReactNode;
  actions?: ReactNode;
  className?: string;
  loading?: boolean;
}

export default function ChartCard({
  title,
  children,
  actions,
  className,
  loading = false,
}: ChartCardProps) {
  return (
    <div className={`glass-panel p-6 ${className || ''}`}>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <h3 className="text-lg font-bold text-[#00f0ff]">{title}</h3>
        {actions}
      </div>

      {/* Content */}
      {loading ? (
        <div className="flex items-center justify-center h-64">
          <div className="loading-spinner"></div>
        </div>
      ) : (
        <div className="h-64">
          {children}
        </div>
      )}
    </div>
  );
}
