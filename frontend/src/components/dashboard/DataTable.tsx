import { ReactNode } from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

interface Column<T> {
  key: keyof T | string;
  header: string;
  render?: (row: T) => ReactNode;
  width?: string;
  align?: 'left' | 'center' | 'right';
}

interface DataTableProps<T> {
  data: T[];
  columns: Column<T>[];
  keyExtractor: (row: T) => string;
  className?: string;
  onRowClick?: (row: T) => void;
  emptyMessage?: string;
}

export default function DataTable<T>({
  data,
  columns,
  keyExtractor,
  className,
  onRowClick,
  emptyMessage = '暂无数据',
}: DataTableProps<T>) {
  const baseClass = 'glass-panel overflow-hidden';

  const mergedClassName = twMerge(clsx(baseClass, className));

  const getAlignClass = (align?: string) => {
    switch (align) {
      case 'center':
        return 'text-center';
      case 'right':
        return 'text-right';
      default:
        return 'text-left';
    }
  };

  if (data.length === 0) {
    return (
      <div className={mergedClassName}>
        <div className="p-12 text-center text-[#648db3]">{emptyMessage}</div>
      </div>
    );
  }

  return (
    <div className={mergedClassName}>
      {/* Header */}
      <div className="border-b border-[rgba(0,240,255,0.2)] bg-[rgba(0,240,255,0.05)]">
        <div className="grid gap-px px-4 py-3" style={{
          gridTemplateColumns: columns.map(c => c.width || '1fr').join(' ')
        }}>
          {columns.map((column, index) => (
            <div
              key={index}
              className={clsx('font-semibold text-sm text-[#00f0ff]', getAlignClass(column.align))}
            >
              {column.header}
            </div>
          ))}
        </div>
      </div>

      {/* Body */}
      <div className="overflow-auto max-h-[600px]">
        {data.map((row, rowIndex) => (
          <div
            key={keyExtractor(row)}
            className={clsx(
              'grid gap-px px-4 py-4 border-b border-[rgba(255,255,255,0.05)]',
              'hover:bg-[rgba(0,240,255,0.05)] transition-colors',
              onRowClick && 'cursor-pointer'
            )}
            style={{
              gridTemplateColumns: columns.map(c => c.width || '1fr').join(' ')
            }}
            onClick={() => onRowClick?.(row)}
          >
            {columns.map((column, colIndex) => (
              <div
                key={colIndex}
                className={clsx('text-sm text-[#e0f7ff]', getAlignClass(column.align))}
              >
                {column.render ? column.render(row) : String((row as any)[column.key] ?? '-')}
              </div>
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}
