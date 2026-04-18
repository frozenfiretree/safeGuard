import { ReactNode } from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

interface TechPanelProps {
  children: ReactNode;
  className?: string;
  glow?: boolean;
  cornerDecoration?: boolean;
  title?: string;
  headerClassName?: string;
  bodyClassName?: string;
}

export default function TechPanel({
  children,
  className,
  glow = false,
  cornerDecoration = false,
  title,
  headerClassName,
  bodyClassName,
}: TechPanelProps) {
  const baseClass = 'glass-panel';
  const glowClass = glow ? 'glow' : '';
  const cornerClass = cornerDecoration ? 'corner-decoration' : '';

  const mergedClassName = twMerge(
    clsx(baseClass, glowClass, cornerClass, className)
  );

  return (
    <div className={mergedClassName}>
      {title && (
        <div
          className={twMerge(
            clsx(
              'px-5 py-4 border-b border-[rgba(0,240,255,0.2)]',
              'bg-[rgba(0,240,255,0.05)]',
              headerClassName
            )
          )}
        >
          <h3 className="text-lg font-bold text-[#00f0ff]">{title}</h3>
        </div>
      )}
      <div
        className={twMerge(
          clsx('flex-1 overflow-hidden relative', bodyClassName)
        )}
      >
        {children}
      </div>
    </div>
  );
}
