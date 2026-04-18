import { ReactNode } from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

interface TechCardProps {
  children: ReactNode;
  className?: string;
  hover?: boolean;
  onClick?: () => void;
}

export default function TechCard({
  children,
  className,
  hover = true,
  onClick,
}: TechCardProps) {
  const baseClass = 'tech-card';
  const hoverClass = hover ? 'cursor-pointer' : '';
  const clickClass = onClick ? 'active' : '';

  const mergedClassName = twMerge(
    clsx(baseClass, hoverClass, clickClass, className)
  );

  if (onClick) {
    return (
      <div className={mergedClassName} onClick={onClick}>
        {children}
      </div>
    );
  }

  return <div className={mergedClassName}>{children}</div>;
}
