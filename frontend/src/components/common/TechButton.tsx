import { ReactNode } from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

interface TechButtonProps {
  children: ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  variant?: 'primary' | 'danger' | 'success' | 'warning';
  className?: string;
}

export default function TechButton({
  children,
  onClick,
  disabled = false,
  variant = 'primary',
  className,
}: TechButtonProps) {
  const baseClass = 'tech-button';
  const variantClasses: Record<string, string> = {
    primary: 'bg-gradient-to-r from-[#0070cc] to-[#00f0ff]',
    danger: 'tech-button-danger',
    success: 'tech-button-success',
    warning: 'tech-button-warning',
  };
  const disabledClass = disabled ? 'opacity-50 cursor-not-allowed' : '';

  const mergedClassName = twMerge(
    clsx(
      baseClass,
      variantClasses[variant],
      disabledClass,
      className
    )
  );

  return (
    <button
      className={mergedClassName}
      onClick={onClick}
      disabled={disabled}
    >
      {children}
    </button>
  );
}
