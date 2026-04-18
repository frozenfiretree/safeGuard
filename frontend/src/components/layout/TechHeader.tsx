import { ReactNode } from 'react';
import { Menu, Bell, LogOut, Settings } from 'lucide-react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

interface TechHeaderProps {
  title: string;
  subtitle?: string;
  rightContent?: ReactNode;
  onMenuClick?: () => void;
  showMenu?: boolean;
  className?: string;
}

export default function TechHeader({
  title,
  subtitle,
  rightContent,
  onMenuClick,
  showMenu = true,
  className,
}: TechHeaderProps) {
  const baseClass = 'h-20 px-6 flex items-center justify-between border-b border-[rgba(0,240,255,0.2)] bg-gradient-to-b from-[rgba(10,21,37,0.95)] to-[rgba(10,21,37,0.4)]';

  const mergedClassName = twMerge(clsx(baseClass, className));

  return (
    <header className={mergedClassName}>
      <div className="flex items-center gap-4">
        {showMenu && onMenuClick && (
          <button
            onClick={onMenuClick}
            className="p-2 hover:bg-[rgba(0,240,255,0.1)] rounded-lg transition-colors"
          >
            <Menu size={20} className="text-[#648db3]" />
          </button>
        )}

        <div>
          <h1 className="text-2xl font-bold text-white glow-text">
            {title}
          </h1>
          {subtitle && (
            <p className="text-sm text-[#648db3] mt-1">{subtitle}</p>
          )}
        </div>
      </div>

      <div className="flex items-center gap-3">
        {rightContent}

        {/* Settings Button */}
        <button className="p-2 hover:bg-[rgba(0,240,255,0.1)] rounded-lg transition-colors group">
          <Settings size={20} className="text-[#648db3] group-hover:text-[#00f0ff]" />
        </button>

        {/* Notifications */}
        <button className="p-2 hover:bg-[rgba(0,240,255,0.1)] rounded-lg transition-colors relative group">
          <Bell size={20} className="text-[#648db3] group-hover:text-[#00f0ff]" />
          <span className="absolute top-1 right-1 w-2 h-2 bg-[#ff3366] rounded-full"></span>
        </button>

        {/* Logout */}
        <button className="p-2 hover:bg-[rgba(255,51,102,0.1)] rounded-lg transition-colors group">
          <LogOut size={20} className="text-[#648db3] group-hover:text-[#ff3366]" />
        </button>
      </div>
    </header>
  );
}
