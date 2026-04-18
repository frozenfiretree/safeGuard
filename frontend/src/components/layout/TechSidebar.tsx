import { LucideIcon } from 'lucide-react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

interface NavItem {
  id: string;
  label: string;
  icon: LucideIcon;
  badge?: number;
}

interface TechSidebarProps {
  items: NavItem[];
  activeItem: string;
  onItemClick: (id: string) => void;
  collapsed?: boolean;
  className?: string;
}

export default function TechSidebar({
  items,
  activeItem,
  onItemClick,
  collapsed = false,
  className,
}: TechSidebarProps) {
  const baseClass = 'glass-panel border-r border-[rgba(0,240,255,0.2)]';
  const collapsedClass = collapsed ? 'w-16' : 'w-64';

  const mergedClassName = twMerge(clsx(baseClass, collapsedClass, className));

  return (
    <nav className={mergedClassName}>
      {/* Logo */}
      <div className="h-20 flex items-center justify-center border-b border-[rgba(0,240,255,0.2)]">
        {!collapsed ? (
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-gradient-to-br from-[#0070cc] to-[#00f0ff] rounded-lg flex items-center justify-center">
              <span className="text-black font-bold text-xl">S</span>
            </div>
            <div>
              <h1 className="text-lg font-bold text-white">SafeGuard</h1>
              <p className="text-xs text-[#648db3]">安全监控系统</p>
            </div>
          </div>
        ) : (
          <div className="w-10 h-10 bg-gradient-to-br from-[#0070cc] to-[#00f0ff] rounded-lg flex items-center justify-center">
            <span className="text-black font-bold text-xl">S</span>
          </div>
        )}
      </div>

      {/* Navigation */}
      <div className="flex-1 py-4 overflow-y-auto">
        <ul className="space-y-1 px-2">
          {items.map((item) => {
            const Icon = item.icon;
            const isActive = activeItem === item.id;

            return (
              <li key={item.id}>
                <button
                  onClick={() => onItemClick(item.id)}
                  className={twMerge(
                    clsx(
                      'w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-200',
                      'hover:bg-[rgba(0,240,255,0.1)]',
                      isActive
                        ? 'bg-gradient-to-r from-[rgba(0,240,255,0.2)] to-transparent'
                        : 'text-[#648db3]',
                      isActive && 'text-[#00f0ff] border-l-2 border-[#00f0ff]',
                      !isActive && 'border-l-2 border-transparent'
                    )
                  )}
                  title={collapsed ? item.label : undefined}
                >
                  <Icon
                    size={20}
                    className={clsx(
                      isActive && 'text-[#00f0ff]',
                      !isActive && 'text-[#648db3]'
                    )}
                  />
                  {!collapsed && (
                    <>
                      <span className="flex-1 text-left font-medium">
                        {item.label}
                      </span>
                      {item.badge && item.badge > 0 && (
                        <span className="px-2 py-0.5 bg-[#ff3366] text-white text-xs rounded-full">
                          {item.badge > 99 ? '99+' : item.badge}
                        </span>
                      )}
                    </>
                  )}
                </button>
              </li>
            );
          })}
        </ul>
      </div>

      {/* Footer */}
      {!collapsed && (
        <div className="p-4 border-t border-[rgba(0,240,255,0.2)]">
          <div className="text-xs text-[#648db3] text-center">
            <p>SafeGuard v2.0.0</p>
            <p className="mt-1">© 2026 安全监控系统</p>
          </div>
        </div>
      )}
    </nav>
  );
}
