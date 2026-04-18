import { ReactNode } from 'react';
import { LucideIcon } from 'lucide-react';
import TechSidebar from './TechSidebar';
import TechHeader from './TechHeader';
import ParticleBackground from '../common/ParticleBackground';

interface NavItem {
  id: string;
  label: string;
  icon: LucideIcon;
  badge?: number;
}

interface TechLayoutProps {
  children: ReactNode;
  navItems: NavItem[];
  activeView: string;
  onViewChange: (id: string) => void;
  title?: string;
  subtitle?: string;
  headerRight?: ReactNode;
  sidebarCollapsed?: boolean;
  onSidebarToggle?: () => void;
}

export default function TechLayout({
  children,
  navItems,
  activeView,
  onViewChange,
  title,
  subtitle,
  headerRight,
  sidebarCollapsed = false,
  onSidebarToggle,
}: TechLayoutProps) {
  return (
    <div className="h-screen flex flex-col relative overflow-hidden">
      {/* Particle Background */}
      <ParticleBackground />

      {/* Grid Background */}
      <div className="grid-background" />

      {/* Main Layout */}
      <div className="flex flex-1 relative z-10">
        {/* Sidebar */}
        <TechSidebar
          items={navItems}
          activeItem={activeView}
          onItemClick={onViewChange}
          collapsed={sidebarCollapsed}
        />

        {/* Main Content Area */}
        <div className="flex-1 flex flex-col overflow-hidden">
          {/* Header */}
          {title && (
            <TechHeader
              title={title}
              subtitle={subtitle}
              rightContent={headerRight}
              onMenuClick={onSidebarToggle}
              showMenu={!!onSidebarToggle}
            />
          )}

          {/* Content */}
          <main className="flex-1 overflow-auto p-6">
            <div className="app-fade-in h-full">
              {children}
            </div>
          </main>
        </div>
      </div>
    </div>
  );
}
