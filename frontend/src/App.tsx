import { useState } from 'react';
import {
  LayoutDashboard,
  Monitor,
  FileText,
  Shield,
  AlertCircle,
  Activity,
  Cpu,
  Settings,
  Globe,
} from 'lucide-react';
import TechLayout from './components/layout/TechLayout';
import OverviewView from './views/OverviewView';
import AgentsView from './views/AgentsView';
import FilesView from './views/FilesView';
import AssetsView from './views/AssetsView';
import SensitiveView from './views/SensitiveView';
import RulesView from './views/RulesView';
import EventsView from './views/EventsView';
import RuntimeView from './views/RuntimeView';
import ConfigView from './views/ConfigView';

export default function App() {
  const [activeView, setActiveView] = useState('overview');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  const navItems = [
    { id: 'overview', label: '总览', icon: LayoutDashboard },
    { id: 'agents', label: 'Agent管理', icon: Monitor },
    { id: 'files', label: '文件监控', icon: FileText },
    { id: 'sensitive', label: '敏感档案', icon: Shield },
    { id: 'rules', label: '检测规则', icon: AlertCircle },
    { id: 'events', label: '事件日志', icon: Activity },
    { id: 'assets', label: '资产发现', icon: Globe },
    { id: 'runtime', label: '运行时监控', icon: Cpu },
    { id: 'config', label: '系统配置', icon: Settings },
  ];

  const renderActiveView = () => {
    switch (activeView) {
      case 'overview':
        return <OverviewView />;
      case 'agents':
        return <AgentsView />;
      case 'files':
        return <FilesView />;
      case 'sensitive':
        return <SensitiveView />;
      case 'rules':
        return <RulesView />;
      case 'events':
        return <EventsView />;
      case 'assets':
        return <AssetsView />;
      case 'runtime':
        return <RuntimeView />;
      case 'config':
        return <ConfigView />;
      default:
        return <OverviewView />;
    }
  };

  return (
    <div className="h-screen flex flex-col relative overflow-hidden">
      {/* Background */}
      <div className="fixed inset-0 bg-[#050a15]"></div>
      <div className="grid-background" />

      {/* Main Layout */}
      <div className="flex flex-1 relative z-10">
        {/* Sidebar */}
        <nav className="glass-panel border-r border-[rgba(0,240,255,0.2)] w-64 flex flex-col">
          {/* Logo */}
          <div className="h-20 flex items-center justify-center border-b border-[rgba(0,240,255,0.2)]">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-gradient-to-br from-[#0070cc] to-[#00f0ff] rounded-lg flex items-center justify-center">
                <span className="text-black font-bold text-xl">S</span>
              </div>
              <div>
                <h1 className="text-lg font-bold text-white">SafeGuard</h1>
                <p className="text-xs text-[#648db3]">安全监控系统</p>
              </div>
                       </div>
          </div>

          {/* Navigation */}
          <div className="flex-1 py-4">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeView === item.id;

              return (
                <button
                  key={item.id}
                  onClick={() => setActiveView(item.id)}
                  className={`w-full flex items-center gap-3 px-6 py-3 transition-all duration-200 ${
                    isActive
                      ? 'bg-gradient-to-r from-[rgba(0,240,255,0.2)] to-transparent text-[#00f0ff] border-l-2 border-[#00f0ff]'
                      : 'text-[#648db3] border-l-2 border-transparent hover:bg-[rgba(0,240,255,0.1)]'
                  }`}
                >
                  <Icon size={20} />
                  <span className="font-medium">{item.label}</span>
                </button>
              );
            })}
          </div>
        </nav>

        {/* Main Content */}
        <div className="flex-1 flex flex-col overflow-hidden">
          {/* Header */}
          <header className="h-20 px-6 flex items-center border-b border-[rgba(0,240,255,0.2)] bg-gradient-to-b from-[rgba(10,21,37,0.95)] to-[rgba(10,21,37,0.4)]">
            <div>
              <h1 className="text-2xl font-bold text-white glow-text">
                SafeGuard 安全监控系统
              </h1>
              <p className="text-sm text-[#648db3]">敏感信息检测与溯源系统 v2.0</p>
            </div>
          </header>

          {/* Content */}
          <main className="flex-1 overflow-auto p-6">
            {renderActiveView()}
          </main>
        </div>
      </div>
    </div>
  );
}
