import { useState } from 'react';
import {
  Users,
  FileText,
  AlertTriangle,
  Shield,
  Cpu,
  HardDrive,
  Network,
} from 'lucide-react';

export default function OverviewView() {
  const [loading, setLoading] = useState(false);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="loading-spinner"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* 统计卡片 */}
      <div className="panel-grid-4">
        <div className="glass-panel p-6 relative overflow-hidden">
          <div className="flex items-start justify-between mb-4">
            <div className="p-3 bg-gradient-to-br from-[rgba(0,240,255,0.2)] to-transparent rounded-lg">
              <Users size={24} className="text-[#00f0ff]" />
            </div>
          </div>
          <div className="text-3xl font-bold text-white mb-1 glow-text">2</div>
          <div className="text-sm text-[#648db3]">在线Agent</div>
        </div>

        <div className="glass-panel p-6 relative overflow-hidden">
          <div className="flex items-start justify-between mb-4">
            <div className="p-3 bg-gradient-to-br from-[rgba(0,240,255,0.2)] to-transparent rounded-lg">
              <FileText size={24} className="text-[#00f0ff]" />
            </div>
          </div>
          <div className="text-3xl font-bold text-white mb-1 glow-text">156</div>
          <div className="text-sm text-[#648db3]">监控文件</div>
        </div>

        <div className="glass-panel p-6 relative overflow-hidden">
          <div className="flex items-start justify-between mb-4">
            <div className="p-3 bg-gradient-to-br from-[rgba(0,240,255,0.2)] to-transparent rounded-lg">
              <Shield size={24} className="text-[#00f0ff]" />
            </div>
          </div>
          <div className="text-3xl font-bold text-white mb-1 glow-text">23</div>
          <div className="text-sm text-[#648db3]">敏感文件</div>
        </div>

        <div className="glass-panel p-6 relative overflow-hidden">
          <div className="flex items-start justify-between mb-4">
            <div className="p-3 bg-gradient-to-br from-[rgba(0,240,255,0.2)] to-transparent rounded-lg">
              <AlertTriangle size={24} className="text-[#00f0ff]" />
            </div>
          </div>
          <div className="text-3xl font-bold text-white mb-1 glow-text">47</div>
          <div className="text-sm text-[#648db3]">安全事件</div>
        </div>
      </div>

      {/* 图表区域 */}
      <div className="panel-grid-2">
        <div className="glass-panel p-6">
          <h3 className="text-lg font-bold text-[#00f0ff] mb-6">事件趋势分析</h3>
          <div className="h-64 flex items-center justify-center text-[#648db3]">
            图表组件加载中...
          </div>
        </div>

        <div className="glass-panel p-6">
          <h3 className="text-lg font-bold text-[#00f0ff] mb-6">敏感文件分布</h3>
          <div className="h-64 flex items-center justify-center text-[#648db3]">
            图表组件加载中...
          </div>
        </div>
      </div>

      {/* 系统状态 */}
      <div className="glass-panel p-6">
        <h3 className="text-lg font-bold text-[#00f0ff] mb-4">系统状态</h3>
        <div className="panel-grid-3">
          <div className="flex items-center gap-4 p-4 bg-[rgba(0,240,255,0.05)] rounded-lg">
            <Cpu size={32} className="text-[#00f0ff]" />
            <div className="flex-1">
              <div className="text-sm text-[#648db3]">CPU使用率</div>
              <div className="text-2xl font-bold text-white">45%</div>
            </div>
          </div>
          <div className="flex items-center gap-4 p-4 bg-[rgba(0,240,255,0.05)] rounded-lg">
            <HardDrive size={32} className="text-[#00f0ff]" />
            <div className="flex-1">
              <div className="text-sm text-[#648db3]">内存使用率</div>
              <div className="text-2xl font-bold text-white">68%</div>
            </div>
          </div>
          <div className="flex items-center gap-4 p-4 bg-[rgba(0,240,255,0.05)] rounded-lg">
            <Network size={32} className="text-[#00f0ff]" />
            <div className="flex-1">
              <div className="text-sm text-[#648db3]">网络状态</div>
              <div className="text-2xl font-bold text-[#00ffaa]">正常</div>
            </div>
          </div>
        </div>
      </div>

      {/* 最近事件 */}
      <div className="glass-panel p-6">
        <h3 className="text-lg font-bold text-[#00f0ff] mb-4">最近安全事件</h3>
        <div className="text-center text-[#648db3] py-8">
          暂无事件数据
        </div>
      </div>
    </div>
  );
}
