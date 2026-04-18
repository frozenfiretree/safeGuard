import { Monitor, RefreshCw } from 'lucide-react';

export default function AgentsView() {
  return (
    <div className="glass-panel p-6 h-full flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <h3 className="text-lg font-bold text-[#00f0ff] flex items-center gap-2">
          <Monitor size={24} />
          Agent 管理
        </h3>
        <button className="tech-button">
          <RefreshCw size={16} className="mr-2" />
          刷新
        </button>
      </div>

      {/* Search */}
      <div className="mb-6">
        <input
          type="text"
          placeholder="搜索Agent..."
          className="tech-input"
        />
      </div>

      {/* Table */}
      <div className="flex-1 overflow-auto">
        <div className="text-center text-[#648db3] py-8">
          暂无Agent注册
        </div>
      </div>

      {/* Footer */}
      <div className="pt-4 border-t border-[rgba(0,240,255,0.2)] text-sm text-[#648db3]">
        共 0 个Agent，其中 0 个在线
      </div>
    </div>
  );
}
