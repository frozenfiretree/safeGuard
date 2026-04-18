import { FileText, Search, Shield } from 'lucide-react';

export default function FilesView() {
  return (
    <div className="glass-panel p-6 h-full flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <h3 className="text-lg font-bold text-[#00f0ff] flex items-center gap-2">
          <FileText size={24} />
          文件管理
        </h3>
        <div className="flex items-center gap-2">
          <button className="tech-button">
            <Shield size={16} className="mr-2" />
            仅敏感
          </button>
          <button className="tech-button">
            <Search size={16} className="mr-2" />
            刷新
          </button>
        </div>
      </div>

      {/* Search */}
      <div className="mb-6">
        <input
          type="text"
          placeholder="搜索文件..."
          className="tech-input"
        />
      </div>

      {/* Table */}
      <div className="flex-1 overflow-auto">
        <div className="text-center text-[#648db3] py-8">
          暂无文件记录
        </div>
      </div>

      {/* Footer */}
      <div className="pt-4 border-t border-[rgba(0,240,255,0.2)] text-sm text-[#648db3]">
        共 0 个文件，其中 0 个敏感
      </div>
    </div>
  );
}
