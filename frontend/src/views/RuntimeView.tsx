import TechPanel from '../components/common/TechPanel';

export default function RuntimeView() {
  return (
    <TechPanel className="flex items-center justify-center">
      <div className="text-center">
        <div className="text-6xl mb-4">⚙️</div>
        <h2 className="text-2xl font-bold text-[#00f0ff] mb-2">运行时监控</h2>
        <p className="text-[#648db3]">系统性能与状态监控</p>
      </div>
    </TechPanel>
  );
}
