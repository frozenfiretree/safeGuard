import TechPanel from '../components/common/TechPanel';

export default function ConfigView() {
  return (
    <TechPanel className="flex items-center justify-center">
      <div className="text-center">
        <div className="text-6xl mb-4">🔧</div>
        <h2 className="text-2xl font-bold text-[#00f0ff] mb-2">系统配置</h2>
        <p className="text-[#648db3]">全局配置与参数设置</p>
      </div>
    </TechPanel>
  );
}
