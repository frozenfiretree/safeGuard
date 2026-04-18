import TechPanel from '../components/common/TechPanel';

export default function RulesView() {
  return (
    <TechPanel className="flex items-center justify-center">
      <div className="text-center">
        <div className="text-6xl mb-4">⚡</div>
        <h2 className="text-2xl font-bold text-[#00f0ff] mb-2">检测规则</h2>
        <p className="text-[#648db3]">配置敏感信息检测规则</p>
      </div>
    </TechPanel>
  );
}
