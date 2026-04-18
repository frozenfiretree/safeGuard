import TechPanel from '../components/common/TechPanel';

export default function SensitiveView() {
  return (
    <TechPanel className="flex items-center justify-center">
      <div className="text-center">
        <div className="text-6xl mb-4">📁</div>
        <h2 className="text-2xl font-bold text-[#00f0ff] mb-2">敏感档案</h2>
        <p className="text-[#648db3]">敏感文件归档与版本追踪</p>
      </div>
    </TechPanel>
  );
}
