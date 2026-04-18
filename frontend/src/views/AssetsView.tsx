import TechPanel from '../components/common/TechPanel';

export default function AssetsView() {
  return (
    <TechPanel className="flex items-center justify-center">
      <div className="text-center">
        <div className="text-6xl mb-4">🌐</div>
        <h2 className="text-2xl font-bold text-[#00f0ff] mb-2">资产发现</h2>
        <p className="text-[#648db3]">自动发现和监控网络资产</p>
      </div>
    </TechPanel>
  );
}
