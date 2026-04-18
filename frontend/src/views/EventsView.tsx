import TechPanel from '../components/common/TechPanel';

export default function EventsView() {
  return (
    <TechPanel className="flex items-center justify-center">
      <div className="text-center">
        <div className="text-6xl mb-4">📊</div>
        <h2 className="text-2xl font-bold text-[#00f0ff] mb-2">事件日志</h2>
        <p className="text-[#648db3]">系统事件审计与查询</p>
      </div>
    </TechPanel>
  );
}
