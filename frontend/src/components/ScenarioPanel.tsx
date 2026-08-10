import type { ScenarioInfo, GraphEvent } from "../types";

const SCENARIO_LIST: ScenarioInfo[] = [
  {
    scenario_id: "threat-intel",
    name: "威胁情报处理",
    description: "外部T1情报 → PDP裁决 → 限制高危工具调用",
    status: "", phase: "", current_agent: "",
  },
  {
    scenario_id: "incident-response",
    name: "安全事件响应",
    description: "内部T3日志 → 高可信链路 → 成功执行处置",
    status: "", phase: "", current_agent: "",
  },
  {
    scenario_id: "echoleak",
    name: "EchoLeak攻击演示",
    description: "恶意情报夹带外泄 → 双平面联合防御截断",
    status: "", phase: "", current_agent: "",
  },
];

interface Props {
  onRun: (scenarioId: string) => void;
  onAbort: () => void;
  running: boolean;
  graphConnected: boolean;
  graphEvents: GraphEvent[];
}

export default function ScenarioPanel({ onRun, onAbort, running, graphConnected, graphEvents }: Props) {
  const phases = ["planner", "intel", "log", "analyst", "executor", "auditor"];
  const currentAgent = graphEvents.length > 0
    ? graphEvents.findLast(e => e.event_type === "node_start")?.agent_id ?? ""
    : "";

  const phaseIndex = phases.indexOf(currentAgent);

  return (
    <div className="flex items-center gap-3 px-4 py-2 bg-slate-900 border-b border-slate-800">
      <span className="text-xs font-semibold text-slate-400 shrink-0">场景选择</span>

      {/* Scenario buttons */}
      <div className="flex gap-1.5">
        {SCENARIO_LIST.map((s) => (
          <button
            key={s.scenario_id}
            onClick={() => onRun(s.scenario_id)}
            disabled={running}
            title={s.description}
            className={`px-3 py-1 rounded text-xs font-medium transition-colors
              ${running
                ? "bg-slate-800 text-slate-600 cursor-not-allowed"
                : "bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700"}`}
          >
            {s.name}
          </button>
        ))}
      </div>

      {/* Phase indicator */}
      {running && (
        <div className="flex items-center gap-1.5 ml-2">
          <span className="text-[10px] text-slate-500">阶段:</span>
          {phases.map((p, i) => (
            <span key={p}
              className={`w-4 h-4 rounded-full text-[9px] flex items-center justify-center font-bold transition-all
                ${i < phaseIndex ? "bg-green-800 text-green-300" : ""}
                ${i === phaseIndex ? "bg-blue-700 text-blue-200 animate-pulse" : ""}
                ${i > phaseIndex ? "bg-slate-800 text-slate-600" : ""}`}
              title={p}>
              {p[0].toUpperCase()}
            </span>
          ))}
          <span className="text-[10px] text-slate-500 ml-1">{currentAgent}</span>
        </div>
      )}

      <div className="flex-1" />

      {/* Connection + controls */}
      <span className={`w-1.5 h-1.5 rounded-full ${graphConnected ? "bg-green-400" : "bg-red-400"}`} />
      <span className="text-[10px] text-slate-500">
        {graphConnected ? "graph已连接" : "graph未连接"}
      </span>

      {running ? (
        <button
          onClick={onAbort}
          className="px-3 py-1 rounded bg-red-800 hover:bg-red-700 text-xs font-semibold text-red-200 transition-colors">
          停止
        </button>
      ) : null}
    </div>
  );
}
