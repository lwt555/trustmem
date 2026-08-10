import { useEffect, useState } from "react";
import type { AgentInfo, StepResult } from "../types";
import { AGENT_LAYOUT } from "../types";
import AgentNode from "./AgentNode";
import MemoryEdge from "./MemoryEdge";

const CONNECTIONS: [string, string, string][] = [
  ["planner", "intel",   "分配情报任务"],
  ["planner", "log",     "分配日志任务"],
  ["planner", "analyst", "分配分析任务"],
  ["intel",   "log",     "原始情报"],
  ["log",     "analyst", "情报流转"],
  ["log",     "executor","执行任务"],
  ["analyst", "executor","分析结果"],
  ["executor","auditor", "操作日志"],
  ["auditor", "planner", "审计报告"],
];

const AGENT_ROLES: Record<string, string> = {
  planner:  "计划者：分配任务、统筹调度",
  intel:    "情报员：收集外部情报",
  log:      "日志员：汇聚、持久化日志",
  analyst:  "分析师：分析情报、生成报告",
  executor: "执行者：执行具体操作",
  auditor:  "审计员：验证操作合法性",
};

interface Props {
  lastResult: StepResult | null;
  agentStatuses?: Record<string, { status: string; t_eff: string }>;
  onSelectAgent?: (agentId: string) => void;
  selectedAgent?: string | null;
}

export default function TopologyView({ lastResult, agentStatuses, onSelectAgent, selectedAgent }: Props) {
  const [agents, setAgents] = useState<AgentInfo[]>([]);
  const [verdictMap, setVerdictMap] = useState<Record<string, string | null>>({});

  useEffect(() => {
    fetch("/api/agents")
      .then((r) => r.json())
      .then((data) => setAgents(data.agents ?? []))
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (lastResult) {
      const v = lastResult.decision_verdict as string;
      CONNECTIONS.forEach(([from, to]) => {
        setVerdictMap((prev) => ({ ...prev, [`${from}->${to}`]: v }));
      });
    }
  }, [lastResult]);

  const getPos = (agentId: string) => {
    const name = agentId.toLowerCase();
    return AGENT_LAYOUT[name] ?? { x: 400, y: 250 };
  };

  const activeAgentId = lastResult?.step_type
    ? (lastResult.step_type === "write" ? "executor" : "analyst")
    : null;

  return (
    <div className="relative w-full h-full">
      <svg viewBox="50 -20 750 430" className="w-full h-full">
        {/* Edge labels */}
        {CONNECTIONS.map(([from, to, label]) => {
          const fp = getPos(from);
          const tp = getPos(to);
          const mx = (fp.x + tp.x) / 2;
          const my = (fp.y + tp.y) / 2;
          // Perpendicular offset to avoid overlapping the edge line
          const dx = tp.x - fp.x;
          const dy = tp.y - fp.y;
          const len = Math.sqrt(dx * dx + dy * dy) || 1;
          const ox = (-dy / len) * 10;
          const oy = (dx / len) * 10;
          return (
            <text
              key={`label-${from}-${to}`}
              x={mx + ox}
              y={my + oy}
              textAnchor="middle"
              fill="#64748b"
              fontSize={9}
              fontFamily="sans-serif"
            >
              {label}
            </text>
          );
        })}

        {/* Edges */}
        {CONNECTIONS.map(([from, to]) => {
          const fp = getPos(from);
          const tp = getPos(to);
          const v = verdictMap[`${from}->${to}`] || null;
          const active = v !== null;
          return (
            <MemoryEdge
              key={`${from}-${to}`}
              fromX={fp.x} fromY={fp.y}
              toX={tp.x} toY={tp.y}
              active={active}
              verdict={v as "ALLOW" | "HIDE" | "DENY" | null}
            />
          );
        })}

        {/* Agents */}
        {agents.map((a) => {
          const pos = getPos(a.agent_id);
          const st = agentStatuses?.[a.agent_id];
          return (
            <g key={a.agent_id}
               onClick={() => onSelectAgent?.(a.agent_id)}
               className={onSelectAgent ? "cursor-pointer" : ""}>
              <AgentNode
                agent={a}
                x={pos.x} y={pos.y}
                active={selectedAgent === a.agent_id || activeAgentId === a.agent_id}
                lastVerdict={activeAgentId === a.agent_id ? (lastResult?.decision_verdict ?? null) : null}
              />
              {st && (
                <text x={pos.x} y={pos.y + 32} textAnchor="middle"
                      fill="#94a3b8" fontSize={8} fontFamily="monospace">
                  {st.status.toUpperCase()} T:{st.t_eff}
                </text>
              )}
            </g>
          );
        })}
      </svg>

      {/* Legend overlay */}
      <div className="absolute bottom-2 left-2 right-2 bg-slate-900/90 border border-slate-700 rounded-lg p-3 text-[10px] leading-relaxed">
        <div className="flex flex-wrap gap-x-5 gap-y-1">
          <div className="flex flex-col gap-0.5 min-w-[140px]">
            <span className="text-slate-400 font-semibold mb-0.5">连线含义</span>
            {CONNECTIONS.map(([from, to, label]) => (
              <span key={`leg-${from}-${to}`} className="text-slate-500">
                <span className="text-slate-300">{from}</span> →{" "}
                <span className="text-slate-300">{to}</span>
                <span className="text-slate-600"> — {label}</span>
              </span>
            ))}
          </div>
          <div className="flex flex-col gap-0.5 min-w-[120px]">
            <span className="text-slate-400 font-semibold mb-0.5">节点角色</span>
            {Object.entries(AGENT_ROLES).map(([id, desc]) => (
              <span key={id} className="text-slate-500">
                <span className="text-slate-300">{id}</span>
                <span className="text-slate-600"> — {desc}</span>
              </span>
            ))}
          </div>
          <div className="flex flex-col gap-0.5 min-w-[100px]">
            <span className="text-slate-400 font-semibold mb-0.5">图例</span>
            <span className="text-slate-500">
              <span className="inline-block w-2.5 h-2.5 rounded-full align-middle mr-1 bg-slate-500" style={{ border: "2px solid #22c55e" }} />
              <span className="text-slate-600">外圈颜色 = 完整性 (T0–T3)</span>
            </span>
            <span className="text-slate-500">
              <span className="inline-block w-2.5 h-2.5 rounded-full align-middle mr-1 bg-green-500/30" />
              <span className="text-slate-600">内圈填充 = 机密级 (L0–L3)</span>
            </span>
            <span className="text-slate-500">
              <span className="inline-block w-2.5 h-2.5 rounded-full align-middle mr-1 bg-slate-400" />
              <span className="text-slate-600">高亮节点 = 当前操作主体</span>
            </span>
            <span className="text-slate-500">
              <span className="inline-block w-2.5 h-2.5 rounded-full align-middle mr-1 bg-green-500" />
              <span className="text-slate-600">粒子 = 裁决结果传播</span>
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
