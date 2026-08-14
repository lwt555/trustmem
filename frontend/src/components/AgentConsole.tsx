import { useState, useRef, useEffect } from "react";
import type { GraphEvent, Watermarks } from "../types";

interface Props {
  selectedAgent: string | null;
  graphEvents: GraphEvent[];
  agentStatuses: Record<string, { status: string; t_eff: string }>;
  watermarks: Watermarks | null;
}

/** Parse "L0".."L3" / "T0".."T3" → 0..3 (missing → 0). */
function levelOf(s: string): number {
  const n = parseInt(s.replace(/[^0-9]/g, ""), 10);
  return Number.isFinite(n) ? n : 0;
}

const GAUGE_W = 280;
const GAUGE_L = 22;
const GAUGE_R = GAUGE_W - 22;
const AXIS = GAUGE_R - GAUGE_L;

/** Map a 0..3 level onto the horizontal track: 0 → left, 3 → right. */
function xOf(level: number): number {
  return GAUGE_L + (level / 3) * AXIS;
}

export default function AgentConsole({ selectedAgent, graphEvents, agentStatuses, watermarks }: Props) {
  const [tab, setTab] = useState<"thought" | "actions" | "memory">("thought");
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [graphEvents]);

  const agentEvents = selectedAgent
    ? graphEvents.filter(e => e.agent_id === selectedAgent)
    : graphEvents;

  const thoughtItems = agentEvents.filter(e =>
    e.event_type === "agent_thought" || e.event_type === "node_start" || e.event_type === "node_end"
  );

  const actionItems = agentEvents.filter(e =>
    e.event_type === "agent_tool_call" || e.event_type === "agent_tool_result"
  );

  const memoryItems = agentEvents.filter(e =>
    e.event_type === "memory_write" || e.event_type === "memory_read" || e.event_type === "pdp_decision"
  );

  const displayItems = tab === "thought" ? thoughtItems
    : tab === "actions" ? actionItems
    : memoryItems;

  const status = selectedAgent ? agentStatuses[selectedAgent] : null;

  // ── F-30 双水位标尺：对接后端 /ws/step 返回的 watermarks ──
  const c = watermarks?.c_eff ?? "?";
  const t = watermarks?.t_eff ?? "?";
  const ctl = watermarks?.t_eff_ctl ?? "?";
  const used = watermarks?.capacity_used_bits ?? 0;
  const budget = watermarks?.capacity_budget_bits ?? 4;

  const cLevel = levelOf(c);
  const tLevel = levelOf(t);
  const ctlLevel = levelOf(ctl);
  const cx = xOf(cLevel);
  const tx = xOf(tLevel);
  const ctlX = xOf(ctlLevel);
  const capacityPct = budget > 0 ? Math.min(100, (used / budget) * 100) : 0;

  return (
    <div className="h-full flex flex-col bg-slate-900 border-l border-slate-700">
      {/* Header */}
      <div className="px-4 py-2 border-b border-slate-700 flex items-center gap-2">
        <h2 className="text-sm font-semibold text-slate-300">
          {selectedAgent ? `${selectedAgent}` : "Agent Console"}
        </h2>
        {status && (
          <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium
            ${status.status === "thinking" ? "bg-blue-900/50 text-blue-300" : ""}
            ${status.status === "done" ? "bg-green-900/50 text-green-300" : ""}`}>
            {status.status}
          </span>
        )}
      </div>

      {/* 双水位标尺 (F-30)：c_eff 只升（向右）、t_eff 只降（向左），相向而行 */}
      <div className="px-3 py-2 border-b border-slate-700 bg-slate-950/40">
        <svg viewBox={`0 0 ${GAUGE_W} 30`} className="w-full">
          {/* axis */}
          <line x1={GAUGE_L} y1={12} x2={GAUGE_R} y2={12} stroke="#334155" strokeWidth={2} />
          {/* ticks 0..3 */}
          {[0, 1, 2, 3].map((lv) => {
            const x = xOf(lv);
            return (
              <g key={lv}>
                <line x1={x} y1={8} x2={x} y2={16} stroke="#1e293b" strokeWidth={1} />
                <text x={x} y={27} textAnchor="middle" fill="#475569" fontSize={7} fontFamily="monospace">
                  {lv}
                </text>
              </g>
            );
          })}
          {/* c_eff pointer（蓝，向右升） */}
          <polygon points={`${cx},12 ${cx - 6},5 ${cx - 6},19`} fill="#60a5fa" />
          <text x={cx} y={4} textAnchor="middle" fill="#60a5fa" fontSize={8} fontWeight={700} fontFamily="monospace">
            {c === "?" ? "c" : c}
          </text>
          {/* t_eff pointer（橙，向左降） */}
          <polygon points={`${tx},12 ${tx + 6},5 ${tx + 6},19`} fill="#f97316" />
          <text x={tx} y={4} textAnchor="middle" fill="#f97316" fontSize={8} fontWeight={700} fontFamily="monospace">
            {t === "?" ? "t" : t}
          </text>
          {/* t_eff_ctl marker（紫虚线） */}
          <line x1={ctlX} y1={6} x2={ctlX} y2={18} stroke="#a78bfa" strokeWidth={1.5} strokeDasharray="3 2" />
        </svg>

        <div className="flex items-center justify-between mt-1 text-[9px] text-slate-500 font-mono">
          <span>c_eff <span className="text-blue-400">{c}</span>↑</span>
          <span>t_eff <span className="text-orange-400">{t}</span>↓</span>
          <span>ctl <span className="text-purple-400">{ctl}</span></span>
        </div>

        {/* 4 bit 容量预算 */}
        <div className="mt-1">
          <div className="flex items-center justify-between text-[9px] text-slate-500">
            <span>容量</span>
            <span className="font-mono">{used.toFixed(1)}/{budget.toFixed(1)} bit</span>
          </div>
          <div className="h-1 rounded bg-slate-800 overflow-hidden">
            <div
              className="h-full rounded transition-all duration-300"
              style={{
                width: `${capacityPct}%`,
                background: capacityPct >= 100 ? "#ef4444" : capacityPct >= 75 ? "#f59e0b" : "#22c55e",
              }}
            />
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-700">
        {(["thought", "actions", "memory"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`flex-1 px-2 py-1.5 text-xs font-medium transition-colors
              ${tab === t ? "bg-slate-800 text-slate-200 border-b-2 border-blue-500" : "text-slate-500 hover:text-slate-400"}`}>
            {t === "thought" ? "思考" : t === "actions" ? "动作" : "记忆"}
          </button>
        ))}
      </div>

      {/* Content */}
      <div ref={scrollRef} className="flex-1 overflow-y-auto p-2 space-y-1">
        {displayItems.length === 0 && (
          <div className="text-center text-slate-600 py-6 text-xs">
            {selectedAgent ? "选择Agent查看详情" : "运行场景查看Agent行为"}
          </div>
        )}

        {displayItems.map((e, i) => (
          <div key={i}
            className={`rounded p-1.5 text-[11px] leading-relaxed
              ${e.event_type === "node_start" ? "bg-blue-950/20 border border-blue-900/30" : ""}
              ${e.event_type === "node_end" ? "bg-green-950/20 border border-green-900/30" : ""}
              ${e.event_type === "agent_thought" ? "bg-slate-800/50" : ""}
              ${e.event_type === "agent_tool_result" ? "bg-purple-950/20 border border-purple-900/30" : ""}
              ${e.event_type === "memory_write" ? "bg-emerald-950/20 border border-emerald-900/30" : ""}
              ${e.event_type === "pdp_decision" ? "bg-orange-950/20 border border-orange-900/30" : ""}
              ${e.event_type === "graph_error" ? "bg-red-950/30 border border-red-900/40" : ""}`}>
            <div className="flex items-center gap-1.5 mb-0.5">
              <span className="text-[10px] font-mono text-slate-600">
                {e.event_type.replace("agent_", "").replace("_", " ")}
              </span>
              <span className="text-[9px] text-slate-600 ml-auto">
                {e.at?.slice(11, 19) ?? ""}
              </span>
            </div>
            <div className="text-slate-400 whitespace-pre-wrap break-words">
              {typeof e.payload?.content === "string"
                ? e.payload.content.slice(0, 300)
                : e.payload?.error
                  ? `Error: ${e.payload.error}`
                  : JSON.stringify(e.payload).slice(0, 300)}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
