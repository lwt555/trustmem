import { useState, useRef, useEffect } from "react";
import type { GraphEvent } from "../types";

interface Props {
  selectedAgent: string | null;
  graphEvents: GraphEvent[];
  agentStatuses: Record<string, { status: string; t_eff: string }>;
}

export default function AgentConsole({ selectedAgent, graphEvents, agentStatuses }: Props) {
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
        {status && status.t_eff !== "?" && (
          <span className="text-[10px] text-slate-500 ml-auto">
            T_eff: {status.t_eff}
          </span>
        )}
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
