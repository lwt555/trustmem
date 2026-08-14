import { useState, useCallback, useEffect } from "react";
import type { StepResult } from "./types";
import { useWebSocket, useGraphWebSocket } from "./hooks/useWebSocket";
import TopologyView from "./components/TopologyView";
import VerdictPanel from "./components/VerdictPanel";
import ScenarioPanel from "./components/ScenarioPanel";
import AgentConsole from "./components/AgentConsole";

type DemoMode = "ON" | "OFF" | "DENY";

const MODE_CONFIG: Record<DemoMode, {
  sensitivity: string;
  layer: string;
  trust: string;
  taskId: string;
  label: string;
  agent?: string;
}> = {
  ON:   { sensitivity: "L0", layer: "C", trust: "T3", taskId: "INC-2026-0731", label: "ON (ALLOW)" },
  OFF:  { sensitivity: "L3", layer: "C", trust: "T0", taskId: "INC-2026-0731", label: "OFF (HIDE)" },
  DENY: { sensitivity: "L3", layer: "D", trust: "T0", taskId: "INC-2026-0731", agent: "intel", label: "DENY" },
};

const MODE_DESC: Record<DemoMode, string> = {
  ON:   "合法写入 — 分析师(L2,信任T3) 向 C层 写入 L0 级记忆，预期 ALLOW。",
  OFF:  "高密写入 — 分析师(L2,信任T0) 向 C层 写入 L3 级记忆，触发 BLP-Star 拒绝，预期 HIDE。",
  DENY: "越层写入 — Intel(L3,信任T0) 向 D层 写入 L3 级记忆，无子节点故 LayerWrite 拒绝，预期 DENY。",
};

export default function App() {
  const { connected, connect, disconnect, sendStep, lastResult, setLastResult } = useWebSocket();
  const {
    graphConnected, graphEvents, graphRunning, agentStatuses,
    connectGraph, disconnectGraph, runScenario, abortGraph, clearGraphEvents,
  } = useGraphWebSocket();

  const [history, setHistory] = useState<StepResult[]>([]);
  const [mode, setMode] = useState<DemoMode>("ON");
  const [lastChunkId, setLastChunkId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [writeContent, setWriteContent] = useState("这是演示记忆内容");
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  // 稳定演示会话：水位跨 write/read 步累积（F-30），清空时重建
  const [demoSessionId, setDemoSessionId] = useState(() => "demo-" + Date.now());

  // Connect on mount
  useEffect(() => {
    connect();
    connectGraph();
    return () => { disconnect(); disconnectGraph(); };
  }, [connect, disconnect, connectGraph, disconnectGraph]);

  // Push new results to history
  useEffect(() => {
    if (lastResult) {
      setHistory((prev) => [lastResult!, ...prev]);
    }
  }, [lastResult]);

  const doWrite = useCallback(() => {
    const cfg = MODE_CONFIG[mode];
    setLastResult(null);
    setBusy(true);
    sendStep({
      step_type: "write",
      payload: {
        agent_id: cfg.agent || "analyst",
        session_id: demoSessionId,
        task_id: cfg.taskId,
        content: writeContent,
        sensitivity: cfg.sensitivity,
        layer: cfg.layer,
        memory_type: "EPISODIC",
        op: "INFER",
      },
    });
    setTimeout(() => setBusy(false), 1500);
  }, [mode, sendStep, setLastResult, writeContent, demoSessionId]);

  const doRead = useCallback(() => {
    if (!lastChunkId) return;
    const cfg = MODE_CONFIG[mode];
    setLastResult(null);
    setBusy(true);
    sendStep({
      step_type: "read",
      payload: {
        agent_id: cfg.agent || "executor",
        session_id: demoSessionId,
        task_id: cfg.taskId,
        chunk_id: lastChunkId,
      },
    });
    setTimeout(() => setBusy(false), 1500);
  }, [mode, lastChunkId, sendStep, setLastResult, demoSessionId]);

  // Capture chunk_id from write results
  useEffect(() => {
    if (lastResult?.step_type === "write") {
      for (const se of lastResult.side_effects ?? []) {
        const m = se.match(/(?:mem|chunk)[-_]([a-f0-9]+)/i);
        if (m) { setLastChunkId(m[0]); break; }
      }
    }
  }, [lastResult]);

  const doClear = useCallback(() => {
    setHistory([]);
    setLastResult(null);
    setLastChunkId(null);
    setDemoSessionId("demo-" + Date.now());
    clearGraphEvents();
  }, [setLastResult, clearGraphEvents]);

  const handleRunScenario = useCallback((scenarioId: string) => {
    setSelectedAgent(null);
    runScenario(scenarioId);
  }, [runScenario]);

  return (
    <div className="h-screen flex flex-col bg-slate-950 text-slate-300">
      {/* Scenario Panel (top bar) */}
      <ScenarioPanel
        onRun={handleRunScenario}
        onAbort={abortGraph}
        running={graphRunning}
        graphConnected={graphConnected}
        graphEvents={graphEvents}
      />

      {/* Main area */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left: Topology */}
        <div className="flex-[3] relative bg-slate-950">
          <TopologyView
            lastResult={lastResult}
            agentStatuses={agentStatuses}
            selectedAgent={selectedAgent}
            onSelectAgent={setSelectedAgent}
          />
          {/* Connection badges */}
          <div className="absolute top-3 left-3 flex flex-col gap-1">
            <span className={`inline-flex items-center gap-1.5 px-2 py-1 rounded text-[10px] font-medium
              ${connected ? "bg-green-900/50 text-green-400" : "bg-red-900/50 text-red-400"}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${connected ? "bg-green-400" : "bg-red-400"}`} />
              ws/step
            </span>
            <span className={`inline-flex items-center gap-1.5 px-2 py-1 rounded text-[10px] font-medium
              ${graphConnected ? "bg-green-900/50 text-green-400" : "bg-red-900/50 text-red-400"}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${graphConnected ? "bg-green-400" : "bg-red-400"}`} />
              ws/graph
            </span>
          </div>
        </div>

        {/* Middle: Agent Console */}
        <div className="w-72 flex-shrink-0">
          <AgentConsole
            selectedAgent={selectedAgent}
            graphEvents={graphEvents}
            agentStatuses={agentStatuses}
            watermarks={lastResult?.watermarks ?? null}
          />
        </div>

        {/* Right: Verdict Panel */}
        <div className="w-80 flex-shrink-0">
          <VerdictPanel result={lastResult} history={history} onClear={doClear} />
        </div>
      </div>

      {/* Bottom controls */}
      <div className="border-t border-slate-800 bg-slate-900 flex-shrink-0">
        <div className="px-4 py-1.5 text-[11px] text-slate-400 bg-slate-900/50 border-b border-slate-800/50">
          {MODE_DESC[mode]}
        </div>

        <div className="flex items-center gap-3 px-4 py-2">
          {/* Mode toggle */}
          <div className="flex rounded-lg overflow-hidden border border-slate-700">
            {(Object.keys(MODE_CONFIG) as DemoMode[]).map((m) => (
              <button
                key={m}
                onClick={() => setMode(m)}
                disabled={busy}
                className={`px-3 py-1.5 text-xs font-semibold transition-colors
                  ${m === "ON" && mode === "ON" ? "bg-green-700 text-green-100" : ""}
                  ${m === "OFF" && mode === "OFF" ? "bg-yellow-700 text-yellow-100" : ""}
                  ${m === "DENY" && mode === "DENY" ? "bg-red-700 text-red-100" : ""}
                  ${mode !== m ? "bg-slate-800 text-slate-500 hover:bg-slate-700" : ""}`}>
                {MODE_CONFIG[m].label}
              </button>
            ))}
          </div>

          <input
            type="text"
            value={writeContent}
            onChange={(e) => setWriteContent(e.target.value)}
            placeholder="输入要写入的记忆内容..."
            disabled={busy}
            className="flex-1 max-w-[280px] px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700
                       text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-600
                       disabled:opacity-40 transition-colors"
          />

          <button
            onClick={doWrite}
            disabled={busy || !connected || !writeContent.trim()}
            className="px-4 py-1.5 rounded-lg bg-blue-700 hover:bg-blue-600 disabled:opacity-40
                       text-xs font-semibold text-white transition-colors">
            Write
          </button>
          <button
            onClick={doRead}
            disabled={busy || !connected || !lastChunkId}
            className="px-4 py-1.5 rounded-lg bg-purple-700 hover:bg-purple-600 disabled:opacity-40
                       text-xs font-semibold text-white transition-colors">
            Read
          </button>

          <div className="flex-1" />

          {lastChunkId && (
            <span className="text-[10px] text-slate-600 font-mono">
              chunk: {lastChunkId.slice(0, 16)}...
            </span>
          )}
        </div>
      </div>
    </div>
  );
}
