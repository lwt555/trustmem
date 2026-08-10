import type { StepResult } from "../types";

interface Props {
  result: StepResult | null;
  history: StepResult[];
  onClear: () => void;
}

export default function VerdictPanel({ result, history, onClear }: Props) {
  const all = result ? [result, ...history] : history;

  return (
    <div className="h-full flex flex-col bg-slate-900 border-l border-slate-700">
      <div className="px-4 py-3 border-b border-slate-700 flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-300">裁决详情</h2>
        <button onClick={onClear}
                className="text-xs text-slate-500 hover:text-slate-300 transition-colors">
          清空
        </button>
      </div>
      <div className="flex-1 overflow-y-auto p-3 space-y-2">
        {all.map((r, i) => (
          <div key={i}
               className={`rounded-lg p-3 text-xs border
                 ${r.decision_verdict === "ALLOW" ? "border-green-800 bg-green-950/30" : ""}
                 ${r.decision_verdict === "HIDE" ? "border-yellow-800 bg-yellow-950/30" : ""}
                 ${r.decision_verdict === "DENY" ? "border-red-800 bg-red-950/30" : ""}
                 ${r.decision_verdict === "ERROR" ? "border-gray-700 bg-gray-900/50" : ""}`}>
            {/* Header */}
            <div className="flex items-center gap-2 mb-1.5">
              <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase
                ${r.decision_verdict === "ALLOW" ? "bg-green-800 text-green-300" : ""}
                ${r.decision_verdict === "HIDE" ? "bg-yellow-800 text-yellow-300" : ""}
                ${r.decision_verdict === "DENY" ? "bg-red-800 text-red-300" : ""}
                ${r.decision_verdict === "ERROR" ? "bg-gray-700 text-gray-300" : ""}`}>
                {r.decision_verdict}
              </span>
              <span className="text-slate-500">{r.step_type.toUpperCase()}</span>
              {r.merkle_root && (
                <span className="text-[10px] text-slate-600 ml-auto"
                      title={r.merkle_root}>
                  #{r.merkle_root.slice(0, 10)}...
                </span>
              )}
            </div>

            {/* Checks */}
            {r.checks.length > 0 && (
              <div className="space-y-0.5 mb-1">
                {r.checks.map((c, j) => (
                  <div key={j} className="flex items-center gap-1.5">
                    <span className={c.passed ? "text-green-400" : "text-red-400"}>
                      {c.passed ? "✓" : "✗"}
                    </span>
                    <span className="text-slate-400">{c.rule}</span>
                    <span className="text-slate-600 text-[10px] truncate">{c.detail}</span>
                  </div>
                ))}
              </div>
            )}

            {/* VarHandle */}
            {r.var_handle && (
              <div className="mt-1 rounded bg-slate-800/50 p-1.5 text-[10px]">
                <span className="text-yellow-400 font-mono">{r.var_handle.placeholder}</span>
                <span className="text-slate-500 ml-1">({r.var_handle.reason})</span>
              </div>
            )}

            {/* Side effects */}
            {r.side_effects.length > 0 && (
              <div className="mt-1 text-[10px] text-slate-500 space-y-0.5">
                {r.side_effects.map((se, j) => (
                  <div key={j}>⚡ {se}</div>
                ))}
              </div>
            )}
          </div>
        ))}

        {all.length === 0 && (
          <div className="text-center text-slate-600 py-8 text-sm">
            尚未执行任何裁决
            <br />
            <span className="text-xs">点击左侧按钮开始单步演示</span>
          </div>
        )}
      </div>

      {/* Legend */}
      <div className="px-4 py-2 border-t border-slate-700 flex gap-3 text-[10px] text-slate-500">
        <span className="flex items-center gap-1">
          <span className="w-2 h-2 rounded-full bg-green-500" /> ALLOW
        </span>
        <span className="flex items-center gap-1">
          <span className="w-2 h-2 rounded-full bg-yellow-500" /> HIDE
        </span>
        <span className="flex items-center gap-1">
          <span className="w-2 h-2 rounded-full bg-red-500" /> DENY
        </span>
      </div>
    </div>
  );
}
