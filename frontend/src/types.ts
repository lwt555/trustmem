/** Shared types matching backend API schemas. */

export interface AgentInfo {
  agent_id: string;
  role: string;
  clearance: string;
  trust: string;
  tools: string[];
  task_domain: string[];
}

export interface VarHandleInfo {
  var_id: string;
  placeholder: string;
  reason: string;
  constraint_types: string[];
  metadata: Record<string, string>;
}

export interface StepResult {
  step_type: "write" | "read";
  allowed: boolean;
  hidden: boolean;
  decision_verdict: string;
  explanation: string;
  checks: CheckInfo[];
  side_effects: string[];
  merkle_root: string | null;
  var_handle: VarHandleInfo | null;
  watermarks: Watermarks | null;
}

export interface Watermarks {
  c_eff: string;            // 机密性高水位（只升）
  t_eff: string;            // 完整性低水位（只降）
  t_eff_ctl: string;        // LLM 控制流隔离水位
  capacity_used_bits: number;
  capacity_budget_bits: number;
}

export interface CheckInfo {
  rule: string;
  passed: boolean;
  detail: string;
}

export interface SystemStats {
  memories: number;
  sessions: number;
  merkle_blocks: number;
  merkle_events: number;
  merkle_root: string | null;
  var_handles: number;
}

/** Topology layout: fixed positions for 6 agents. */
export const AGENT_LAYOUT: Record<string, { x: number; y: number }> = {
  planner: { x: 400, y: 20 },
  intel: { x: 100, y: 160 },
  log: { x: 400, y: 160 },
  analyst: { x: 700, y: 160 },
  executor: { x: 400, y: 320 },
  auditor: { x: 700, y: 350 },
};

export const CLEARANCE_COLORS: Record<string, string> = {
  L0: "#94a3b8",
  L1: "#60a5fa",
  L2: "#f59e0b",
  L3: "#ef4444",
};

export const TRUST_COLORS: Record<string, string> = {
  T0: "#ef4444",
  T1: "#f97316",
  T2: "#eab308",
  T3: "#22c55e",
};

// ── Agent Runtime types ────────────────────────────────

export interface AgentStatus {
  agent_id: string;
  role: string;
  status: "thinking" | "acting" | "waiting" | "done" | "idle";
  t_eff: string;
  t_intrinsic: string;
  tool_names: string[];
  steps: AgentStep[];
  recent_reads: string[];
  recent_writes: string[];
}

export interface AgentStep {
  step_id: string;
  step_type: "thought" | "tool_call" | "tool_result" | "memory_read" | "memory_write" | "report";
  content: string;
  tool_name?: string;
  tool_args?: Record<string, unknown>;
  decision?: {
    verdict: string;
    action: string;
    subject: string;
    object: string;
    checks: CheckInfo[];
    denied_by?: string;
  };
  at: string;
}

export interface GraphEvent {
  event_type: string;
  agent_id: string;
  payload: Record<string, unknown>;
  at: string;
}

export interface ScenarioInfo {
  scenario_id: string;
  name: string;
  description: string;
  status: string;
  phase: string;
  current_agent: string;
}

/** Agent status colors */
export const STATUS_COLORS: Record<string, string> = {
  idle: "#475569",
  thinking: "#3b82f6",
  acting: "#f59e0b",
  waiting: "#8b5cf6",
  done: "#22c55e",
};
