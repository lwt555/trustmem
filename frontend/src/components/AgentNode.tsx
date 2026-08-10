import { useEffect, useState } from "react";
import type { AgentInfo } from "../types";
import { CLEARANCE_COLORS, TRUST_COLORS } from "../types";

interface Props {
  agent: AgentInfo;
  x: number;
  y: number;
  active: boolean;
  lastVerdict: string | null; // "ALLOW" | "HIDE" | "DENY" | null
}

export default function AgentNode({ agent, x, y, active, lastVerdict }: Props) {
  const cLevel = agent.clearance; // "L0".."L3"
  const tLevel = agent.trust; // "T0".."T3"
  const borderColor = TRUST_COLORS[tLevel] ?? "#666";
  const fillColor = CLEARANCE_COLORS[cLevel] ?? "#666";

  // Pulse animation on verdict change
  const [pulse, setPulse] = useState(false);
  useEffect(() => {
    if (lastVerdict) {
      setPulse(true);
      const t = setTimeout(() => setPulse(false), 800);
      return () => clearTimeout(t);
    }
  }, [lastVerdict]);

  return (
    <g>
      {/* Pulsing ring */}
      {pulse && (
        <circle
          cx={x} cy={y} r={46}
          fill="none"
          stroke={lastVerdict === "ALLOW" ? "#22c55e" : lastVerdict === "HIDE" ? "#f59e0b" : "#ef4444"}
          strokeWidth={3}
          opacity={0.6}
          className="animate-ping"
        />
      )}

      {/* Dual watermarks: outer ring = trust (integrity), inner fill = clearance (secrecy) */}
      <circle cx={x} cy={y} r={42} fill={fillColor} fillOpacity={0.15}
              stroke={borderColor} strokeWidth={3} />

      {/* Center icon/initials */}
      <circle cx={x} cy={y} r={30} fill={active ? fillColor : "#1e293b"}
              fillOpacity={0.6} stroke={borderColor} strokeWidth={1.5} />

      <text x={x} y={y + 5} textAnchor="middle" fill="#f8fafc"
            fontSize={13} fontWeight={700} fontFamily="monospace">
        {agent.agent_id.slice(0, 2).toUpperCase()}
      </text>

      {/* Agent name */}
      <text x={x} y={y + 60} textAnchor="middle" fill="#cbd5e1"
            fontSize={12} fontWeight={500}>
        {agent.agent_id}
      </text>

      {/* Role */}
      <text x={x} y={y + 76} textAnchor="middle" fill="#64748b"
            fontSize={10}>
        {agent.role}
      </text>
    </g>
  );
}
