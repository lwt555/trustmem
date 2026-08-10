import { useEffect, useState } from "react";

interface Particle {
  id: number;
  x1: number; y1: number;
  x2: number; y2: number;
  progress: number;
  verdict: "ALLOW" | "HIDE" | "DENY";
  active: boolean;
}

interface Props {
  fromX: number; fromY: number;
  toX: number; toY: number;
  active: boolean;
  verdict: "ALLOW" | "HIDE" | "DENY" | null;
}

let _particleId = 0;

export default function MemoryEdge({ fromX, fromY, toX, toY, active, verdict }: Props) {
  const [particles, setParticles] = useState<Particle[]>([]);

  useEffect(() => {
    if (!active || !verdict) return;

    const p: Particle = {
      id: ++_particleId,
      x1: fromX, y1: fromY, x2: toX, y2: toY,
      progress: 0,
      verdict,
      active: true,
    };
    setParticles((prev) => [...prev, p]);

    const start = performance.now();
    const duration = 1200; // ms

    const tick = (now: number) => {
      const elapsed = now - start;
      const prog = Math.min(elapsed / duration, 1);
      setParticles((prev) =>
        prev.map((pp) => (pp.id === p.id ? { ...pp, progress: prog } : pp))
      );
      if (prog < 1) {
        requestAnimationFrame(tick);
      } else {
        // Remove after animation completes
        setParticles((prev) => prev.filter((pp) => pp.id !== p.id));
      }
    };
    requestAnimationFrame(tick);
  }, [active, verdict, fromX, fromY, toX, toY]);

  return (
    <g>
      {/* Edge line */}
      <line x1={fromX} y1={fromY} x2={toX} y2={toY}
            stroke="#334155" strokeWidth={1.5} strokeDasharray="6 3" />

      {/* Particles */}
      {particles.map((p) => {
        const cx = p.x1 + (p.x2 - p.x1) * p.progress;
        const cy = p.y1 + (p.y2 - p.y1) * p.progress;
        const opacity = p.verdict === "HIDE" ? 0.4 : p.verdict === "DENY" ? 0.9 : 1;
        const color = p.verdict === "ALLOW" ? "#22c55e"
                    : p.verdict === "HIDE" ? "#f59e0b" : "#ef4444";
        return (
          <circle key={p.id} cx={cx} cy={cy} r={5}
                  fill={color} fillOpacity={opacity} />
        );
      })}
    </g>
  );
}
