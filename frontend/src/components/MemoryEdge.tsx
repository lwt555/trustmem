import { useEffect, useState } from "react";

type Verdict = "ALLOW" | "HIDE" | "DENY";

interface Particle {
  id: number;
  x1: number; y1: number;
  x2: number; y2: number;
  progress: number;
  verdict: Verdict;
}

interface Props {
  fromX: number; fromY: number;
  toX: number; toY: number;
  active: boolean;
  verdict: "ALLOW" | "HIDE" | "DENY" | null;
}

let _particleId = 0;

const DURATION = 1200; // ms（ALLOW 全程 / DENY 单程来回）
const HALF = DURATION / 2;
const HIDE_HOLD = 1400; // HIDE 粒子到达句柄后停留时长

/**
 * F-30 粒子三态：
 *   ALLOW — 实心粒子全程流过（0 → 1）
 *   HIDE  — 半透明粒子走到中点挂在 #var# 句柄上（0 → 0.5 后停留）
 *   DENY  — 红色粒子撞墙回弹（0 → 0.5 → 0）
 */
export default function MemoryEdge({ fromX, fromY, toX, toY, active, verdict }: Props) {
  const [particles, setParticles] = useState<Particle[]>([]);

  useEffect(() => {
    if (!active || !verdict) return;

    const v = verdict as Verdict;
    const p: Particle = {
      id: ++_particleId,
      x1: fromX, y1: fromY, x2: toX, y2: toY,
      progress: 0,
      verdict: v,
    };
    setParticles((prev) => [...prev, p]);

    const start = performance.now();
    const totalLife = v === "HIDE" ? HALF + HIDE_HOLD : DURATION;

    const tick = (now: number) => {
      const elapsed = now - start;
      const prog = progressAt(v, elapsed);
      setParticles((prev) =>
        prev.map((pp) => (pp.id === p.id ? { ...pp, progress: prog } : pp))
      );
      if (elapsed < totalLife) {
        requestAnimationFrame(tick);
      } else {
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
        const color = p.verdict === "ALLOW" ? "#22c55e"
                    : p.verdict === "HIDE" ? "#f59e0b" : "#ef4444";
        const opacity = p.verdict === "HIDE" ? 0.4 : 1;

        // HIDE：到达句柄后渲染一个半透明 #var# 占位框
        const hung = p.verdict === "HIDE" && p.progress >= 0.49;
        // DENY：撞墙点闪一下红色墙
        const atWall = p.verdict === "DENY" && p.progress >= 0.48 && p.progress <= 0.52;
        const wallX = p.x1 + (p.x2 - p.x1) * 0.5;
        const wallY = p.y1 + (p.y2 - p.y1) * 0.5;

        return (
          <g key={p.id}>
            {hung && (
              <rect x={cx - 7} y={cy - 7} width={14} height={14} rx={3}
                    fill="none" stroke="#f59e0b" strokeWidth={1} strokeDasharray="3 2"
                    opacity={0.7} />
            )}
            {atWall && (
              <line x1={wallX - 5} y1={wallY - 8} x2={wallX - 5} y2={wallY + 8}
                    stroke="#ef4444" strokeWidth={2.5} opacity={0.9} />
            )}
            <circle cx={cx} cy={cy} r={5}
                    fill={color} fillOpacity={opacity} />
          </g>
        );
      })}
    </g>
  );
}

function progressAt(verdict: Verdict, elapsed: number): number {
  if (verdict === "DENY") {
    // 0 → 0.5 前进，0.5 → 0 回弹
    if (elapsed <= HALF) return (elapsed / HALF) * 0.5;
    return 0.5 - ((elapsed - HALF) / HALF) * 0.5;
  }
  if (verdict === "HIDE") {
    // 走到中点后挂住（progress 固定在 0.5）
    return Math.min(elapsed / HALF, 1) * 0.5;
  }
  // ALLOW 全程流过
  return Math.min(elapsed / DURATION, 1);
}
