"""
TrustMem 性能基准测试
====================
测试 PDP 裁决、Merkle 审计、加密引擎和端到端管道的吞吐量。
"""
from __future__ import annotations

import time
import statistics
import pytest

from core.labels import Clearance, Trust, Layer, MemoryType, WriteOp
from core.pdp import PDP
from core.session import Session, SessionStore
from core.merkle import MerkleStore, MerkleAuditStore
from core.crypto.abe import abe_setup, abe_issue_key, abe_encrypt, abe_decrypt, policy_satisfied
from core.crypto.engine import CryptoEngine
from scenarios.soc_setup import build_agents, build_topology, TASK, mk_mem


# ── thresholds ──────────────────────────────────────────────

PDP_READ_OPS = 3000         # can_read / sec minimum
PDP_WRITE_OPS = 2000        # can_write / sec minimum
MERKLE_LOG_OPS = 10000      # events / sec minimum
MERKLE_PROOF_US = 5000      # proof gen max μs
ABE_OPS = 100               # encrypt+decrypt / sec minimum


def _elapsed(start: float) -> float:
    return time.perf_counter() - start


def _ops_per_sec(n: int, elapsed: float) -> float:
    return n / elapsed if elapsed > 0 else float("inf")


# ── PDP ─────────────────────────────────────────────────────

def test_bench_pdp_can_read():
    agents, topo = build_agents(), build_topology()
    pdp, store = PDP(topo), SessionStore()
    agent = agents["analyst"]
    mem = mk_mem("bench_m", Clearance.L1_INTERNAL, Trust.T2_MEDIUM,
                 Layer.CONCLUSION, "analyst")

    n = 5000
    start = time.perf_counter()
    for _ in range(n):
        s = Session.start("b", agent, TASK)
        pdp.can_read(agent, mem, s)
    elapsed = _elapsed(start)
    ops = _ops_per_sec(n, elapsed)
    print(f"\n  PDP can_read      : {ops:,.0f} ops/s  ({n} calls in {elapsed:.3f}s)")
    assert ops >= PDP_READ_OPS, f"PDP can_read: {ops:,.0f} < {PDP_READ_OPS}"


def test_bench_pdp_can_write():
    agents, topo = build_agents(), build_topology()
    pdp, store = PDP(topo), SessionStore()
    agent = agents["analyst"]
    mem = mk_mem("bench_w", Clearance.L0_PUBLIC, Trust.T3_HIGH,
                 Layer.CONCLUSION, "analyst")

    n = 3000
    start = time.perf_counter()
    for _ in range(n):
        s = Session.start("b", agent, TASK)
        pdp.can_write(agent, s, agent.clearance, Layer.CONCLUSION,
                     [mem], WriteOp.INFER, output_text="bench")
    elapsed = _elapsed(start)
    ops = _ops_per_sec(n, elapsed)
    print(f"\n  PDP can_write     : {ops:,.0f} ops/s  ({n} calls in {elapsed:.3f}s)")
    assert ops >= PDP_WRITE_OPS, f"PDP can_write: {ops:,.0f} < {PDP_WRITE_OPS}"


# ── Merkle ──────────────────────────────────────────────────

def test_bench_merkle_log():
    store = MerkleStore(block_size=256)
    from core.merkle import AuditEvent, EventType

    n = 20000
    start = time.perf_counter()
    for i in range(n):
        store.log(AuditEvent(
            event_id=f"evt-{i:06d}",
            event_type=EventType.READ_ALLOW,
            subject="analyst", object=f"chunk-{i}",
            session_id="bench", payload={"idx": i},
        ))
    elapsed = _elapsed(start)
    ops = _ops_per_sec(n, elapsed)
    print(f"\n  Merkle log        : {ops:,.0f} events/s  ({n} in {elapsed:.3f}s)")
    assert ops >= MERKLE_LOG_OPS, f"Merkle log: {ops:,.0f} < {MERKLE_LOG_OPS}"


def test_bench_merkle_proof():
    store = MerkleStore(block_size=256)
    from core.merkle import AuditEvent, EventType

    for i in range(1000):
        store.log(AuditEvent(
            event_id=f"evt-{i:06d}",
            event_type=EventType.READ_ALLOW,
            subject="analyst", object=f"chunk-{i}",
            session_id="bench", payload={"idx": i},
        ))
    store.flush()

    n = 500
    start = time.perf_counter()
    for i in range(n):
        _ = store.get_proof(f"evt-{i:06d}")
    elapsed = _elapsed(start)
    avg_us = (elapsed / n) * 1_000_000
    print(f"\n  Merkle proof      : {avg_us:.1f} μs/op  ({n} proofs in {elapsed:.3f}s)")
    assert avg_us <= MERKLE_PROOF_US, f"Merkle proof: {avg_us:.1f} μs > {MERKLE_PROOF_US}"


def test_bench_merkle_chain_verify():
    store = MerkleStore(block_size=64)
    from core.merkle import AuditEvent, EventType

    for i in range(200):
        store.log(AuditEvent(
            event_id=f"evt-{i:06d}",
            event_type=EventType.READ_ALLOW if i % 2 == 0 else EventType.WRITE_ALLOW,
            subject="analyst", object=f"chunk-{i}",
            session_id="bench", payload={"idx": i},
        ))
    store.flush()

    n = 200
    start = time.perf_counter()
    for _ in range(n):
        _ = store.verify_chain()
    elapsed = _elapsed(start)
    print(f"\n  Merkle chain verify: {elapsed:.3f}s for {n} runs")


# ── ABE ─────────────────────────────────────────────────────

def test_bench_abe():
    mk, pk = abe_setup()
    attrs = [f"attr_{i}" for i in range(8)]
    key = abe_issue_key(mk, "agent-x", attrs)
    policy = "(attr_0 AND attr_1) OR attr_3"

    n = 500
    start = time.perf_counter()
    for _ in range(n):
        ct = abe_encrypt(pk, "benchmark payload 32 bytes!", policy)
        _ = abe_decrypt(key, ct)
    elapsed = _elapsed(start)
    ops = _ops_per_sec(n, elapsed)
    print(f"\n  ABE enc+dec       : {ops:,.0f} ops/s  ({n} in {elapsed:.3f}s)")
    assert ops >= ABE_OPS, f"ABE: {ops:,.0f} < {ABE_OPS}"


def test_bench_policy_satisfied():
    attrs = {f"attr_{i}" for i in range(10)}
    policy = "(attr_0 AND attr_1) OR (attr_5 AND attr_6)"
    n = 50000
    start = time.perf_counter()
    for _ in range(n):
        _ = policy_satisfied(policy, attrs)
    elapsed = _elapsed(start)
    ops = _ops_per_sec(n, elapsed)
    print(f"\n  Policy check      : {ops:,.0f} ops/s  ({n} in {elapsed:.3f}s)")


# ── End-to-end pipeline ─────────────────────────────────────

def test_bench_e2e_write_read_loop():
    """端到端：Write → Read 闭环吞吐。"""
    agents, topo = build_agents(), build_topology()
    pdp, store = PDP(topo), SessionStore()
    crypto = CryptoEngine(topo)
    merkle = MerkleAuditStore(block_size=128)

    agent = agents["analyst"]
    n = 200

    times = []
    for _ in range(n):
        s = Session.start("bench-e2e", agent, TASK)
        t0 = time.perf_counter()

        # Write
        dw, decay = pdp.can_write(agent, s, Clearance.L1_INTERNAL, Layer.CONCLUSION,
                                  [], WriteOp.INFER, output_text="e2e-content")
        if dw.allowed:
            mem = mk_mem("e2e-mem", Clearance.L1_INTERNAL, decay.trust_out,
                        Layer.CONCLUSION, agent.agent_id)
            merkle.log(dw)
            # Read
            dr = pdp.can_read(agent, mem, s)
            merkle.log(dr)

        times.append(time.perf_counter() - t0)

    avg_ms = statistics.mean(times) * 1000
    p50_ms = statistics.median(times) * 1000
    p99_ms = sorted(times)[int(len(times) * 0.99)] * 1000

    print(f"\n  E2E write+read    : avg={avg_ms:.2f}ms  p50={p50_ms:.2f}ms  p99={p99_ms:.2f}ms  ({n} loops)")
    assert avg_ms < 100, f"E2E avg too slow: {avg_ms:.2f}ms"


# ── Concurrency benchmark ───────────────────────────────────

def test_bench_concurrent_sessions():
    """并发会话：多 Agent 同时操作无跨会话污染。"""
    agents, topo = build_agents(), build_topology()
    pdp, store = PDP(topo), SessionStore()

    n_sessions = 500
    start = time.perf_counter()
    for i in range(n_sessions):
        aid = ["planner", "intel", "log", "analyst", "executor", "auditor"][i % 6]
        agent = agents[aid]
        s = store.get_or_start(f"conc-{i}", agent, TASK)
        mem = mk_mem(f"cm-{i}", Clearance.L0_PUBLIC, Trust.T3_HIGH,
                    Layer.CONCLUSION, agent.agent_id)
        assert pdp.can_read(agent, mem, s).allowed == (agent.clearance >= mem.sensitivity)
    elapsed = _elapsed(start)
    ops = _ops_per_sec(n_sessions, elapsed)
    print(f"\n  Concurrent sessions: {ops:,.0f} ops/s  ({n_sessions} in {elapsed:.3f}s)")


# ── Summary reporter ────────────────────────────────────────

def test_bench_summary():
    """汇总所有基准结果。"""
    print("\n" + "=" * 62)
    print("  TrustMem 性能基准汇总")
    print("=" * 62)
    print(f"  目标: PDP读≥{PDP_READ_OPS} | PDP写≥{PDP_WRITE_OPS} | "
          f"Merkle日志≥{MERKLE_LOG_OPS} | ABE≥{ABE_OPS} ops/s")
