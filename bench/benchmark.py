"""
TrustMem 核心模块吞吐量微基准（供 scripts/generate_figures.py fig3 读取）
======================================================================
真实计时，写 ``bench/benchmarks.json``。每次重跑覆盖旧值，绘图脚本只读不写。

用法:
    python -m bench.benchmark
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from core.crypto import abe_setup, abe_encrypt, abe_decrypt, abe_issue_key, check_policy
from core.labels import Clearance, Trust, Layer, MemoryType, WriteOp
from core.merkle import MerkleStore, AuditEvent, EventType, MerkleTree
from core.pdp import PDP
from core.session import SessionStore
from scenarios.soc_setup import build_agents, build_topology, mk_mem

OUT = Path(__file__).resolve().parent / "benchmarks.json"


def _ops_per_sec(n: int, fn) -> float:
    t0 = time.perf_counter()
    for _ in range(n):
        fn()
    dt = time.perf_counter() - t0
    return n / dt if dt > 0 else float("inf")


def _us_per_op(n: int, fn) -> float:
    t0 = time.perf_counter()
    for _ in range(n):
        fn()
    dt = time.perf_counter() - t0
    return (dt / n) * 1e6 if n else float("inf")


def main() -> None:
    agents = build_agents()
    topo = build_topology()
    pdp = PDP(topo)
    store = SessionStore()
    analyst = agents["analyst"]
    sess = store.get_or_start("bench", analyst, "INC-BENCH")
    m_intel = mk_mem("bm_intel", Clearance.L0_PUBLIC, Trust.T1_LOW,
                     Layer.CONCLUSION, "intel", MemoryType.INTEL)
    m_log = mk_mem("bm_log", Clearance.L2_SENSITIVE, Trust.T3_HIGH,
                   Layer.CONCLUSION, "log")

    can_read = _ops_per_sec(20000, lambda: pdp.can_read(analyst, m_log, sess))
    can_write = _ops_per_sec(20000, lambda: pdp.can_write(
        analyst, sess, Clearance.L2_SENSITIVE, Layer.CONCLUSION,
        [m_log, m_intel], WriteOp.INFER, output_text="结论"))

    ms = MerkleStore()
    def _log():
        ms.log(AuditEvent(event_id=f"ev-{time.perf_counter_ns()}",
                          event_type=EventType.READ_ALLOW,
                          subject="analyst", object="obj", session_id="s"))
    merkle_log = _ops_per_sec(5000, _log)

    tree = MerkleTree([bytes([i]) for i in range(256)])
    merkle_proof_us = _us_per_op(5000, lambda: tree.proof(7))

    mk, pk = abe_setup()
    attr_key = abe_issue_key(mk, "analyst", ["clearance_2", "task_bench"])
    ct = abe_encrypt(pk, "secret", "clearance_2 and task_bench")
    abe_us = _us_per_op(500, lambda: abe_decrypt(attr_key, ct))

    policy_check = _ops_per_sec(20000,
                                lambda: check_policy("clearance_2 and task_bench",
                                                     ["clearance_2", "task_bench"]))

    data = {
        "can_read_ops_s": round(can_read),
        "can_write_ops_s": round(can_write),
        "merkle_log_ops_s": round(merkle_log),
        "merkle_proof_us": round(merkle_proof_us),
        "abe_enc_dec_us": round(abe_us),
        "policy_check_ops_s": round(policy_check),
        # 设计目标（答辩达标线，非实测；与实测并列展示，供 fig3 对照）
        "targets": {
            "can_read_ops_s": 3000,
            "can_write_ops_s": 2000,
            "merkle_log_ops_s": 10000,
            "merkle_proof_us": 5000,
            "abe_enc_dec_us": 100,
            "policy_check_ops_s": 10000,
        },
    }
    OUT.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[OK] 已写 {OUT}")
    print(json.dumps(data, ensure_ascii=False))


if __name__ == "__main__":
    main()
