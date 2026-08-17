"""军事场景（joint）安全语料写入 —— 经既有 WritePipeline 以 security 身份写共享记忆。

secure_corpus.json 的 3 条高密内部安全研判，必须经 WritePipeline 落库，不得直接插
memory_chunks 表：直接插表的记忆没有密文、没有审计事件、没有写入签名，门②
（先判决后解密）演示时切到密码机会当场露馅。

写入可信度由 compute_trust 推导（security 固有 T3 + VERBATIM δ=0 → T3），不直接
读 JSON 的 trust 字段。input_texts 提供原文使 VERBATIM 的字面重叠率校验通过。
"""
from __future__ import annotations

import json
import os

from sqlalchemy.orm import Session as SASession

from core.labels import Clearance, Layer, MemoryType, WriteOp
from core.pdp import PDP
from core.session import Session
from core.pipeline import WritePipeline
from core.crypto.engine import CryptoEngine

from backend.db.database import get_db
from backend.db.models import Base, MemoryChunk
from backend.db.store import MemoryStore, AuditStore, ProvenanceStore

from scenarios.joint.setup import build_topology, build_agents, load_task, JOINT_TASK

_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
_SESSION_ID = "seed-secure-corpus"


def _load(name: str) -> list[dict]:
    with open(os.path.join(_DATA_DIR, name), "r", encoding="utf-8") as f:
        return json.load(f)


def seed_memory(db: SASession | None = None, reset: bool = False) -> dict[str, str]:
    """以 security 身份把 secure_corpus.json 写入共享记忆。返回 {chunk_id: 标题}。

    幂等：memory_chunks 中已存在 security 为 JOINT_TASK 写入的记忆时跳过，重复调用
    返回空字典。
    """
    db = db or get_db()
    Base.metadata.create_all(bind=db.get_bind())

    if reset:
        for row in db.query(MemoryChunk).filter_by(
                owner_agent="security", task_binding=JOINT_TASK).all():
            db.delete(row)
        db.commit()

    if db.query(MemoryChunk).filter_by(
            owner_agent="security", task_binding=JOINT_TASK).count():
        return {}

    topo = build_topology()
    crypto = CryptoEngine(topo)
    pdp = PDP(topo)
    agents = build_agents()
    security = agents["security"]
    crypto.register_agent(security)

    mem_store = MemoryStore(db)
    audit = AuditStore(db)
    prov = ProvenanceStore(db)
    wp = WritePipeline(pdp, crypto, mem_store, audit, prov)

    sess = Session.start(_SESSION_ID, security, JOINT_TASK)
    scope = load_task("JOINT-2026-RISKLEVEL").scope

    written: dict[str, str] = {}
    for item in _load("secure_corpus.json"):
        res = wp.write(
            agent=security, session=sess,
            content=item["content"],
            target_sensitivity=Clearance.L3_SECRET,
            target_layer=Layer.CONCLUSION,
            memory_type=MemoryType.SEMANTIC,
            op=WriteOp.VERBATIM,
            input_texts=[item["content"]],
            scope=scope,
        )
        if not res.allowed:
            raise RuntimeError(f"安全语料写入被拒: {res.denied_by}")
        written[res.chunk_id] = item["title"]

    return written
