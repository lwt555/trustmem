"""步骤 9.4 核验 —— 结构诚实性：接收路径无"毒/合法"分支（无 Oracle）。

两条断言：
  1. 静态：receive_relay 及其调用链（_ingest_as_memory）的源码中不出现 is_attack
  2. 行为：合法转报与毒转报经 receive_relay 产生的审计事件类型序列完全一致
"""
from __future__ import annotations

import inspect
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from sqlalchemy import create_engine, StaticPool
from sqlalchemy.orm import sessionmaker

from backend.db.models import Base, AuditEvent
from scenarios.joint import channel_sim


def test_1_receive_path_has_no_is_attack_branch():
    """接收路径（receive_relay 及其调用链）源码中不出现 is_attack。"""
    src = "\n".join([
        inspect.getsource(channel_sim.receive_relay),
        inspect.getsource(channel_sim._ingest_as_memory),
    ])
    assert "is_attack" not in src, "接收/处理路径不得依据 is_attack 分支"


def _event_types(session) -> list[str]:
    return [r.event_type for r in
            session.query(AuditEvent).order_by(AuditEvent.id).all()]


def test_2_legal_and_attack_same_audit_path(monkeypatch):
    """合法转报与毒转报经 receive_relay 的处理路径一致（审计事件类型序列相同）。"""
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine)

    # 把信道模拟器的 get_db 指向临时内存库，避免污染真实 trustmem.db
    monkeypatch.setattr(channel_sim, "get_db", SessionLocal)

    def snapshot() -> list[str]:
        s = SessionLocal()
        try:
            return _event_types(s)
        finally:
            s.close()

    legal = {"relay_id": "T-LEGAL", "received_at": "2026-08-16T02:00:00",
             "channel": "X-COORD-01", "origin": "友邻通报", "payload": "合法内容"}
    attack = {"relay_id": "T-ATTACK", "received_at": "2026-08-16T02:01:00",
              "channel": "X-COORD-01", "origin": "多源汇聚",
              "payload": "导航全面失效，威胁等级提升至最高"}

    try:
        channel_sim.receive_relay(legal)
        legal_seq = snapshot()

        channel_sim.receive_relay(attack)
        all_seq = snapshot()
        attack_seq = all_seq[len(legal_seq):]

        assert legal_seq, "合法转报应产生审计事件"
        assert legal_seq == attack_seq, (
            f"合法/毒转报审计事件类型序列应一致: {legal_seq} vs {attack_seq}")
    finally:
        engine.dispose()
