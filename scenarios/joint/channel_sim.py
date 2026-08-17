"""军事场景（joint）跨域协同信道模拟器。

数据是预置的，抵达是事件驱动的。合法转报与毒转报走同一条信道、同一个 receive_relay
函数、同一套打标动作，唯一区别是内容。

铁律：receive_relay 及其处理链不得依据 is_attack、relay_id 或正文内容分支——
差别只在调用方传入哪条记录。选择哪条记录推送是 CLI（信道外的"发送方"）的事，
不在接收/处理路径上。
"""
from __future__ import annotations

import argparse
import json
import os
import time
from datetime import datetime

from core.labels import Clearance, Layer, MemoryType, WriteOp
from core.pdp import PDP
from core.session import Session
from core.pipeline import WritePipeline
from core.crypto.engine import CryptoEngine

from backend.db.database import get_db
from backend.db.models import RelayIntel
from backend.db.store import MemoryStore, AuditStore, ProvenanceStore

from scenarios.joint.setup import build_topology, build_agents, JOINT_TASK

_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")


def _parse_ts(s: str) -> datetime:
    return datetime.fromisoformat(s)


def _load(name: str) -> list[dict]:
    with open(os.path.join(_DATA_DIR, name), "r", encoding="utf-8") as f:
        return json.load(f)


def _ingest_as_memory(record: dict) -> None:
    """external 智能体经写入管线把转报登记为共享记忆（trust 一律 T1）。

    原始转报是信道抵达的裸数据，尚未绑定任何任务，故 scope=None（不做任务区间
    裁剪）；登记后的记忆 task_binding 落在 JOINT_TASK，供后续任务按需读取。
    """
    topo = build_topology()
    crypto = CryptoEngine(topo)
    pdp = PDP(topo)
    agents = build_agents()
    external = agents["external"]
    crypto.register_agent(external)

    db = get_db()
    try:
        mem_store = MemoryStore(db)
        audit = AuditStore(db)
        prov = ProvenanceStore(db)
        wp = WritePipeline(pdp, crypto, mem_store, audit, prov)
        sess = Session.start(f"relay-{record['relay_id']}", external, JOINT_TASK)
        res = wp.write(
            agent=external, session=sess,
            content=record.get("payload", ""),
            target_sensitivity=Clearance.L1_INTERNAL,
            target_layer=Layer.CONCLUSION,
            memory_type=MemoryType.INTEL,
            op=WriteOp.VERBATIM,
            input_texts=[record.get("payload", "")],
            scope=None,
        )
        if not res.allowed:
            raise RuntimeError(f"转报登记被拒: {res.denied_by}")
    finally:
        db.close()


def receive_relay(record: dict) -> str:
    """跨域信道唯一接收入口：写 relay_intel 表 → external 登记为共享记忆。

    对传入记录不做任何内容/来源判断，合法转报与毒转报走完全相同的路径，trust
    一律 T1。幂等：relay_id 已存在则直接返回，不重复入库。
    """
    relay_id = record["relay_id"]
    db = get_db()
    try:
        if db.query(RelayIntel).filter_by(relay_id=relay_id).first():
            return relay_id
        db.add(RelayIntel(
            relay_id=relay_id,
            received_at=_parse_ts(record["received_at"]),
            channel=record.get("channel", ""),
            origin=record.get("origin", ""),
            payload=record.get("payload", ""),
            verified=False,
            trust=1,
        ))
        db.commit()
    finally:
        db.close()

    _ingest_as_memory(record)
    return relay_id


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(description="跨域协同信道模拟器")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--timeline", action="store_true",
                   help="按时间线逐条推送合法转报")
    g.add_argument("--attack", action="store_true",
                   help="推送毒转报")
    p.add_argument("--interval", type=float, default=3.0,
                   help="时间线推送间隔（秒，0 表示不等待）")
    args = p.parse_args(argv)

    records = _load("relay_feed.json")
    if args.timeline:
        for item in [r for r in records if not r.get("is_attack")]:
            rid = receive_relay(item)
            print(f"[{rid}] 已入库 (origin={item.get('origin')})")
            if args.interval > 0:
                time.sleep(args.interval)
    else:
        item = next(r for r in records if r.get("is_attack"))
        rid = receive_relay(item)
        print(f"[{rid}] 已入库 (origin={item.get('origin')})")


if __name__ == "__main__":
    main()
