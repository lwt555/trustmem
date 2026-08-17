"""军事场景（joint）数据种子。

向本地 SQLite 灌入联合态势研判场景的结构化演示数据：
  - sensor_feed.json → sensor_reports（传感器直报，trust 由 verified 推导）
  - relay_feed.json  → relay_intel（只灌合法转报，毒转报 M237 不入库）
  - netprobe.json    → siem_logs（网络探针日志，复用既有表）

幂等：每类数据插入前检查是否已存在，重复调用不产生重复行。
"""
from __future__ import annotations

import json
import os
from datetime import datetime

from sqlalchemy.orm import Session

from backend.db.models import Base, SensorReport, RelayIntel, SiemLog, trust_from_verified


_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")


def _load(name: str) -> list[dict]:
    path = os.path.join(_DATA_DIR, name)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _parse_ts(s: str) -> datetime:
    return datetime.fromisoformat(s)


def seed_joint(db: Session, reset: bool = False) -> dict[str, int]:
    """建表并灌入军事场景数据。返回各表写入行数（重复调用各项为 0）。"""
    Base.metadata.create_all(bind=db.get_bind())

    if reset:
        for model in (SensorReport, RelayIntel):
            db.query(model).delete()

    counts: dict[str, int] = {}

    # 传感器直报：trust 一律经 trust_from_verified 推导，禁止直接读 JSON 的 trust。
    if db.query(SensorReport).count() == 0:
        n = 0
        for item in _load("sensor_feed.json"):
            db.add(SensorReport(
                report_id=item["report_id"],
                ts=_parse_ts(item["ts"]),
                sensor_type=item["sensor_type"],
                sector=item.get("sector", ""),
                payload=item.get("payload", {}),
                signature=item.get("signature", ""),
                verified=item.get("verified", False),
                sensitivity=item.get("sensitivity", 1),
                trust=trust_from_verified(item.get("verified", False)),
            ))
            n += 1
        counts["sensor_reports"] = n
    else:
        counts["sensor_reports"] = 0

    # 跨域转报：只灌合法转报，毒转报（is_attack=True）不入库，由信道模拟器在演示时推送。
    if db.query(RelayIntel).count() == 0:
        n = 0
        for item in _load("relay_feed.json"):
            if item.get("is_attack"):
                continue
            db.add(RelayIntel(
                relay_id=item["relay_id"],
                received_at=_parse_ts(item["received_at"]),
                channel=item.get("channel", ""),
                origin=item.get("origin", ""),
                payload=item.get("payload", ""),
                verified=False,
                trust=1,
                is_attack=False,
            ))
            n += 1
        counts["relay_intel"] = n
    else:
        counts["relay_intel"] = 0

    # 网络探针日志 → 复用既有 siem_logs 表（按 hostname 前缀 NET- 判定是否已灌）。
    if db.query(SiemLog).filter(SiemLog.hostname.like("NET-%")).count() == 0:
        n = 0
        for item in _load("netprobe.json"):
            db.add(SiemLog(
                ts=_parse_ts(item["ts"]),
                source_ip=item.get("source_ip", ""),
                dest_ip=item.get("dest_ip", ""),
                hostname=item.get("hostname", ""),
                event_type=item.get("event_type", ""),
                user=item.get("user", ""),
                outcome=item.get("outcome", ""),
                raw=item.get("raw", ""),
                sensitivity=item.get("sensitivity", 1),
                trust=item.get("trust", 2),
            ))
            n += 1
        counts["netprobe"] = n
    else:
        counts["netprobe"] = 0

    db.commit()
    return counts
