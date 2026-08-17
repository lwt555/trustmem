"""SQLAlchemy ORM models for TrustMem persistence."""
from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class MemoryChunk(Base):
    __tablename__ = "memory_chunks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    chunk_id = Column(String(64), unique=True, nullable=False, index=True)
    sensitivity = Column(Integer, nullable=False)          # Clearance int
    provenance_trust = Column(Integer, nullable=False)     # Trust int
    layer = Column(String(4), nullable=False)              # D/C/R
    memory_type = Column(String(20), nullable=False)       # semantic/episodic/...
    owner_agent = Column(String(32), nullable=False, index=True)
    task_binding = Column(String(64), nullable=False, index=True)
    collab_group = Column(JSON, default=list)               # list[str]
    provenance_chain = Column(JSON, default=list)           # list[str] chunk_ids
    lifecycle = Column(String(12), default="active")
    epoch = Column(Integer, default=1)
    declassified = Column(Boolean, default=False)
    derived_from_consult = Column(Boolean, default=False)   # F-29：CONSULT 派生写回标记
    content_encrypted = Column(Text, default="")            # placeholder for CP-ABE ciphertext
    ttl_end = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self) -> dict:
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class SessionRecord(Base):
    __tablename__ = "session_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(64), nullable=False, index=True)
    agent_id = Column(String(32), nullable=False, index=True)
    task_id = Column(String(64), nullable=False)
    t_eff = Column(Integer, nullable=False)
    t_intrinsic = Column(Integer, nullable=False)
    is_active = Column(Boolean, default=True)
    consulted = Column(JSON, default=list)   # list[str] chunk_ids
    hitl_confirmations = Column(JSON, default=list)
    created_at = Column(DateTime, default=datetime.utcnow)


class ReadRecord(Base):
    __tablename__ = "read_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(64), nullable=False, index=True)
    agent_id = Column(String(32), nullable=False)
    chunk_id = Column(String(64), nullable=False, index=True)
    trust = Column(Integer, nullable=False)
    t_eff_before = Column(Integer, nullable=False)
    t_eff_after = Column(Integer, nullable=False)
    read_at = Column(DateTime, default=datetime.utcnow)


class AuditEvent(Base):
    """13类事件锚定 —— Merkle commit 前的载体。"""
    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_type = Column(String(32), nullable=False, index=True)
    agent_id = Column(String(32), nullable=False)
    chunk_id = Column(String(64), nullable=True)
    decision = Column(String(16), nullable=False)     # ALLOW/HIDE/CONFIRM/DENY
    denied_by = Column(String(32), nullable=True)
    side_effect = Column(String(256), nullable=True)
    checks_detail = Column(JSON, default=list)        # list of Check dicts
    merkle_root = Column(String(128), nullable=True)  # placeholder for Merkle
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class ProvenanceLink(Base):
    """溯源链边：哪条记忆在写哪条记忆时被引用。"""
    __tablename__ = "provenance_links"

    id = Column(Integer, primary_key=True, autoincrement=True)
    source_chunk_id = Column(String(64), nullable=False, index=True)
    target_chunk_id = Column(String(64), nullable=False, index=True)
    op = Column(String(16), nullable=False)
    op_effective = Column(String(16), nullable=False)
    t_inputs = Column(Integer, nullable=False)
    t_agent = Column(Integer, nullable=False)
    delta = Column(Integer, nullable=False)
    trust_out = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


# ──────────────────────────────────────────────────────────────
# 业务数据表 —— SOC 工具的真实数据源（本地方便演示，接 SQLite）
# ──────────────────────────────────────────────────────────────

class Asset(Base):
    """资产台账：内网主机 / 服务器 / 网络设备的清单。"""
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    asset_id = Column(String(64), unique=True, nullable=False, index=True)
    hostname = Column(String(128), nullable=False)
    ip = Column(String(64), nullable=False, index=True)
    os = Column(String(64), default="")
    owner = Column(String(64), default="")
    env = Column(String(32), default="internal")   # internal / dmz / prod
    sensitivity = Column(Integer, nullable=False, default=1)   # Clearance int
    trust = Column(Integer, nullable=False, default=3)         # Trust int
    tags = Column(JSON, default=list)
    created_at = Column(DateTime, default=datetime.utcnow)


class SiemLog(Base):
    """SIEM 日志：内部安全日志平台的原始事件。"""
    __tablename__ = "siem_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ts = Column(DateTime, nullable=False, index=True)
    source_ip = Column(String(64), index=True)
    dest_ip = Column(String(64), index=True)
    hostname = Column(String(128), default="")
    event_type = Column(String(32), nullable=False, index=True)  # login_failed / login_success / process_inject ...
    user = Column(String(64), default="")
    outcome = Column(String(16), default="")                     # success / failure
    raw = Column(Text, default="")
    sensitivity = Column(Integer, nullable=False, default=1)
    trust = Column(Integer, nullable=False, default=3)


class ThreatIntel(Base):
    """威胁情报：外部/内部情报源的结构化 IOC 与 TTP。"""
    __tablename__ = "threat_intel"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ioc_type = Column(String(16), nullable=False, index=True)    # ip / domain / hash / cve / url
    ioc_value = Column(String(256), nullable=False, index=True)
    source = Column(String(128), default="")
    confidence = Column(Integer, nullable=False, default=1)      # Trust int
    ttp = Column(String(128), default="")
    description = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)


# ──────────────────────────────────────────────────────────────
# 军事场景（joint）数据表
# ──────────────────────────────────────────────────────────────

def trust_from_verified(verified: bool) -> int:
    """由 verified 推导 trust：True → 3，False → 2。

    这是"设备验签"从口播变成机制的唯一落点，所有写入路径必须经过它。
    """
    return 3 if verified else 2


class SensorReport(Base):
    """传感器直报 · 输入边界①（雷达 / 频谱装备直报）。"""
    __tablename__ = "sensor_reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    report_id = Column(String(64), unique=True, nullable=False, index=True)  # 如 EW-001 / RAD-001
    ts = Column(DateTime, nullable=False, index=True)
    sensor_type = Column(String(16), nullable=False, index=True)  # spectrum / radar
    sector = Column(String(16), default="")                       # 如 Bravo / Charlie
    payload = Column(JSON, default=dict)                          # 各传感器类型的结构化读数
    signature = Column(String(128), default="")                   # 设备签名串
    verified = Column(Boolean, nullable=False, default=False)     # 验签结果
    sensitivity = Column(Integer, nullable=False, default=1)      # 密级整数值
    # 本字段一律由 verified 推导（True → 3，False → 2），禁止在种子数据或任何业务代码中直接赋值。
    # 这一行是"设备验签"从口播变成机制的唯一落点。所有写入路径必须经过 trust_from_verified()。
    trust = Column(Integer, nullable=False)

    def to_dict(self) -> dict:
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class RelayIntel(Base):
    """跨域协同信道转报 · 输入边界②（外协智能体的外部情报源）。"""
    __tablename__ = "relay_intel"

    id = Column(Integer, primary_key=True, autoincrement=True)
    relay_id = Column(String(64), unique=True, nullable=False, index=True)  # 如 M231
    received_at = Column(DateTime, nullable=False, index=True)
    channel = Column(String(32), default="")                      # 如 X-COORD-01
    origin = Column(String(32), default="")                       # 友邻通报 / 上级下发 / 多源汇聚
    payload = Column(Text, default="")                            # 转报正文
    verified = Column(Boolean, nullable=False, default=False)     # 恒为 False
    trust = Column(Integer, nullable=False, default=1)            # 恒为 1
    # 本字段仅用于演示后的回放标注与统计，严禁出现在任何判定、分支、过滤或裁决路径上。
    # 系统靠标签与裁决拦截攻击，不靠预先知道哪条是攻击。步骤 9 有一条针对本约束的静态检查测试。
    is_attack = Column(Boolean, nullable=False, default=False)

    def to_dict(self) -> dict:
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}
