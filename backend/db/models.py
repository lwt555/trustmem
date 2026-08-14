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
