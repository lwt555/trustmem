"""业务数据种子 —— 向本地 SQLite 灌入 SOC 三场景对应的结构化演示数据。

这些是演示数据（非真实生产资产/日志/情报），但结构与字段是真实的，
用于让 asset_query / log_query / intel_fetch 走真实 SQLite 查询而非 STUB。
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from .models import Base, Asset, SiemLog, ThreatIntel


def _utc(hours_ago: float = 0.0) -> datetime:
    return datetime.now(timezone.utc) - timedelta(hours=hours_ago)


ASSETS = [
    dict(asset_id="DC-01", hostname="dc01.internal", ip="192.168.1.10",
         os="Windows Server 2022", owner="IT", env="prod",
         sensitivity=3, trust=3, tags=["domain-controller", "critical"]),
    dict(asset_id="WS-105", hostname="workstation-105.internal", ip="192.168.1.105",
         os="Windows 11", owner="finance", env="internal",
         sensitivity=2, trust=2, tags=["workstation", "domain-joined"]),
    dict(asset_id="SRV-WEB-01", hostname="web01.dmz", ip="10.0.0.11",
         os="Ubuntu 22.04", owner="ops", env="dmz",
         sensitivity=2, trust=2, tags=["web", "public-facing"]),
    dict(asset_id="SRV-DB-01", hostname="db01.internal", ip="192.168.1.20",
         os="CentOS 8", owner="ops", env="prod",
         sensitivity=3, trust=3, tags=["database", "sensitive"]),
    dict(asset_id="FW-EDGE-01", hostname="fw-edge.internal", ip="192.168.1.1",
         os="FortiOS", owner="net", env="prod",
         sensitivity=3, trust=3, tags=["firewall", "edge"]),
    dict(asset_id="SIEM-01", hostname="siem01.internal", ip="192.168.1.30",
         os="Linux", owner="sec", env="prod",
         sensitivity=3, trust=3, tags=["siem", "audit"]),
]

SIEM_LOGS = [
    # 场景2：外部 198.51.100.7 对 192.168.1.105 的失败登录 → 成功登录 → lsass 注入
    dict(ts=_utc(2.5), source_ip="198.51.100.7", dest_ip="192.168.1.105",
         hostname="workstation-105.internal", event_type="login_failed",
         user="domain\\admin", outcome="failure",
         raw="EventID 4625: failed logon, 3 attempts, source 198.51.100.7"),
    dict(ts=_utc(2.2), source_ip="198.51.100.7", dest_ip="192.168.1.105",
         hostname="workstation-105.internal", event_type="login_success",
         user="domain\\admin", outcome="success",
         raw="EventID 4624: successful logon type 10, source 198.51.100.7"),
    dict(ts=_utc(2.0), source_ip="192.168.1.105", dest_ip="192.168.1.10",
         hostname="workstation-105.internal", event_type="process_inject",
         user="SYSTEM", outcome="success",
         raw="Sysmon 10: lsass.exe process injection from 192.168.1.105"),
    # 场景1：203.0.113.42 对内网网段端口扫描
    dict(ts=_utc(24.0), source_ip="203.0.113.42", dest_ip="192.168.1.0/24",
         hostname="-", event_type="port_scan",
         user="-", outcome="success",
         raw="Firewall log: port scan from 203.0.113.42 to 192.168.1.0/24, 3 days"),
    # 场景3：内部告警——可疑进程
    dict(ts=_utc(1.0), source_ip="192.168.1.105", dest_ip="10.0.0.11",
         hostname="workstation-105.internal", event_type="suspicious_process",
         user="domain\\admin", outcome="success",
         raw="EDR: powershell.exe spawning from svchost, downloading payload"),
]

THREAT_INTEL = [
    dict(ioc_type="ip", ioc_value="203.0.113.42", source="OSINT-feed",
         confidence=1, ttp="T1595", description="已知 APT 组织 'DeepPanda' 的扫描节点，活跃端口扫描"),
    dict(ioc_type="ip", ioc_value="198.51.100.7", source="OSINT-feed",
         confidence=1, ttp="T1078", description="与 DeepPanda 关联的 C2 / 暴力破解源"),
    dict(ioc_type="domain", ioc_value="evil-c2.example.com", source="OSINT-feed",
         confidence=1, ttp="T1102", description="DeepPanda 命令与控制回连域名"),
    dict(ioc_type="cve", ioc_value="CVE-2026-9999", source="vendor-advisory",
         confidence=2, ttp="T1190", description="内部系统高危漏洞，可被远程利用"),
    dict(ioc_type="hash", ioc_value="e3b0c44298fc1c149afbf4c8996fb924",
         source="internal-sandbox", confidence=2, ttp="T1059",
         description="投放器样本 SHA256，与 CVE-2026-9999 利用链关联"),
]


def seed(db: Session, reset: bool = False) -> dict[str, int]:
    """建表并灌入演示数据。返回各表写入行数。"""
    Base.metadata.create_all(bind=db.get_bind())

    if reset:
        for model in (ThreatIntel, SiemLog, Asset):
            db.query(model).delete()

    counts: dict[str, int] = {}

    if db.query(Asset).count() == 0:
        for a in ASSETS:
            db.add(Asset(**a))
        counts["assets"] = len(ASSETS)
    else:
        counts["assets"] = 0

    if db.query(SiemLog).count() == 0:
        for l in SIEM_LOGS:
            db.add(SiemLog(**l))
        counts["siem_logs"] = len(SIEM_LOGS)
    else:
        counts["siem_logs"] = 0

    if db.query(ThreatIntel).count() == 0:
        for t in THREAT_INTEL:
            db.add(ThreatIntel(**t))
        counts["threat_intel"] = len(THREAT_INTEL)
    else:
        counts["threat_intel"] = 0

    db.commit()
    return counts
