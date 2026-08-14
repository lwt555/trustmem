"""作战场景内部数据种子 —— 大体量、结构真实、按 APT 杀伤链关联。

这是**内部私有数据的结构真实替身**(非真实生产资产/日志),字段与真实
SIEM / CMDB / TIP 一致,用于让 log_query / asset_query / intel_fetch 走真实
SQLite 查询而非 STUB。答辩口径:内部源用结构真实的演示数据,外部威胁情报接
真实源(ThreatFox 等,见 backend/live_intel.py)。

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
一条完整的 APT 入侵叙事(代号 INC-2026-0731 · 归因 DeepPanda / APT-DP)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  D-3  侦察      203.0.113.42 对 DMZ 网段端口扫描(T1595)
  D-2  初始访问   web01.dmz 的 CVE-2026-63077 被利用,植入 webshell(T1190)
  D-1  凭据窃取   web01 → lsass 转储,横向探测(T1003)
  D-0  横向移动   198.51.100.7 暴力破解 → ws-105 登录成功(T1078)
       提权      ws-105 lsass 注入 → 获取域管 token(T1055 / T1134)
       C2 回连    ws-105 → evil-c2.example.com 心跳(T1102 / T1071)
       数据打包   db01 大量导出 → 尝试外发(T1030 / T1041)
掺入正常业务噪声:补丁分发、备份任务、正常登录、DNS 查询等,信噪比贴近真实。
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from .models import Base, Asset, SiemLog, ThreatIntel

_RND = random.Random(20260731)


def _utc(hours_ago: float = 0.0) -> datetime:
    return datetime.now(timezone.utc) - timedelta(hours=hours_ago)


# ══════════════════════════════════════════════════════════════
# 1. 资产台账(assets)—— 一个中型企业内网,54 台
#    sensitivity: 0=L0 1=L1 2=L2 3=L3   trust: 0..3
# ══════════════════════════════════════════════════════════════
def _build_assets() -> list[dict]:
    A: list[dict] = []

    # ── 核心基础设施(L3 / T3)──
    A += [
        dict(asset_id="DC-01", hostname="dc01.corp.internal", ip="10.10.1.10",
             os="Windows Server 2022", owner="IT-Infra", env="prod",
             sensitivity=3, trust=3, tags=["domain-controller", "critical", "tier0"]),
        dict(asset_id="DC-02", hostname="dc02.corp.internal", ip="10.10.1.11",
             os="Windows Server 2022", owner="IT-Infra", env="prod",
             sensitivity=3, trust=3, tags=["domain-controller", "critical", "tier0"]),
        dict(asset_id="CA-01", hostname="ca01.corp.internal", ip="10.10.1.12",
             os="Windows Server 2019", owner="IT-Infra", env="prod",
             sensitivity=3, trust=3, tags=["pki", "certificate-authority", "tier0"]),
        dict(asset_id="DB-01", hostname="db01.corp.internal", ip="10.10.2.20",
             os="Oracle Linux 8", owner="DBA", env="prod",
             sensitivity=3, trust=3, tags=["database", "oracle", "crown-jewel", "pii"]),
        dict(asset_id="DB-02", hostname="db02.corp.internal", ip="10.10.2.21",
             os="CentOS 8", owner="DBA", env="prod",
             sensitivity=3, trust=3, tags=["database", "postgres", "crown-jewel", "financial"]),
        dict(asset_id="SIEM-01", hostname="siem01.corp.internal", ip="10.10.1.30",
             os="RHEL 9", owner="SecOps", env="prod",
             sensitivity=3, trust=3, tags=["siem", "splunk", "audit", "tier0"]),
        dict(asset_id="VAULT-01", hostname="vault01.corp.internal", ip="10.10.1.31",
             os="RHEL 9", owner="SecOps", env="prod",
             sensitivity=3, trust=3, tags=["secrets", "hashicorp-vault", "tier0"]),
    ]

    # ── 网络与安全设备(L3 / T3)──
    A += [
        dict(asset_id="FW-EDGE-01", hostname="fw-edge01.corp.internal", ip="10.10.0.1",
             os="FortiOS 7.4", owner="NetOps", env="prod",
             sensitivity=3, trust=3, tags=["firewall", "edge", "perimeter"]),
        dict(asset_id="FW-CORE-01", hostname="fw-core01.corp.internal", ip="10.10.0.2",
             os="Palo Alto PAN-OS 11", owner="NetOps", env="prod",
             sensitivity=3, trust=3, tags=["firewall", "core", "segmentation"]),
        dict(asset_id="VPN-01", hostname="vpn01.corp.internal", ip="10.10.0.5",
             os="FortiOS 7.4", owner="NetOps", env="prod",
             sensitivity=2, trust=3, tags=["vpn", "remote-access"]),
        dict(asset_id="PROXY-01", hostname="proxy01.corp.internal", ip="10.10.0.8",
             os="Ubuntu 22.04", owner="NetOps", env="prod",
             sensitivity=2, trust=3, tags=["proxy", "egress", "web-filter"]),
    ]

    # ── DMZ 面向公网(L2 / T2)—— 攻击入口 ──
    A += [
        dict(asset_id="WEB-01", hostname="web01.dmz.corp.internal", ip="172.16.0.11",
             os="Ubuntu 22.04", owner="AppDev", env="dmz",
             sensitivity=2, trust=2, tags=["web", "public-facing", "nginx", "compromised"]),
        dict(asset_id="WEB-02", hostname="web02.dmz.corp.internal", ip="172.16.0.12",
             os="Ubuntu 22.04", owner="AppDev", env="dmz",
             sensitivity=2, trust=2, tags=["web", "public-facing", "nginx"]),
        dict(asset_id="MAIL-01", hostname="mail01.dmz.corp.internal", ip="172.16.0.20",
             os="Ubuntu 22.04", owner="IT-Infra", env="dmz",
             sensitivity=2, trust=2, tags=["mail", "smtp", "public-facing"]),
        dict(asset_id="API-GW-01", hostname="apigw01.dmz.corp.internal", ip="172.16.0.30",
             os="Ubuntu 22.04", owner="AppDev", env="dmz",
             sensitivity=2, trust=2, tags=["api-gateway", "public-facing", "kong"]),
    ]

    # ── 应用服务器(L2 / T2)──
    for i, (aid, name, app) in enumerate([
        ("APP-CRM-01", "crm01", "salesforce-connector"),
        ("APP-ERP-01", "erp01", "sap-app"),
        ("APP-HR-01", "hr01", "workday-connector"),
        ("APP-FILE-01", "fileshare01", "smb-share"),
        ("APP-JUMP-01", "jump01", "bastion"),
    ]):
        A.append(dict(asset_id=aid, hostname=f"{name}.corp.internal",
                      ip=f"10.10.3.{40 + i}", os="Windows Server 2019",
                      owner="AppDev", env="prod",
                      sensitivity=2, trust=2, tags=["app-server", app]))

    # ── 财务/HR 敏感工作站(L2 / T2)—— 横向目标 ──
    for i in range(6):
        A.append(dict(asset_id=f"WS-FIN-{101 + i}",
                      hostname=f"ws-fin-{101 + i}.corp.internal",
                      ip=f"10.10.5.{101 + i}", os="Windows 11",
                      owner="Finance", env="internal",
                      sensitivity=2, trust=2,
                      tags=["workstation", "finance", "domain-joined"]))
    # ws-105 是被攻陷点
    A.append(dict(asset_id="WS-105", hostname="ws-105.corp.internal",
                  ip="10.10.5.105", os="Windows 11", owner="Finance",
                  env="internal", sensitivity=2, trust=2,
                  tags=["workstation", "finance", "domain-joined", "compromised", "patient-zero"]))

    # ── 普通办公工作站(L1 / T2)—— 正常业务噪声来源 ──
    depts = ["eng", "sales", "mkt", "ops", "legal", "exec"]
    for i in range(24):
        d = depts[i % len(depts)]
        A.append(dict(asset_id=f"WS-{d.upper()}-{200 + i}",
                      hostname=f"ws-{d}-{200 + i}.corp.internal",
                      ip=f"10.10.6.{10 + i}", os="Windows 11" if i % 3 else "macOS 14",
                      owner=d.capitalize(), env="internal",
                      sensitivity=1, trust=2, tags=["workstation", "domain-joined", d]))

    # ── 开发/测试(L1 / T1)──
    A += [
        dict(asset_id="DEV-K8S-01", hostname="k8s-dev01.corp.internal", ip="10.10.7.10",
             os="Ubuntu 22.04", owner="Platform", env="dev",
             sensitivity=1, trust=1, tags=["kubernetes", "dev", "non-prod"]),
        dict(asset_id="DEV-CI-01", hostname="ci01.corp.internal", ip="10.10.7.11",
             os="Ubuntu 22.04", owner="Platform", env="dev",
             sensitivity=1, trust=1, tags=["ci-cd", "jenkins", "dev"]),
        dict(asset_id="DEV-REG-01", hostname="registry01.corp.internal", ip="10.10.7.12",
             os="Ubuntu 22.04", owner="Platform", env="dev",
             sensitivity=1, trust=1, tags=["container-registry", "dev"]),
    ]
    return A


# ══════════════════════════════════════════════════════════════
# 2. SIEM 日志(siem_logs)—— 攻击链事件 + 正常业务噪声
# ══════════════════════════════════════════════════════════════
def _build_siem_logs() -> list[dict]:
    L: list[dict] = []

    # ─────────────────────────────────────────────
    # 攻击链主线(高完整性:来自可信 SIEM,trust=3;但记录的是恶意行为)
    # ─────────────────────────────────────────────
    ATT = "attacker"

    # D-3 侦察:外部扫描 DMZ
    for h, port in [(72, "80"), (72, "443"), (71.9, "22"), (71.8, "3389"), (71.7, "8080")]:
        L.append(dict(ts=_utc(h), source_ip="203.0.113.42", dest_ip="172.16.0.0/24",
                      hostname="fw-edge01.corp.internal", event_type="port_scan",
                      user="-", outcome="success",
                      raw=f"FortiGate: port scan from 203.0.113.42 dst_port={port} "
                          f"to DMZ 172.16.0.0/24 [T1595 Active Scanning]",
                      sensitivity=2, trust=3))

    # D-2 初始访问:CVE-2026-63077 利用 web01
    L += [
        dict(ts=_utc(48.5), source_ip="203.0.113.42", dest_ip="172.16.0.11",
             hostname="web01.dmz.corp.internal", event_type="exploit_attempt",
             user="-", outcome="success",
             raw="nginx/modsec: POST /api/v2/upload — CVE-2026-63077 deserialization "
                 "exploit, 200 OK [T1190 Exploit Public-Facing Application]",
             sensitivity=2, trust=3),
        dict(ts=_utc(48.4), source_ip="172.16.0.11", dest_ip="203.0.113.42",
             hostname="web01.dmz.corp.internal", event_type="webshell_drop",
             user="www-data", outcome="success",
             raw="EDR: /var/www/html/uploads/x.php created by nginx worker; "
                 "sha256=44d88612fea8a8f36de82e1278abb02f [T1505.003 Web Shell]",
             sensitivity=2, trust=3),
        dict(ts=_utc(48.2), source_ip="172.16.0.11", dest_ip="203.0.113.42",
             hostname="web01.dmz.corp.internal", event_type="c2_beacon",
             user="www-data", outcome="success",
             raw="proxy01: HTTPS beacon 172.16.0.11 → evil-c2.example.com every 60s "
                 "[T1071.001 Web Protocols]", sensitivity=2, trust=3),
    ]

    # D-1 凭据窃取 + 横向探测
    L += [
        dict(ts=_utc(30.0), source_ip="172.16.0.11", dest_ip="172.16.0.11",
             hostname="web01.dmz.corp.internal", event_type="cred_dump",
             user="root", outcome="success",
             raw="EDR: /proc/*/maps scraped, mimipenguin-like credential access "
                 "[T1003 OS Credential Dumping]", sensitivity=3, trust=3),
        dict(ts=_utc(29.5), source_ip="172.16.0.11", dest_ip="10.10.5.0/24",
             hostname="fw-core01.corp.internal", event_type="lateral_probe",
             user="-", outcome="success",
             raw="PAN-OS: unusual DMZ→internal SMB/445 sweep from 172.16.0.11 "
                 "[T1021.002 SMB/Windows Admin Shares]", sensitivity=2, trust=3),
    ]

    # D-0 暴力破解 → 登录成功(ws-105)
    for i in range(6):
        L.append(dict(ts=_utc(6.0 - i * 0.05), source_ip="198.51.100.7",
                      dest_ip="10.10.5.105", hostname="ws-105.corp.internal",
                      event_type="login_failed", user="CORP\\svc-backup",
                      outcome="failure",
                      raw=f"EventID 4625: failed logon attempt #{i + 1}, "
                          f"NTLM, src 198.51.100.7 [T1110 Brute Force]",
                      sensitivity=2, trust=3))
    L += [
        dict(ts=_utc(5.6), source_ip="198.51.100.7", dest_ip="10.10.5.105",
             hostname="ws-105.corp.internal", event_type="login_success",
             user="CORP\\svc-backup", outcome="success",
             raw="EventID 4624: successful logon type 3 (network), NTLM, "
                 "src 198.51.100.7 [T1078 Valid Accounts]", sensitivity=2, trust=3),
        # 提权:lsass 注入 → 域管 token
        dict(ts=_utc(5.2), source_ip="10.10.5.105", dest_ip="10.10.5.105",
             hostname="ws-105.corp.internal", event_type="process_inject",
             user="SYSTEM", outcome="success",
             raw="Sysmon EventID 10: cross-process access to lsass.exe by "
                 "rundll32.exe, GrantedAccess 0x1010 [T1055 Process Injection]",
             sensitivity=3, trust=3),
        dict(ts=_utc(5.0), source_ip="10.10.5.105", dest_ip="10.10.1.10",
             hostname="ws-105.corp.internal", event_type="token_theft",
             user="CORP\\Administrator", outcome="success",
             raw="EDR: SeDebugPrivilege abuse, domain-admin token impersonated on "
                 "ws-105 [T1134 Access Token Manipulation]", sensitivity=3, trust=3),
        # C2 回连
        dict(ts=_utc(4.5), source_ip="10.10.5.105", dest_ip="203.0.113.88",
             hostname="ws-105.corp.internal", event_type="c2_beacon",
             user="CORP\\Administrator", outcome="success",
             raw="proxy01: 10.10.5.105 → evil-c2.example.com HTTPS beacon, "
                 "JA3=e7d705a3286e19ea42f587b344ee6865 [T1102 Web Service]",
             sensitivity=3, trust=3),
        # DNS 隧道迹象
        dict(ts=_utc(4.2), source_ip="10.10.5.105", dest_ip="10.10.1.10",
             hostname="ws-105.corp.internal", event_type="dns_tunnel",
             user="CORP\\Administrator", outcome="success",
             raw="DNS: high-entropy TXT queries *.evil-c2.example.com from "
                 "10.10.5.105, 340 req/min [T1071.004 DNS]", sensitivity=3, trust=3),
        # 数据打包 + 外发尝试(被边界拦)
        dict(ts=_utc(3.0), source_ip="10.10.5.105", dest_ip="10.10.2.20",
             hostname="db01.corp.internal", event_type="mass_query",
             user="CORP\\Administrator", outcome="success",
             raw="Oracle audit: SELECT * FROM customers/payments, 1.2M rows dumped "
                 "by unusual principal [T1030 Data Transfer Size Limits]",
             sensitivity=3, trust=3),
        dict(ts=_utc(2.5), source_ip="10.10.5.105", dest_ip="203.0.113.88",
             hostname="fw-edge01.corp.internal", event_type="exfil_blocked",
             user="CORP\\Administrator", outcome="failure",
             raw="FortiGate DLP: BLOCKED 480MB HTTPS upload 10.10.5.105 → "
                 "evil-c2.example.com, matched rule 'PII-egress' [T1041 Exfil over C2]",
             sensitivity=3, trust=3),
    ]

    # ─────────────────────────────────────────────
    # 正常业务噪声(信噪比:攻击 ~30 条 vs 噪声 ~140 条)
    # ─────────────────────────────────────────────
    depts_ips = [f"10.10.6.{10 + i}" for i in range(24)]
    normal_events = [
        ("login_success", "success", "EventID 4624: interactive logon type 2, Kerberos"),
        ("login_success", "success", "EventID 4624: network logon type 3, Kerberos"),
        ("file_access", "success", "EventID 5145: SMB read \\\\fileshare01\\dept"),
        ("dns_query", "success", "DNS: A record lookup for update.microsoft.com"),
        ("dns_query", "success", "DNS: A record lookup for github.com"),
        ("patch_install", "success", "WSUS: KB5041580 installed successfully"),
        ("vpn_connect", "success", "FortiClient: SSL-VPN tunnel established"),
        ("mail_send", "success", "Exchange: message sent, SPF/DKIM pass"),
        ("web_access", "success", "proxy01: GET https://salesforce.com 200"),
        ("backup_job", "success", "Veeam: nightly backup completed, 0 errors"),
    ]
    for i in range(140):
        ev, out, tmpl = _RND.choice(normal_events)
        sip = _RND.choice(depts_ips)
        user = f"CORP\\user{_RND.randint(100, 899)}"
        L.append(dict(ts=_utc(_RND.uniform(0.1, 96.0)), source_ip=sip,
                      dest_ip=_RND.choice(["10.10.1.10", "10.10.3.43", "10.10.2.20",
                                           "10.10.0.8", "8.8.8.8"]),
                      hostname=f"ws-{_RND.choice(['eng','sales','ops','mkt'])}-"
                               f"{_RND.randint(200, 223)}.corp.internal",
                      event_type=ev, user=user, outcome=out,
                      raw=f"{tmpl} [routine]", sensitivity=1, trust=3))

    # 少量误报级可疑(让 Analyst 有得研判,不是非黑即白)
    L += [
        dict(ts=_utc(12.0), source_ip="10.10.6.15", dest_ip="8.8.8.8",
             hostname="ws-eng-205.corp.internal", event_type="dns_query",
             user="CORP\\user204", outcome="success",
             raw="DNS: lookup for pastebin.com — dev pasting logs? [low-confidence]",
             sensitivity=1, trust=3),
        dict(ts=_utc(8.0), source_ip="10.10.7.11", dest_ip="10.10.7.12",
             hostname="ci01.corp.internal", event_type="anomalous_pull",
             user="jenkins", outcome="success",
             raw="registry01: 3am mass image pull from CI — scheduled build or "
                 "off-hours? [low-confidence]", sensitivity=1, trust=2),
    ]
    return L


# ══════════════════════════════════════════════════════════════
# 3. 内部威胁情报(threat_intel)—— 内部 TIP 沉淀的 IOC/TTP
#    与上面日志中的 IP / 域名 / hash / CVE 一一对应,可交叉印证
#    confidence 用 Trust int:内部沙箱/供应商=T2,OSINT=T1
# ══════════════════════════════════════════════════════════════
def _build_threat_intel() -> list[dict]:
    return [
        # 归因主线:DeepPanda / APT-DP
        dict(ioc_type="ip", ioc_value="203.0.113.42", source="internal-TIP",
             confidence=2, ttp="T1595",
             description="APT-DP(DeepPanda)侦察节点,历史多次对本组织 DMZ 扫描"),
        dict(ioc_type="ip", ioc_value="198.51.100.7", source="internal-TIP",
             confidence=2, ttp="T1110/T1078",
             description="APT-DP 暴力破解源,针对 svc-* 服务账户"),
        dict(ioc_type="ip", ioc_value="203.0.113.88", source="internal-TIP",
             confidence=2, ttp="T1071/T1041",
             description="APT-DP C2 备用出口,承载 evil-c2 回连与外发"),
        dict(ioc_type="domain", ioc_value="evil-c2.example.com", source="internal-TIP",
             confidence=2, ttp="T1102",
             description="APT-DP 命令与控制域,HTTPS beacon + DNS TXT 隧道"),
        dict(ioc_type="hash", ioc_value="44d88612fea8a8f36de82e1278abb02f",
             source="internal-sandbox", confidence=2, ttp="T1505.003",
             description="web01 上落地的 PHP webshell 样本 MD5,沙箱确认恶意"),
        dict(ioc_type="cve", ioc_value="CVE-2026-63077", source="vendor-advisory",
             confidence=2, ttp="T1190",
             description="TeamCity 反序列化 RCE,CVSS 9.8,web01 的 CI 服务受影响,已被在野利用"),
        dict(ioc_type="ja3", ioc_value="e7d705a3286e19ea42f587b344ee6865",
             source="internal-TIP", confidence=2, ttp="T1071.001",
             description="APT-DP 定制 TLS 指纹,匹配 ws-105 的 C2 心跳"),
        # 低可信 OSINT(T1)—— 供背书门/多源印证演示
        dict(ioc_type="ip", ioc_value="203.0.113.42", source="OSINT-feed-A",
             confidence=1, ttp="T1595",
             description="公开黑名单标记 203.0.113.42 为扫描源(未验签,低可信)"),
        dict(ioc_type="domain", ioc_value="evil-c2.example.com", source="OSINT-feed-B",
             confidence=1, ttp="T1102",
             description="公开情报社区标记该域为可疑 C2(未验签,低可信)"),
        # 干扰项:良性但看着像 IOC(考验研判)
        dict(ioc_type="ip", ioc_value="8.8.8.8", source="internal-TIP",
             confidence=3, ttp="-",
             description="Google Public DNS,已知良性,勿误判"),
        dict(ioc_type="domain", ioc_value="pastebin.com", source="OSINT-feed-A",
             confidence=1, ttp="T1567",
             description="常被滥用作数据外带,但本组织研发有合规用途,需结合上下文"),
    ]


ASSETS = _build_assets()
SIEM_LOGS = _build_siem_logs()
THREAT_INTEL = _build_threat_intel()


def seed_ops(db: Session, reset: bool = False) -> dict[str, int]:
    """建表并灌入作战级演示数据。reset=True 先清空三张表。"""
    Base.metadata.create_all(bind=db.get_bind())
    if reset:
        for model in (ThreatIntel, SiemLog, Asset):
            db.query(model).delete()
        db.commit()

    counts: dict[str, int] = {}
    if db.query(Asset).count() == 0:
        db.bulk_insert_mappings(Asset, ASSETS)
        counts["assets"] = len(ASSETS)
    else:
        counts["assets"] = 0
    if db.query(SiemLog).count() == 0:
        db.bulk_insert_mappings(SiemLog, SIEM_LOGS)
        counts["siem_logs"] = len(SIEM_LOGS)
    else:
        counts["siem_logs"] = 0
    if db.query(ThreatIntel).count() == 0:
        db.bulk_insert_mappings(ThreatIntel, THREAT_INTEL)
        counts["threat_intel"] = len(THREAT_INTEL)
    else:
        counts["threat_intel"] = 0
    db.commit()
    return counts


if __name__ == "__main__":
    print(f"资产 {len(ASSETS)} 台 · SIEM 日志 {len(SIEM_LOGS)} 条 · "
          f"内部情报 {len(THREAT_INTEL)} 条")
