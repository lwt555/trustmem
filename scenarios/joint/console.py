"""军事场景（joint）指挥控制台 —— 人工下达任务的唯一入口。

指挥官是人，不是 Agent：不注册为 Agent、不进 Topology、不新建 command_orders 表。
指令记录复用既有 audit_events 表（event_type="TASK_ISSUE"）。
签名复用 ifc/writer_sign.py 的既有 ECDSA 机制（KeyRing 管密钥、ECDSA 原语签名/验签），
不新造一套。
"""
from __future__ import annotations

from core.labels import TaskScope
from core.pdp import Decision
from core.verdict import Verdict

from backend.db.database import get_db
from backend.db.store import AuditStore

from scenarios.joint.setup import load_task

# 复用既有签名机制：KeyRing 管密钥生命周期，_ecdsa_sign/_ecdsa_verify 是通用 ECDSA 原语。
from ifc.writer_sign import KeyRing, _ecdsa_sign, _ecdsa_verify


def _order_payload(order_text: str) -> bytes:
    """命令正文的规范序列化：UTF-8 编码的 order_text。"""
    return order_text.encode("utf-8")


def sign_order(commander_id: str, order_text: str) -> str:
    """用指挥员私钥对命令正文签名，返回十六进制签名串。

    私钥由 KeyRing 按 commander_id 生成/加载（keys/ 目录），幂等：首次生成、
    后续复用。
    """
    ring = KeyRing()
    try:
        priv = ring.load_private(commander_id)
    except (FileNotFoundError, KeyError):
        kp = ring.generate(commander_id)
        priv = kp.private_key
    return _ecdsa_sign(_order_payload(order_text), priv).hex()


def issue_order(commander_id: str, order_text: str, signature: str,
                task_id: str) -> TaskScope:
    """校验签名 → 写 TASK_ISSUE 审计事件 → 返回任务 TaskScope 供派发给 planner。

    签名不合法抛 PermissionError，不写任何审计记录。
    """
    ring = KeyRing()
    pub = ring.load_public(commander_id)
    if not _ecdsa_verify(_order_payload(order_text), bytes.fromhex(signature), pub):
        raise PermissionError(f"命令签名校验失败: commander={commander_id}")

    db = get_db()
    try:
        audit = AuditStore(db)
        decision = Decision(
            verdict=Verdict.ALLOW, action="TASK_ISSUE", subject=commander_id,
            object=task_id, denied_by=None,
        )
        audit.log(decision)
    finally:
        db.close()

    return load_task(task_id).scope
