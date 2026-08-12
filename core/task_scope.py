"""
TaskScope 上链承诺与运行时校验（F-09）。

TaskScope 的可行区间来自「签名清单」而非上下文，其 scope_hash 随 MANIFEST_COMMIT
上链。运行时若当前 scope 的 hash（或其后继 narrow 的 lineage）与链上承诺不符，
调用方必须对本任务的所有读写返回 DENY——注入内容里写「本任务也允许写 /tmp」结构上无效。
"""
from __future__ import annotations

import uuid

from .labels import TaskScope
from .merkle import AuditEvent, EventType, MerkleStore


def commit_scope(scope: TaskScope, store: MerkleStore) -> AuditEvent:
    """把 TaskScope 的 scope_hash 上链（MANIFEST_COMMIT），返回锚定事件。"""
    ev = AuditEvent(
        event_id=f"mcommit-{uuid.uuid4().hex[:12]}",
        event_type=EventType.MANIFEST_COMMIT,
        subject="manifest",
        object=scope.task_id,
        session_id="manifest",
        payload={"task_id": scope.task_id, "scope_hash": scope.scope_hash},
    )
    store.log(ev)
    return ev


def verify_scope_against_chain(scope: TaskScope, store: MerkleStore) -> bool:
    """运行时校验：scope.scope_hash 或其 parent_hash 链上是否有承诺。

    只支持单层 narrow 的 lineage（parent_hash → 已承诺的原清单）。更深链需在
    MANIFEST_COMMIT 载荷里存完整 lineage（本仿真档未展开）。
    """
    committed = {e.payload.get("scope_hash") for e in store.events_by_type(EventType.MANIFEST_COMMIT)}
    if not committed:
        return False
    if scope.scope_hash in committed:
        return True
    if scope.parent_hash and scope.parent_hash in committed:
        return True
    return False
