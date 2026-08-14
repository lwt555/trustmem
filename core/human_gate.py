"""人环门 (Human Gate) — 流式 demo 中暂停等待人工决定的同步组件。

两处人工判断点共用此组件：

  背书门 (kind="endorse")  — 人判断 analyst 的 T1 研判是否可信，批准则升 T3
  HITL 门 (kind="hitl")    — 人判断 executor 的高危动作是否执行，批准则放行

用法（阻塞在后台线程，主循环轮询 drain_new 推事件、REST resolve 唤醒）：

    req = HumanRequest(kind="hitl", agent_id="executor", tool_name="host_isolate", ...)
    gate.submit(req)                       # ① 非阻塞登记
    decision = gate.wait(req.request_id)   # ② 阻塞等人工（超时默认 deny）
    if decision["decision"] == "approve": ...

resolve 由 REST 端点 POST /api/human/resolve 调用；drain_new 由 /ws/graph
主循环在 wait_for 超时/每次推事件后调用，把新请求推给前端展示确认框。
"""
from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field

# 人工未在此时长内确认，默认按拒绝处理（fail-closed），避免 demo 卡死。
HUMAN_TIMEOUT_S = 300.0


@dataclass
class HumanRequest:
    """一条待人工决定的请求，同时作为推给前端的展示载体。"""
    kind: str                      # "endorse" | "hitl"
    agent_id: str
    summary: str = ""
    tool_name: str | None = None
    tool_args: dict | None = None
    action_fingerprint: str = ""
    checks: list = field(default_factory=list)   # list[dict] 完整 check trace
    chunk_id: str = ""
    trust: str = ""
    sensitivity: str = ""          # 内容密级，如 "L2"
    layer: str = ""                # 认知层，如 "C"
    owner: str = ""                # 写入主体，如 "analyst"
    policy: str = ""               # CP-ABE 策略串
    request_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "kind": self.kind,
            "agent_id": self.agent_id,
            "summary": self.summary,
            "tool_name": self.tool_name,
            "tool_args": self.tool_args or {},
            "action_fingerprint": self.action_fingerprint,
            "checks": self.checks,
            "chunk_id": self.chunk_id,
            "trust": self.trust,
            "sensitivity": self.sensitivity,
            "layer": self.layer,
            "owner": self.owner,
            "policy": self.policy,
        }


class HumanGate:
    """线程安全的阻塞式人工确认门。

    后台线程 submit+wait，主循环 drain_new 拉新请求推送，REST resolve 唤醒。
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # request_id -> [Event, result dict | None]
        self._pending: dict[str, list] = {}
        self._new: list[HumanRequest] = []

    def submit(self, req: HumanRequest) -> str:
        with self._lock:
            self._pending[req.request_id] = [threading.Event(), None]
            self._new.append(req)
        return req.request_id

    def wait(self, request_id: str, timeout: float = HUMAN_TIMEOUT_S) -> dict:
        with self._lock:
            item = self._pending.get(request_id)
        if item is None:
            return {"decision": "deny", "reason": "请求不存在或已过期"}
        ev = item[0]
        got = ev.wait(timeout)
        with self._lock:
            _, result = self._pending.get(request_id, (None, None))
            self._pending.pop(request_id, None)
        if not got or result is None:
            return {"decision": "deny", "reason": "超时未人工确认，默认拒绝"}
        return result

    def resolve(self, request_id: str, decision: str, reason: str = "") -> bool:
        with self._lock:
            item = self._pending.get(request_id)
        if item is None:
            return False
        item[1] = {"decision": decision, "reason": reason}
        item[0].set()
        return True

    def drain_new(self) -> list[HumanRequest]:
        """取出尚未推送的新请求并清空，供主循环推给前端（避免重复推送）。"""
        with self._lock:
            out = list(self._new)
            self._new.clear()
        return out

    def list_new(self) -> list[HumanRequest]:
        """只读快照：尚未推送的新请求（REST 调试端点用，不清空）。"""
        with self._lock:
            return list(self._new)

    @property
    def pending_count(self) -> int:
        with self._lock:
            return len(self._pending)
