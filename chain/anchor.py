"""
锚定抽象层（F-18 / 设计文档 §3.7）。

on_anchor 走后台队列，绝不阻塞裁决路径（铁律 10）。
on_decision 保持同步（推前端）。LocalAnchor 与 FiscoAnchor 同接口，一行切换。
"""
from __future__ import annotations

import queue
import threading
from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class AnchorReceipt:
    """锚定回执。verified=False 即视为未上链。"""
    tx_id: str
    verified: bool
    root: bytes | None = None
    meta: dict = field(default_factory=dict)


class AnchorBackend(Protocol):
    """锚定后端统一接口（设计文档 §3.7"一行切换"）。"""
    def send(self, root: bytes, meta: dict) -> AnchorReceipt: ...


class AnchorQueue:
    """on_anchor 走后台队列，绝不阻塞裁决路径（铁律 10）。"""

    def __init__(self, backend: AnchorBackend) -> None:
        self.backend = backend
        self._q: "queue.Queue[tuple[bytes, dict]]" = queue.Queue()
        self.receipts: list[AnchorReceipt] = []
        self._thread = threading.Thread(target=self._drain, daemon=True)
        self._thread.start()

    def submit(self, root: bytes, meta: dict) -> None:
        """只入队，立即返回。"""
        self._q.put_nowait((root, meta))

    def _send(self, root: bytes, meta: dict) -> AnchorReceipt:
        try:
            return self.backend.send(root, meta)
        except Exception as exc:  # 后端故障不得让裁决线程崩溃
            return AnchorReceipt("", False, root, {"error": str(exc)})

    def _drain(self) -> None:
        while True:
            root, meta = self._q.get()
            self.receipts.append(self._send(root, meta))

    def drain_now(self) -> list[AnchorReceipt]:
        """同步冲刷队列（测试/关机用）。"""
        while True:
            try:
                root, meta = self._q.get_nowait()
            except queue.Empty:
                break
            self.receipts.append(self._send(root, meta))
        return list(self.receipts)


def on_decision(decision, sink=None) -> None:
    """同步推送裁决（前端 WebSocket 等）。sink 为可调用对象或 None。"""
    if sink is not None:
        sink(decision)


def on_anchor(q: AnchorQueue, root: bytes, meta: dict) -> None:
    """异步锚定入口：只入队，立即返回（铁律 10）。"""
    q.submit(root, meta)
