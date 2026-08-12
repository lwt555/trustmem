"""FISCO BCOS 锚定后端。mock=True 返回本地回执（仿真档不依赖链 SDK）。"""
from __future__ import annotations

import uuid

from .anchor import AnchorReceipt


class FiscoAnchor:
    def __init__(self, mock: bool = False, **kwargs) -> None:
        self.mock = mock
        if not mock:
            # 真实 SDK 接入点：不在此处 import，避免硬依赖。
            raise NotImplementedError("FISCO SDK 未接入（演示档用 mock=True）")

    def send(self, root: bytes, meta: dict) -> AnchorReceipt:
        if not self.mock:
            raise NotImplementedError("FISCO SDK 未接入")
        tx_id = f"fisco-mock-{uuid.uuid4().hex[:12]}"
        return AnchorReceipt(tx_id=tx_id, verified=True, root=root, meta=meta)
