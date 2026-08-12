"""本地锚定后端：root 写入 append-only JSONL，返回回执。"""
from __future__ import annotations

import json
import uuid

from .anchor import AnchorReceipt


class LocalAnchor:
    def __init__(self, path: str = "chain/anchor_log.jsonl") -> None:
        self.path = path

    def send(self, root: bytes, meta: dict) -> AnchorReceipt:
        tx_id = f"local-{uuid.uuid4().hex[:12]}"
        record = {"tx_id": tx_id, "root": root.hex(), "meta": meta}
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
        return AnchorReceipt(tx_id=tx_id, verified=True, root=root, meta=meta)
