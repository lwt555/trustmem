"""
内容级能力推断（F-25，设计文档 §3.1 第 7 步）。

待写内容若含外链 / 「请发送至」等回传标记 / 大块 base64，则推断出
``net.post`` / ``context.inject`` 能力，与人工维护的工具注册表取交集。

关键：本模块的产出**只能收紧、不能放宽**。它是抽取器的一环，其结果必须
经过 ``manifest.schema.compose_capabilities`` 与注册表求交后才生效——交集
运算才是安全边界（见 manifest/schema.py 模块注释）。
"""
from __future__ import annotations

import re

_URL_RE = re.compile(r"https?://", re.IGNORECASE)
_SEND_MARKERS = ("发送至", "外发", "上传至", "回传", "转发至", "exfiltrate")
_DATA_URI_RE = re.compile(r"^data:[a-z0-9/+.-]+;base64,", re.IGNORECASE)

# 大块 base64 / 数据块的判定阈值（字节）。超过视为「内容级注入 / 外发」信号。
BASE64_THRESHOLD = 2048


def infer_from_content(content: str) -> set[str]:
    """从待写内容推断能力需求。

    规则（保守方向，宁可多推断，不可漏推断——因为交集会兜底收紧）：
      - 含外链（http/https）或回传标记 → net.post
      - 含大块 base64 / data URI → net.post（外发通道） + context.inject（注入载体）
    """
    caps: set[str] = set()
    if not content:
        return caps

    has_url = _URL_RE.search(content) is not None
    has_send = any(m in content for m in _SEND_MARKERS)
    has_big_base64 = bool(_DATA_URI_RE.match(content)) or len(content) > BASE64_THRESHOLD

    if has_url or has_send or has_big_base64:
        caps.add("net.post")
    if has_big_base64:
        caps.add("context.inject")
    return caps
