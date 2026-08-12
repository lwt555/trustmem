"""
会话回放（F-18 / 设计文档 §3.7）。

    python chain/replay.py --session sess-11

输出完整时间线并校验 Merkle 链完整性；改一行后 verify() ok=False。
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime

from core.merkle import AuditEvent, EventType, MerkleStore


@dataclass
class ReplayResult:
    session_id: str
    events: list[AuditEvent] = field(default_factory=list)
    verified: bool = True

    def timeline(self) -> str:
        lines = [f"session {self.session_id}: {len(self.events)} events, "
                 f"verify={'ok' if self.verified else 'FAILED'}"]
        for e in self.events:
            lines.append(f"  [{e.at.isoformat()}] {e.event_type.value:14s} "
                         f"{e.subject} -> {e.object}")
        return "\n".join(lines)


def replay(session_id: str, store: MerkleStore | None = None) -> ReplayResult:
    store = store or MerkleStore()
    events = store.replay_session(session_id)
    verified = all(store.verify_event(e.event_id) for e in events)
    chain_ok = store.verify_chain()["valid"]
    return ReplayResult(session_id, events, verified and chain_ok)


# ── JSONL 持久化（事件级）───────────────────────────────────────

def _event_to_line(e: AuditEvent) -> str:
    return e.serialize().decode("utf-8")


def _line_to_event(line: str) -> AuditEvent:
    d = json.loads(line)
    return AuditEvent(
        event_id=d["id"],
        event_type=EventType(d["type"]),
        subject=d["subject"],
        object=d["object"],
        session_id=d["session"],
        payload=d["payload"],
        at=datetime.fromisoformat(d["at"]),
    )


def save_log(store: MerkleStore, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for session_id in store._session_index:
            for e in store.replay_session(session_id):
                f.write(_event_to_line(e) + "\n")


def load_log(path: str) -> MerkleStore:
    store = MerkleStore()
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                store.log(_line_to_event(line))
    store.flush()
    return store


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="回放任一会话的完整决策链")
    parser.add_argument("--session", required=True, help="会话 id")
    parser.add_argument("--log", default="chain/anchor_log.jsonl",
                        help="事件日志路径")
    args = parser.parse_args(argv)

    try:
        store = load_log(args.log)
    except FileNotFoundError:
        print(f"日志不存在: {args.log}", file=sys.stderr)
        return 1

    r = replay(args.session, store=store)
    print(r.timeline())
    print(f"verify() {'ok' if r.verified else 'False'}")
    return 0 if r.verified else 2


if __name__ == "__main__":
    raise SystemExit(main())
