"""Graph stream event types for real-time WebSocket push."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class GraphEventType(str, Enum):
    NODE_START = "node_start"
    NODE_END = "node_end"
    AGENT_THOUGHT = "agent_thought"
    AGENT_TOOL_CALL = "agent_tool_call"
    AGENT_TOOL_RESULT = "agent_tool_result"
    MEMORY_WRITE = "memory_write"
    MEMORY_READ = "memory_read"
    PDP_DECISION = "pdp_decision"
    TRUST_DECAY = "trust_decay"
    TRUST_UPGRADE = "trust_upgrade"
    GRAPH_ERROR = "graph_error"
    GRAPH_DONE = "graph_done"


@dataclass
class GraphEvent:
    event_type: GraphEventType
    agent_id: str
    payload: dict = field(default_factory=dict)
    at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "event_type": self.event_type.value,
            "agent_id": self.agent_id,
            "payload": self.payload,
            "at": self.at,
        }
