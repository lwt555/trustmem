"""
编排拓扑 ---- 认知分层判定的依据。

关键设计：拓扑关系（谁是谁的上级）**不可由系统提示词声明**，
只能从编排 DAG 直接读取。这是防止提示词篡改提权的第一道闸。
"""
from __future__ import annotations

import networkx as nx


class Topology:
    def __init__(self) -> None:
        self.g = nx.DiGraph()   # 边方向：parent -> child

    def add_agent(self, agent_id: str, parent: str | None = None) -> None:
        self.g.add_node(agent_id)
        if parent is not None:
            self.g.add_node(parent)
            self.g.add_edge(parent, agent_id)

    # ── 关系查询 ──────────────────────────────────────────────
    def parent(self, a: str) -> str | None:
        preds = list(self.g.predecessors(a)) if a in self.g else []
        return preds[0] if preds else None

    def children(self, a: str) -> set[str]:
        return set(self.g.successors(a)) if a in self.g else set()

    def ancestors(self, a: str) -> set[str]:
        """a 的所有上级（不含自己）。"""
        return set(nx.ancestors(self.g, a)) if a in self.g else set()

    def descendants(self, a: str) -> set[str]:
        return set(nx.descendants(self.g, a)) if a in self.g else set()

    def is_ancestor_of(self, x: str, y: str) -> bool:
        """x 是 y 的上级？"""
        return x in self.ancestors(y)

    def is_descendant_of(self, x: str, y: str) -> bool:
        return x in self.descendants(y)

    def siblings(self, a: str) -> set[str]:
        p = self.parent(a)
        return (self.children(p) - {a}) if p else set()
