"""F-22 验收：TaskScope 全路径启用 —— scope 必填、攻击路径传 scope、
derive_taskscope 按设计公式、六个 SOC 任务模式声明。
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from core.labels import (AgentLabel, MemoryLabel, Clearance, Trust, Layer, Role,
                         TaskScope, IngestMode, derive_taskscope)
from core.session import Session
from core.topology import Topology
from core.pdp import PDP
from core.pipeline import ReadPipeline


def _agent(clearance=Clearance.L2_SENSITIVE) -> AgentLabel:
    return AgentLabel("a", Role.ANALYST, clearance, Trust.T2_MEDIUM,
                      task_domain={"t"}, collab_group={"g"}, epoch=1)


def _read_pipe():
    class Store:
        def get(self, chunk_id):
            return None
    class Audit:
        def log(self, d):
            pass
    return ReadPipeline(PDP(Topology()), None, Store(), Audit())


def test_F22_scope_is_mandatory():
    pipe = _read_pipe()
    a = _agent()
    s = Session.start("s", a, "t")
    with pytest.raises(TypeError):
        pipe.read(agent=a, session=s, chunk_id="c")      # 缺 scope


# ── AST：scenarios/attacks.py 每条 read/write 调用都必须显式传 scope ──
def _read_write_calls(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in ("read", "write"):
                yield node


def _has_kwarg(call, name):
    return any(kw.arg == name for kw in call.keywords)


def test_F22_all_attacks_pass_scope():
    src = Path("scenarios/attacks.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    calls = list(_read_write_calls(tree))
    assert calls, "attacks.py 应至少含一条 read/write 调用"
    for call in calls:
        assert _has_kwarg(call, "scope"), f"{call.lineno} 行未传 scope"


def test_F22_derive_matches_design_formula():
    a_l2 = _agent(Clearance.L2_SENSITIVE)
    a_l3 = _agent(Clearance.L3_SECRET)

    # 出口集为空 → c_ctx_max = agent.clearance
    s = derive_taskscope("t", exports=set(), tools=set(), agent=a_l2)
    assert s.c_ctx_max == Clearance.L2_SENSITIVE
    assert s.t_ctx_min == Trust.T0_UNTRUSTED

    # 有 web_search 出口（readers=L0）→ c_ctx_max = L0
    s2 = derive_taskscope("t", exports={"web_search"}, tools=set(), agent=a_l3)
    assert s2.c_ctx_max == Clearance.L0_PUBLIC

    # 有 firewall_block（required=T3）→ t_ctx_min = T3
    s3 = derive_taskscope("t", exports=set(), tools={"firewall_block"}, agent=a_l3)
    assert s3.t_ctx_min == Trust.T3_HIGH


def test_F22_six_soc_tasks_declared():
    from scenarios.soc_setup import SOC_TASK_MODES, load_task
    assert len(SOC_TASK_MODES) == 6
    for tid, mode in SOC_TASK_MODES.items():
        assert load_task(tid).scope.ingest == mode, \
            f"{tid} 应声明为 {mode.value}"
