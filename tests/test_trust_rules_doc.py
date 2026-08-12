"""F-15 验收：TR1–TR16 可信流转规则表 + 反向生成脚本 + 三段论证。

- 16 条规则全部有文档且代码位置有效
- 文档与代码对拍一致（python tools/gen_trust_rules.py --check）
- B 组优先级：TR10（硬拒）> TR7（谎报降级）
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from core.labels import (AgentLabel, MemoryLabel, Clearance, Trust, Layer,
                         MemoryType, Role, WriteOp)
from core.session import Session
from core.topology import Topology
from core.pdp import PDP
from core.trust_rules import parse_trust_rules, count_lines


def test_F15_all_16_rules_documented_and_located():
    rules = parse_trust_rules("docs/TRUST_RULES.md")
    assert {r.id for r in rules} == {f"TR{i}" for i in range(1, 17)}, \
        f"规则集合不全：{sorted(r.id for r in rules)}"
    for r in rules:
        fname, ln = r.code_location.split(":")
        assert Path(fname).exists(), f"{r.id} 代码位置文件不存在: {fname}"
        assert int(ln) <= count_lines(fname), f"{r.id} 代码位置越界: {r.code_location}"


def test_F15_doc_matches_code():
    proc = subprocess.run(["python", "tools/gen_trust_rules.py", "--check"],
                          capture_output=True, encoding="utf-8")
    assert proc.returncode == 0, f"文档与代码不一致：\n{proc.stdout}\n{proc.stderr}"


def test_F15_group_priority_enforced():
    """B 组优先级：同时命中 TR10（CONSULT 写回）与 TR7（谎报降级）时，
    TR10 胜出——DENY 而非降级写入。"""
    pdp = PDP(Topology())
    agent = AgentLabel(agent_id="a", role=Role.ANALYST,
                       clearance=Clearance.L2_SENSITIVE, trust_intrinsic=Trust.T2_MEDIUM,
                       task_domain={"task-x"}, collab_group={"g"})
    sess = Session.start("s", agent, "task-x")
    consulted = MemoryLabel(chunk_id="consulted", sensitivity=Clearance.L0_PUBLIC,
                            provenance_trust=Trust.T3_HIGH, layer=Layer.CONCLUSION,
                            memory_type=MemoryType.INTEL, owner_agent="o",
                            task_binding="task-x")
    sess.consult("consulted")

    # op=VERBATIM + 完全不相关的 output_text 本会触发 TR7 降级；
    # 但 input_mems 含 CONSULT 读入的 chunk，TR10 应先命中硬拒。
    d, _decay = pdp.can_write(agent, sess, Clearance.L0_PUBLIC, Layer.CONCLUSION,
                              [consulted], WriteOp.VERBATIM,
                              input_texts=["original text"],
                              output_text="完全不相关的内容")
    assert d.denied_by == "Provenance-NoConsult", \
        f"TR10 应胜过 TR7，denied_by={d.denied_by}"
