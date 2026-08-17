"""
标签 → CP-ABE 访问策略串
=========================
不重写 CP-ABE，只改属性串的生成方式。现有 bswabe/charm 实现完全复用。

★ 一个必须讲清楚的分工（答辩加分点）：

    CP-ABE 只约束**解密**，不约束**加密** ---- 任何人都能用任意策略加密。
    所以：
        保密性（读）  → 可以用 CP-ABE 强制。密钥不满足策略就是解不开。
        完整性（写）  → 无法用 CP-ABE 表达，必须由运行时 PDP 强制。

    更根本的原因：完整性约束是**状态相关**的。T_eff 随会话中读过什么而变化，
    而密码学策略是静态的、在加密那一刻就固定了。静态策略天然表达不了动态状态。

    这就是我们保留"可信 PEP"这一信任假设的原因，也是回答
    "为什么不把所有事都用密码学做"的标准答案。

CP-ABE 不支持数值比较（>=），所有序关系必须展开为离散属性的析取。
"""
from __future__ import annotations

from .labels import AgentLabel, MemoryLabel, Clearance, Layer, Role
from .topology import Topology


def agent_attributes(agent: AgentLabel, topo: Topology) -> list[str]:
    """签发属性私钥时授予的属性集合。"""
    attrs: list[str] = [
        f"agent_{agent.agent_id}",
        f"role_{agent.role.value}",
        f"clearance_{int(agent.clearance)}",
        f"epoch_{agent.epoch}",
    ]
    attrs += [f"task_{t}" for t in sorted(agent.task_domain)]
    attrs += [f"group_{g}" for g in sorted(agent.collab_group)]
    # 关系型属性：拓扑固定后在签发期展开为静态属性
    # 这是把"关系"塞进 CP-ABE 的标准做法
    for d in sorted(topo.descendants(agent.agent_id)):
        attrs.append(f"ancestorof_{d}")
    for a in sorted(topo.ancestors(agent.agent_id)):
        attrs.append(f"descendantof_{a}")
    return attrs


def policy_from_label(mem: MemoryLabel, topo: Topology) -> str:
    """
    生成 CP-ABE 策略串（charm bswabe 语法：属性名 + and/or + 括号）。

    注意策略里**没有 trust 属性** ---- 完整性不是读约束，见模块说明。
    """
    clauses: list[str] = []

    # 保密性：clearance >= sensitivity，展开为析取
    lv = [f"clearance_{i}" for i in range(int(mem.sensitivity), 4)]
    clauses.append("(" + " or ".join(lv) + ")")

    # need-to-know：task 绑定
    clauses.append(f"task_{mem.task_binding}")

    owner = mem.owner_agent
    group_clause = None
    if mem.collab_group:
        group_clause = "(" + " or ".join(f"group_{g}" for g in sorted(mem.collab_group)) + ")"

    # 认知分层 → 关系型属性
    if mem.layer == Layer.REASONING:
        # 只向上：owner 自己 or owner 的上级 or Auditor；且同协作组
        if group_clause:
            clauses.append(group_clause)
        readers = [f"agent_{owner}", f"ancestorof_{owner}", f"role_{Role.AUDITOR.value}"]
        clauses.append("(" + " or ".join(readers) + ")")
    elif mem.layer == Layer.DIRECTIVE:
        # 向下：owner 自己 or owner 的下级 or Auditor；且同协作组
        if group_clause:
            clauses.append(group_clause)
        readers = [f"agent_{owner}", f"descendantof_{owner}", f"role_{Role.AUDITOR.value}"]
        clauses.append("(" + " or ".join(readers) + ")")
    else:
        # C 层：同协作组 or 上级 or 自己 or Auditor（与 PDP _layer_readable 对齐）
        readers = [f"agent_{owner}", f"ancestorof_{owner}", f"role_{Role.AUDITOR.value}"]
        if group_clause:
            readers = [group_clause] + readers
        clauses.append("(" + " or ".join(readers) + ")")

    # 版本号：权限撤销靠 epoch 递增使旧密钥失效
    clauses.append(f"epoch_{mem.epoch}")

    return " and ".join(clauses)


def key_binding_payload(agent: AgentLabel, attrs: list[str]) -> dict:
    """
    属性私钥签发时的链上承诺载荷。

    prompt_hash 绑定是防提示词篡改提权的关键：
    运行时校验实际 prompt 的哈希与链上承诺不符 → 私钥立即失效。
    这也是回答"区块链是不是硬凑的"的实证 ---- 这个锚点各方都不能单独修改。
    """
    return {
        "event": "ATTRIBUTE_KEY_ISSUE",
        "agent_id": agent.agent_id,
        "prompt_hash": agent.prompt_hash,
        "epoch": agent.epoch,
        "attributes": sorted(attrs),
        "clearance": int(agent.clearance),
        "trust_intrinsic": int(agent.trust_intrinsic),
    }
