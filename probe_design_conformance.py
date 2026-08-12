"""对抗性探针：验证设计文档要求与实现之间的差距。"""
import sys
from core.labels import *
from core.verdict import Verdict
from core.session import Session, SessionStore
from core.pdp import PDP
from core.topology import Topology
from core.upgrader import Upgrader, Evidence, EvidenceType
from core.crypto.abe import *

FAIL = []
def check(name, cond, detail=""):
    tag = "OK  " if cond else "BROKEN"
    print(f"[{tag}] {name}  {detail}")
    if not cond:
        FAIL.append(name)

topo = Topology()
try:
    topo.add_edge("planner", "analyst"); topo.add_edge("planner", "intel")
except Exception:
    pass

def mk_agent(aid, role, cl, tr):
    return AgentLabel(agent_id=aid, role=role, clearance=cl, trust_intrinsic=tr,
                      task_domain={"soc"}, collab_group={"a"},
                      tool_scope={"web_search","file_write","firewall_block","log_query"})

def mk_mem(cid, sens, tr, layer=Layer.CONCLUSION, owner="intel"):
    return MemoryLabel(chunk_id=cid, sensitivity=sens, provenance_trust=tr, layer=layer,
                       memory_type=MemoryType.INTEL, owner_agent=owner,
                       task_binding="soc", collab_group={"a"})

pdp = PDP(topo)

print("\n########## 1. I8 隐藏中立性：CONSULT 是否真的不动水位 ##########")
analyst = mk_agent("analyst", Role.ANALYST, Clearance.L3_SECRET, Trust.T3_HIGH)
s = Session.start("s1", analyst, "soc")
scope = TaskScope("soc", Clearance.L3_SECRET, Trust.T0_UNTRUSTED, IngestMode.CONSULT)
m = mk_mem("m1", Clearance.L2_SENSITIVE, Trust.T1_LOW)
before = (s.c_eff, s.t_eff, s.t_eff_ctl)
d = pdp.can_read_scoped(analyst, m, s, scope)
after = (s.c_eff, s.t_eff, s.t_eff_ctl)
check("I8: CONSULT 裁决为 HIDE", d.verdict == Verdict.HIDE if hasattr(d,'verdict') else False,
      f"verdict={d.verdict}")
check("I8: CONSULT 后三水位纹丝不动", before == after,
      f"before={[str(x) for x in before]} after={[str(x) for x in after]}")

print("\n########## 2. I8 隐藏中立性：TaskScope 越界 HIDE 是否动水位 ##########")
s2 = Session.start("s2", analyst, "soc")
scope2 = TaskScope("soc", Clearance.L1_INTERNAL, Trust.T0_UNTRUSTED, IngestMode.LEARN)
m2 = mk_mem("m2", Clearance.L3_SECRET, Trust.T1_LOW)
b2 = (s2.c_eff, s2.t_eff)
d2 = pdp.can_read_scoped(analyst, m2, s2, scope2)
a2 = (s2.c_eff, s2.t_eff)
check("I8: 超密级区间 HIDE 后水位不动", b2 == a2, f"before={[str(x) for x in b2]} after={[str(x) for x in a2]}")

print("\n########## 3. 区间外可信度：设计要求 HIDE，实现给什么 ##########")
s3 = Session.start("s3", analyst, "soc")
scope3 = TaskScope("soc", Clearance.L3_SECRET, Trust.T3_HIGH, IngestMode.LEARN)
m3 = mk_mem("m3", Clearance.L0_PUBLIC, Trust.T1_LOW)
d3 = pdp.can_read_scoped(analyst, m3, s3, scope3)
check("TR/铁律5: 跌破 t_ctx_min 应 HIDE 而非 DENY", d3.verdict == Verdict.HIDE,
      f"实际 verdict={d3.verdict}, denied_by={d3.denied_by}")

print("\n########## 4. I1 无读上：越权读应 DENY（硬拒绝，不可 HIDE） ##########")
low = mk_agent("low", Role.RETRIEVER, Clearance.L0_PUBLIC, Trust.T2_MEDIUM)
s4 = Session.start("s4", low, "soc")
m4 = mk_mem("m4", Clearance.L3_SECRET, Trust.T3_HIGH)
d4 = pdp.can_read(low, m4, s4)
check("I1: clearance < sensitivity 必须 DENY", d4.verdict == Verdict.DENY,
      f"实际 verdict={d4.verdict}（HIDE 意味着越权目标仍可被受限查询）")

print("\n########## 5. P-F 出口约束方向：c_eff 高的主体能否外发 ##########")
s5 = Session.start("s5", analyst, "soc")
s5.absorb_c(Clearance.L3_SECRET)          # 读过 L3 内网资产
d5 = pdp.can_invoke(analyst, s5, "web_search", "egress:public")
check("I4/P-F: c_eff=L3 调 L0 出口必须 DENY", not d5.allowed,
      f"实际 allowed={d5.allowed}；c_eff={s5.c_eff.name}, 出口readers=L0")

print("\n########## 6. P-T 门查的是 t_eff_ctl 还是 t_eff ##########")
s6 = Session.start("s6", analyst, "soc")
s6.t_eff = Trust.T3_HIGH
s6.t_eff_ctl = Trust.T0_UNTRUSTED         # 控制流已被污染
d6 = pdp.can_invoke(analyst, s6, "firewall_block", "fp")
uses_ctl = not d6.allowed
check("P-T: 高危工具门必须查 t_eff_ctl", uses_ctl,
      f"t_eff=T3 t_eff_ctl=T0 -> allowed={d6.allowed}（说明只查了 t_eff）")

print("\n########## 7. I6 单调性：t_eff 能否被无门直接抬升 ##########")
s7 = Session.start("s7", analyst, "soc")
s7.absorb("x", Trust.T0_UNTRUSTED)
s7.elevate(Trust.T3_HIGH)
check("I6: t_eff 不得绕过背书门上升", s7.t_eff == Trust.T0_UNTRUSTED,
      f"elevate() 后 t_eff={s7.t_eff.name}")

print("\n########## 8. I13 区间单调收紧：widen 必须抛异常 ##########")
sc = TaskScope("soc", Clearance.L1_INTERNAL, Trust.T2_MEDIUM)
try:
    sc.widen(Clearance.L3_SECRET, Trust.T0_UNTRUSTED, sc.scope_hash)
    widened = True
except Exception:
    widened = False
check("I13: widen() 必须无条件抛异常", not widened,
      "持有 scope_hash 即可放宽区间；而 scope_hash 就在对象上，注入方读得到")
check("I13: narrow() 方法存在", hasattr(sc, "narrow"), "设计要求运行时只可 narrow")

print("\n########## 9. TR14 抗 Sybil：ASN/publisher 级独立性 ##########")
up = Upgrader()
mm = mk_mem("m9", Clearance.L0_PUBLIC, Trust.T1_LOW)
ev = Evidence(etype=EvidenceType.CROSS_SOURCE,
              source_urls=["https://a-threat.com/x", "https://b-threat.net/y"])
r = up.try_upgrade(mm, ev)
check("TR14: 同 publisher 不同域名应判 1 源", not r.applied,
      f"两个不同注册域即通过 -> applied={r.applied}（无 ASN/publisher 判定）")

print("\n########## 10. TR13 人工背书：无验签器能否直升 T3 ##########")
mm2 = mk_mem("m10", Clearance.L0_PUBLIC, Trust.T0_UNTRUSTED)
r2 = up.try_upgrade(mm2, Evidence(etype=EvidenceType.HUMAN, human_signature="随便一个字符串"))
check("TR13: 无密码学验签不得提升", not r2.applied,
      f"任意非空字符串 -> {r2.trust_before.name}->{r2.trust_after.name}, applied={r2.applied}")

print("\n########## 11. STRUCTURAL / LOCAL 提升是否可被调用方自证 ##########")
mm3 = mk_mem("m11", Clearance.L0_PUBLIC, Trust.T0_UNTRUSTED)
r3 = up.try_upgrade(mm3, Evidence(etype=EvidenceType.STRUCTURAL, validator="随便"),
                    content="随便")
check("TR12: 结构校验必须由系统执行而非入参声明", not r3.applied,
      f"调用方传 validated=True 即提升 -> applied={r3.applied}")

print("\n########## 12. CP-ABE：属性不满足者能否用自己的密钥解开密文 ##########")
mk_, pk_ = abe_setup()
k_high = abe_issue_key(mk_, "planner", ["clearance_3", "task_soc"])
k_low  = abe_issue_key(mk_, "intel",   ["clearance_0", "task_soc"])
ct = abe_encrypt(pk_, "内网资产清单：10.0.0.1", "(clearance_3) and task_soc")
via_api = abe_decrypt(k_low, ct)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
try:
    direct = AESGCM(k_low.enc_key).decrypt(ct.nonce, ct.ct, ct.policy.encode())
except Exception as e:
    direct = None
check("CP-ABE: 低属性主体经 API 解密失败", via_api is None, "软件 if 判定拦住了")
check("CP-ABE: 低属性主体绕过 API 直接解密应失败", direct is None,
      f"低权限密钥直接解出明文 = {direct!r}  ← 所有 agent 共享同一把 AES 主密钥")
check("CP-ABE: 不同主体密钥材料应不同", k_high.enc_key != k_low.enc_key,
      "enc_key 完全相同，属性绑定是装饰性的")

print("\n########## 13. 读管线是否真的解密 ##########")
import inspect
from core.pipeline import ReadPipeline
src = inspect.getsource(ReadPipeline.read)
check("Pipeline: ALLOW 路径传入真实密文", "decrypt_memory(agent, None)" not in src,
      "源码为 self.crypto.decrypt_memory(agent, None)  # placeholder")
check("Pipeline: CONFIRM 不得直落解密路径",
      "Verdict.CONFIRM" in src, "CONFIRM 未被拦截，直接走到第6步解密")

print("\n########## 14. 4bit 容量预算一致性 ##########")
from core.isolated_llm import ControlFlowBudget
ss = SessionStore()
a_ = mk_agent("a", Role.ANALYST, Clearance.L2_SENSITIVE, Trust.T3_HIGH)
ss.get_or_start("sB", a_, "soc")
n = 0
while ss.consume_ctl("sB", 1.0):
    n += 1
check("容量: 会话级预算应为 4bit", n == 4, f"会话级实际允许 {n} 次查询（SessionStore 硬编码 16.0）")
check("容量: 两处预算应一致", ControlFlowBudget.MAX_BITS == 4.0 and n == 4,
      f"IsolatedLLM={ControlFlowBudget.MAX_BITS}bit vs SessionStore={n}bit")

print("\n########## 15. TR3/TR4 展开语义方向 ##########")
ss2 = SessionStore()
s15 = ss2.get_or_start("sC", a_, "soc")
t_before, ctl_before = s15.t_eff, s15.t_eff_ctl
ss2.consume_ctl("sC", 1.0, Trust.T0_UNTRUSTED)
check("TR3: 受限展开应 t_eff↓ 而 t_eff_ctl 不变",
      s15.t_eff < t_before and s15.t_eff_ctl == ctl_before,
      f"实际 t_eff {t_before.name}->{s15.t_eff.name}, t_eff_ctl {ctl_before.name}->{s15.t_eff_ctl.name} ← 方向恰好相反")

print("\n########## 16. VarStore 受限展开 expand() 是否存在 ##########")
from core.varstore import VarStore as VS
check("TR3/TR4: VarStore.expand() 存在", hasattr(VS, "expand"), "受限展开路径完全缺失")

print("\n" + "="*70)
print(f"探针结论：{len(FAIL)} 项与设计文档不符")
for f in FAIL:
    print("  ✗ " + f)
