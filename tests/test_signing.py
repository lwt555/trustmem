"""F-14 验收：写入签名（ECDSA P-256 / SM2），三种篡改全拒，背书门强制验签。"""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from core.labels import (AgentLabel, MemoryLabel, Clearance, Trust, Layer,
                         MemoryType, Role, TaskScope)
from core.session import Session
from core.topology import Topology
from core.pdp import PDP
from core.pipeline import ReadPipeline
from core.upgrader import Upgrader, Evidence, EvidenceType
from core.verdict import Verdict
from ifc import writer_sign


def _mem() -> MemoryLabel:
    return MemoryLabel(chunk_id="m1", sensitivity=Clearance.L1_INTERNAL,
                       provenance_trust=Trust.T2_MEDIUM, layer=Layer.CONCLUSION,
                       memory_type=MemoryType.INTEL, owner_agent="a",
                       task_binding="t", collab_group={"g"})


def _flip_one_bit(b: bytes) -> bytes:
    arr = bytearray(b)
    arr[0] ^= 0x01
    return bytes(arr)


def test_F14_backend_is_asymmetric():
    assert writer_sign.backend_name() in ("ecdsa-p256", "sm2")
    assert "hmac" not in writer_sign.backend_name()


def test_F14_三种篡改全部被拒():
    mem = _mem()
    ct = b"\xab" * 64
    priv, pub = writer_sign.generate_keypair()
    _, other_pub = writer_sign.generate_keypair()
    sig = writer_sign.sign(mem, ct, priv)

    # ① 篡改元数据
    m2 = replace(mem, provenance_trust=Trust.T3_HIGH)
    assert not writer_sign.verify(m2, ct, sig, pub)
    # ② 篡改密文
    assert not writer_sign.verify(mem, _flip_one_bit(ct), sig, pub)
    # ③ 换签名者
    assert not writer_sign.verify(mem, ct, sig, other_pub)


def test_F14_signature_payload_excludes_plaintext():
    mem = _mem()
    ct = b"\xab" * 32
    payload = writer_sign.canonical_payload(mem, ct)
    assert "内网".encode("utf-8") not in payload
    assert b"\xe5\x86\x85\xe7\xbd\x91" not in payload
    # 只含密文摘要，不含密文原文
    assert ct not in payload


def test_F14_human_endorsement_requires_real_signature():
    upgrader = Upgrader()
    r = upgrader.try_upgrade(_mem(), Evidence(etype=EvidenceType.HUMAN,
                                              human_signature="随便一个字符串"))
    assert not r.applied


def test_F14_read_verifies_signature():
    priv, pub = writer_sign.generate_keypair()
    signer = writer_sign.MemorySigner(priv)

    class _Store:
        def __init__(self):
            self.s = {}
        def get(self, chunk_id):
            return self.s[chunk_id]["mem"]
        def get_ciphertext(self, chunk_id):
            return self.s[chunk_id]["ct"]
        def put(self, mem, ciphertext=None):
            self.s[mem.chunk_id] = {"mem": mem, "ct": ciphertext}
        def list_by_task(self, task_id):
            return []

    class _Audit:
        def __init__(self):
            self.events = []
        def log(self, d):
            self.events.append(d)

    st = _Store()
    topo = Topology()
    topo.add_agent("a")
    agent = AgentLabel("a", Role.ANALYST, Clearance.L3_SECRET, Trust.T3_HIGH,
                       task_domain={"t"}, collab_group={"g"}, epoch=1)
    sess = Session.start("s", agent, "t")

    mem = _mem()
    ct = b"\x00" * 32
    signer.sign(mem, ct)
    st.put(mem, ct)

    # 篡改存储的元数据（provenance_trust T2 → T3）
    st.s["m1"]["mem"] = replace(mem, provenance_trust=Trust.T3_HIGH)

    pipe = ReadPipeline(PDP(topo), None, st, _Audit(), verifier=signer)
    r = pipe.read(agent=agent, session=sess, chunk_id="m1",
                  scope=TaskScope("t", Clearance.L3_SECRET, Trust.T0_UNTRUSTED))
    assert r.decision.verdict is Verdict.DENY
    assert r.denied_by == "SignatureInvalid"


def test_F14_private_keys_not_in_repo():
    assert "keys/" in Path(".gitignore").read_text(encoding="utf-8")
    assert list(Path("keys").glob("*.pem")) == [], "keys/ 不应残留私钥"
