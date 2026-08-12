"""F-19 验收：背书门证据不可自证 + 提升不改原件。"""
from __future__ import annotations

from core.labels import (MemoryLabel, Clearance, Trust, Layer, MemoryType)
from core.upgrader import (Upgrader, Evidence, EvidenceType, SourceRegistry)


def _mem(trust=Trust.T1_LOW) -> MemoryLabel:
    return MemoryLabel(chunk_id="m", sensitivity=Clearance.L0_PUBLIC,
                       provenance_trust=trust, layer=Layer.CONCLUSION,
                       memory_type=MemoryType.INTEL, owner_agent="a",
                       task_binding="t", collab_group={"g"})


def test_F19_structural_evidence_cannot_be_self_declared():
    assert not hasattr(Evidence, "validated"), "校验结果不得由调用方声明"
    upgrader = Upgrader()
    r = upgrader.try_upgrade(_mem(), Evidence(etype=EvidenceType.STRUCTURAL,
                                              validator="stix2_ioc"),
                             content="这不是合法的 STIX2")
    assert not r.applied


def test_F19_structural_valid_content_passes():
    upgrader = Upgrader()
    r = upgrader.try_upgrade(_mem(), Evidence(etype=EvidenceType.STRUCTURAL,
                                              validator="stix2_ioc"),
                             content='{"type": "bundle", "id": "b"}')
    assert r.applied and r.new_chunk is not None


def test_F19_local_consistency_checks_matched_chunks():
    upgrader = Upgrader(chunk_lookup=lambda cid: None)
    r = upgrader.try_upgrade(_mem(), Evidence(etype=EvidenceType.LOCAL_CONSISTENCY,
                                              matched_chunks=["不存在的id"]))
    assert not r.applied


def test_F19_local_consistency_requires_high_trust():
    low = _mem(trust=Trust.T1_LOW)
    upgrader = Upgrader(chunk_lookup=lambda cid: low)
    r = upgrader.try_upgrade(_mem(), Evidence(etype=EvidenceType.LOCAL_CONSISTENCY,
                                              matched_chunks=["low-trust"]))
    assert not r.applied


def test_F19_sybil_same_publisher_counts_as_one():
    registry = SourceRegistry()
    registry.register("a.com", publisher="EvilCorp", asn="AS12345")
    registry.register("b.net", publisher="EvilCorp", asn="AS12345")
    upgrader = Upgrader(registry=registry)
    r = upgrader.try_upgrade(_mem(), Evidence(etype=EvidenceType.CROSS_SOURCE,
                                              source_urls=["https://a.com/x",
                                                           "https://b.net/y"]))
    assert not r.applied
    assert "1 源" in r.reason


def test_F19_upgrade_preserves_original():
    mem = _mem(trust=Trust.T2_MEDIUM)
    before = mem.provenance_trust
    upgrader = Upgrader()
    r = upgrader.try_upgrade(mem, Evidence(etype=EvidenceType.HUMAN,
                                           human_signature="sig"),
                             sig_verifier=lambda sig, cid: True)
    assert r.applied
    assert mem.provenance_trust == before, "原件不得被修改"
    assert r.new_chunk is not None
    assert r.new_chunk.upgraded_from == mem.chunk_id
    assert r.anchor_payload["event"] == "TRUST_UPGRADE"
    assert r.anchor_payload["upgraded_from"] == mem.chunk_id
