"""F-10 验收：CP-ABE 密钥隔离（KEM 路线 B），无共享主密钥。

对应《TrustMem 修补工程提示词》F-10 路线 B 的验收断言。
"""
from __future__ import annotations

from core.crypto.abe import (
    abe_setup, abe_issue_key, abe_encrypt, abe_decrypt, Ciphertext, ENFORCEMENT,
)
from core.crypto.abe_simulation import ABESimulationBackend
from core.crypto.engine import CryptoEngine
from core.topology import Topology


def _extract_key_material(key) -> bytes:
    return b"|".join(sorted(key.keys.values()))


def _key_contains_master_secret(key, backend) -> bool:
    mk = getattr(backend, "_mk", None)
    if mk is None:
        return False
    return any(v == mk.key_bytes for v in key.keys.values())


def test_F10_agent_keys_are_distinct():
    backend = ABESimulationBackend()
    k1 = backend.issue_key("a", ["clearance_0"])
    k2 = backend.issue_key("b", ["clearance_3"])
    assert _extract_key_material(k1) != _extract_key_material(k2)


def test_F10_no_shared_master_secret_in_agent_key():
    backend = ABESimulationBackend()
    k = backend.issue_key("a", ["clearance_0", "task_soc"])
    assert not _key_contains_master_secret(k, backend)
    # 主体只拿得到自身属性，拿不到未授予属性的派生密钥
    assert "clearance_3" not in k.keys
    assert "clearance_0" in k.keys


def test_F10_bypassing_policy_check_still_fails():
    """核心断言：绕过软件策略检查，仍然解不开（无软件 if）。"""
    backend = ABESimulationBackend()
    ct = backend.encrypt("secret", "(clearance_3)")
    k_low = backend.issue_key("low", ["clearance_0"])
    raw = abe_decrypt(k_low, Ciphertext.from_bytes(ct))
    assert raw is None


def test_F10_cross_decrypt_fails_without_software_check():
    mk, pk = abe_setup()
    k_high = abe_issue_key(mk, "high", ["clearance_3"])
    k_low = abe_issue_key(mk, "low", ["clearance_0"])
    ct = abe_encrypt(pk, "top secret", "clearance_3")
    assert abe_decrypt(k_high, ct) == b"top secret"
    assert abe_decrypt(k_low, ct) is None


def test_F10_backend_declares_enforcement_level():
    engine = CryptoEngine(Topology(), ckks_dim=8)
    assert engine.stats()["abe_enforcement"] in ("pairing", "kem-derived")
    assert engine.stats()["abe_enforcement"] != "software-if"
    assert ENFORCEMENT == "kem-derived"
