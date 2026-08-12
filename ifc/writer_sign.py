"""
写入签名（F-14）——"写入不可抵赖"的非对称实现。

用写入方私钥对「规范化元数据 + 密文摘要」签名（ECDSA P-256 默认 / SM2 国密可选）。
签名对象不含明文 —— 服务端无需看明文即可验签。

完整性只能签名，不能靠 CP-ABE：公钥体系人人可加密，但只有持有私钥的人能签名。
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass

from core.labels import MemoryLabel

# 规范化字段顺序固定：任何实现都必须按此顺序序列化。
CANONICAL_FIELDS = ("chunk_id", "sensitivity", "provenance_trust", "layer",
                    "owner_agent", "task_binding", "provenance_chain",
                    "epoch", "ciphertext_digest")


def canonical_payload(mem: MemoryLabel, ct_bytes: bytes) -> bytes:
    """规范化序列化：字段顺序固定，JSON sort_keys，UTF-8，无空格。

    ciphertext_digest = sha256(ct_bytes).hexdigest()。不含明文。
    """
    digest = hashlib.sha256(ct_bytes).hexdigest()
    obj = {
        "chunk_id": mem.chunk_id,
        "sensitivity": int(mem.sensitivity),
        "provenance_trust": int(mem.provenance_trust),
        "layer": mem.layer.value,
        "owner_agent": mem.owner_agent,
        "task_binding": mem.task_binding,
        "provenance_chain": list(mem.provenance_chain),
        "epoch": int(mem.epoch),
        "ciphertext_digest": digest,
    }
    return json.dumps(obj, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")


def backend_name() -> str:
    """当前签名后端。TRUSTMEM_SIGN=sm2 且 gmssl 可用 → "sm2"，否则 "ecdsa-p256"。

    装不上 gmssl 就抛错，绝不静默降级（铁律 11 / F-14）。
    """
    mode = os.environ.get("TRUSTMEM_SIGN", "ecdsa").lower()
    if mode == "sm2":
        try:
            import gmssl  # noqa: F401
        except ImportError:
            raise RuntimeError("TRUSTMEM_SIGN=sm2 但 gmssl 未安装；不静默降级")
        return "sm2"
    return "ecdsa-p256"


def _ecdsa_sign(payload: bytes, priv_key) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    return priv_key.sign(payload, ec.ECDSA(hashes.SHA256()))


def _ecdsa_verify(payload: bytes, signature: bytes, pub_key) -> bool:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    try:
        pub_key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def sign(mem: MemoryLabel, ct_bytes: bytes, priv_key, backend: str = "ecdsa") -> bytes:
    """对「规范化元数据 + 密文摘要」签名。返回签名字节串。"""
    payload = canonical_payload(mem, ct_bytes)
    if backend == "ecdsa":
        return _ecdsa_sign(payload, priv_key)
    if backend == "sm2":
        raise NotImplementedError("SM2 后端需 gmssl；生产路径见 backend_name()")
    raise ValueError(f"未知签名后端: {backend}")


def verify(mem: MemoryLabel, ct_bytes: bytes, signature: bytes,
           pub_key, backend: str = "ecdsa") -> bool:
    """验签。任何篡改（元数据 / 密文 / 换签名者）都返回 False。"""
    payload = canonical_payload(mem, ct_bytes)
    if backend == "ecdsa":
        return _ecdsa_verify(payload, signature, pub_key)
    if backend == "sm2":
        raise NotImplementedError("SM2 后端需 gmssl；生产路径见 backend_name()")
    raise ValueError(f"未知签名后端: {backend}")


# ──────────────────────────────────────────────────────────────
# 密钥管理（keys/ 目录）
# ──────────────────────────────────────────────────────────────

@dataclass
class KeyPair:
    agent_id: str
    private_key: object
    public_key: object
    public_pem: str


def generate_keypair() -> tuple[object, object]:
    """生成 ECDSA P-256 密钥对 (priv, pub)。"""
    from cryptography.hazmat.primitives.asymmetric import ec
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv, priv.public_key()


def serialize_public_key(pub_key) -> str:
    from cryptography.hazmat.primitives import serialization
    return pub_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def load_public_key(pem: str):
    from cryptography.hazmat.primitives import serialization
    return serialization.load_pem_public_key(pem.encode("utf-8"))


def serialize_private_key(priv_key) -> str:
    from cryptography.hazmat.primitives import serialization
    return priv_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")


def load_private_key(pem: str):
    from cryptography.hazmat.primitives import serialization
    return serialization.load_pem_private_key(pem.encode("utf-8"), password=None)


class MemorySigner:
    """写路径签名 + 读路径验签的统一组件（仿真档：签名账本在内存）。"""

    def __init__(self, priv_key, backend: str = "ecdsa",
                 store: dict[str, bytes] | None = None) -> None:
        self.priv_key = priv_key
        self.public_key = priv_key.public_key() if priv_key is not None else None
        self.backend = backend
        self._store: dict[str, bytes] = store if store is not None else {}

    def sign(self, mem: MemoryLabel, ct_bytes: bytes) -> bytes:
        sig = sign(mem, ct_bytes, self.priv_key, self.backend)
        self._store[mem.chunk_id] = sig
        return sig

    def verify(self, mem: MemoryLabel, ct_bytes: bytes) -> bool:
        sig = self._store.get(mem.chunk_id)
        if sig is None or self.public_key is None:
            return False
        return verify(mem, ct_bytes, sig, self.public_key, self.backend)

    def tamper(self, chunk_id: str) -> None:
        """测试辅助：模拟密文/签名账本被篡改（删除签名）。"""
        self._store.pop(chunk_id, None)


class KeyRing:
    """写路径的签名密钥环。私钥单文件 600，公钥入 keyring.json。"""

    def __init__(self, keys_dir: str = "keys") -> None:
        self.keys_dir = keys_dir
        self.keyring_path = os.path.join(keys_dir, "keyring.json")

    def ensure_dir(self) -> None:
        os.makedirs(self.keys_dir, exist_ok=True)

    def _load_keyring(self) -> dict[str, str]:
        if not os.path.exists(self.keyring_path):
            return {}
        with open(self.keyring_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save_keyring(self, ring: dict[str, str]) -> None:
        self.ensure_dir()
        with open(self.keyring_path, "w", encoding="utf-8") as f:
            json.dump(ring, f, ensure_ascii=False, indent=2)

    def generate(self, agent_id: str) -> KeyPair:
        """生成并持久化密钥对，返回可序列化的 KeyPair。"""
        priv, pub = generate_keypair()
        self.ensure_dir()
        priv_path = os.path.join(self.keys_dir, f"{agent_id}.pem")
        with open(priv_path, "w", encoding="utf-8") as f:
            f.write(serialize_private_key(priv))
        try:
            os.chmod(priv_path, 0o600)
        except OSError:
            pass
        ring = self._load_keyring()
        ring[agent_id] = serialize_public_key(pub)
        self._save_keyring(ring)
        return KeyPair(agent_id=agent_id, private_key=priv,
                       public_key=pub, public_pem=ring[agent_id])

    def load_private(self, agent_id: str):
        path = os.path.join(self.keys_dir, f"{agent_id}.pem")
        with open(path, "r", encoding="utf-8") as f:
            return load_private_key(f.read())

    def load_public(self, agent_id: str):
        ring = self._load_keyring()
        if agent_id not in ring:
            raise KeyError(f"未登记公钥: {agent_id}")
        return load_public_key(ring[agent_id])
