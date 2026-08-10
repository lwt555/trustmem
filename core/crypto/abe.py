"""
CP-ABE (Ciphertext-Policy Attribute-Based Encryption) simulation.

Production uses charm-crypto/bswabe (bilinear pairings over elliptic curves).
This module provides an API-compatible simulation using AES-GCM + attribute checking
so the system can be developed and tested on Windows without native crypto libraries.

The decision logic is identical: policy string is parsed, attributes are matched,
and decryption is only allowed if the policy is satisfied. The difference is that
enforcement happens in software rather than at the mathematical pairing level.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ──────────────────────────────────────────────────────────────
# Key types
# ──────────────────────────────────────────────────────────────

@dataclass
class ABEMasterKey:
    """Master secret key for the attribute authority."""
    key_bytes: bytes
    enc_key: bytes                # shared symmetric key for encrypt/decrypt (simulates pairing)
    version: int = 1

    def export(self) -> bytes:
        return self.key_bytes + self.enc_key


@dataclass
class ABEPublicKey:
    """Public parameters for encryption. Contains enc_key for pairing simulation."""
    key_bytes: bytes
    enc_key: bytes                # shared key — in real CP-ABE this is recovered via pairing
    version: int = 1

    def export(self) -> bytes:
        return self.key_bytes


@dataclass
class ABEAttributeKey:
    """Attribute-bound private key issued to an agent."""
    agent_id: str
    attributes: list[str]
    key_bytes: bytes
    enc_key: bytes                # shared key — same as in PK, simulating pairing recovery
    epoch: int = 0

    def has_attr(self, name: str) -> bool:
        return name in self.attributes


@dataclass
class Ciphertext:
    """CP-ABE ciphertext. Contains AES-GCM encrypted payload + policy metadata."""
    policy: str
    nonce: bytes
    ct: bytes                     # AES-GCM ciphertext
    tag: bytes | None = None      # auth tag if separate from ct

    def to_bytes(self) -> bytes:
        return json.dumps({
            "policy": self.policy,
            "nonce": self.nonce.hex(),
            "ct": self.ct.hex(),
            "tag": self.tag.hex() if self.tag else "",
        }).encode()

    @classmethod
    def from_bytes(cls, data: bytes) -> "Ciphertext":
        d = json.loads(data.decode())
        return cls(
            policy=d["policy"],
            nonce=bytes.fromhex(d["nonce"]),
            ct=bytes.fromhex(d["ct"]),
            tag=bytes.fromhex(d["tag"]) if d.get("tag") else None,
        )


# ──────────────────────────────────────────────────────────────
# Policy parser
# ──────────────────────────────────────────────────────────────

def _tokenize(policy: str) -> list[str]:
    """Tokenize a bswabe-style policy string. Supports hyphens in identifiers."""
    return re.findall(r'\(|\)|\band\b|\bor\b|[-\w]+', policy, re.IGNORECASE)


def _eval_policy(attributes: list[str], tokens: list[str], pos: int) -> tuple[bool, int]:
    """Recursive descent policy evaluator. Returns (result, new_pos).

    Delegates to _eval_or at the top level, then _eval_and, then _eval_atom.
    The and/or chain evaluators handle operator precedence correctly:
    'or' chains _eval_and groups, 'and' chains atoms within each or-branch.
    """
    return _eval_or(attributes, tokens, pos)


def _eval_or(attributes: list[str], tokens: list[str], pos: int) -> tuple[bool, int]:
    """Evaluate top-level and/or chain."""
    left, pos = _eval_and(attributes, tokens, pos)
    while pos < len(tokens) and tokens[pos].lower() == 'or':
        right, pos = _eval_and(attributes, tokens, pos + 1)
        left = left or right
    return left, pos


def _eval_and(attributes: list[str], tokens: list[str], pos: int) -> tuple[bool, int]:
    """Evaluate and-chain."""
    left, pos = _eval_atom(attributes, tokens, pos)
    while pos < len(tokens) and tokens[pos].lower() == 'and':
        right, pos = _eval_atom(attributes, tokens, pos + 1)
        left = left and right
    return left, pos


def _eval_atom(attributes: list[str], tokens: list[str], pos: int) -> tuple[bool, int]:
    """Evaluate a single atom (attribute name or parenthesized group)."""
    token = tokens[pos]

    if token == '(':
        pos += 1
        result, pos = _eval_or(attributes, tokens, pos)
        if pos < len(tokens) and tokens[pos] == ')':
            pos += 1
        return result, pos

    return token in attributes, pos + 1


def policy_satisfied(policy: str, attributes: list[str]) -> bool:
    """Check whether a set of attributes satisfies a CP-ABE policy string."""
    if not policy:
        return False
    try:
        tokens = _tokenize(policy)
        attr_set = set(attributes)
        result, _ = _eval_policy(list(attr_set), tokens, 0)
        return result
    except (IndexError, ValueError):
        return False


def check_policy(policy: str, attributes: list[str]) -> tuple[bool, str]:
    """Return (satisfied, explanation)."""
    ok = policy_satisfied(policy, attributes)
    if ok:
        return True, f"[PASS] 属性集合满足策略: {policy}"
    else:
        return False, f"[FAIL] 属性集合不满足策略: {policy}"


# ──────────────────────────────────────────────────────────────
# CP-ABE API (charm-compatible interface)
# ──────────────────────────────────────────────────────────────

def abe_setup() -> tuple[ABEMasterKey, ABEPublicKey]:
    """Generate master key and public parameters."""
    mk_bytes = os.urandom(32)
    # Shared encryption key — simulates the bilinear pairing e(g^alpha, g^s)
    enc_key = hashlib.pbkdf2_hmac("sha256", mk_bytes, b"trustmem-pairing", 100000, 32)
    pk_bytes = hashlib.sha256(mk_bytes + b"public").digest()
    return ABEMasterKey(mk_bytes, enc_key), ABEPublicKey(pk_bytes, enc_key)


def abe_issue_key(mk: ABEMasterKey, agent_id: str,
                  attributes: list[str], epoch: int = 0) -> ABEAttributeKey:
    """Issue an attribute-bound private key to an agent."""
    material = mk.key_bytes + agent_id.encode() + b"".join(a.encode() for a in sorted(attributes))
    derived = hashlib.pbkdf2_hmac("sha256", material, b"trustmem-abe-key", 100000, 32)
    return ABEAttributeKey(agent_id=agent_id, attributes=list(attributes),
                           key_bytes=derived, enc_key=mk.enc_key, epoch=epoch)


def abe_encrypt(pk: ABEPublicKey, plaintext: str, policy: str) -> Ciphertext:
    """
    Encrypt plaintext under a CP-ABE policy.

    Uses AES-256-GCM with the shared enc_key (simulating pairing-derived key).
    The policy is embedded in the ciphertext header so the decryptor can
    check attribute satisfaction.
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(pk.enc_key)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), policy.encode())  # AAD = policy
    return Ciphertext(policy=policy, nonce=nonce, ct=ct)


def abe_decrypt(attr_key: ABEAttributeKey, ct: Ciphertext) -> bytes | None:
    """
    Decrypt a CP-ABE ciphertext. Returns None if the agent's attributes
    do not satisfy the policy.

    In real CP-ABE, attribute matching is enforced by the bilinear map.
    Here we check attributes explicitly before decrypting, then use the
    shared enc_key (which in production would be recovered via pairing).
    """
    if not policy_satisfied(ct.policy, attr_key.attributes):
        return None

    aesgcm = AESGCM(attr_key.enc_key)
    try:
        return aesgcm.decrypt(ct.nonce, ct.ct, ct.policy.encode())
    except Exception:
        return None
