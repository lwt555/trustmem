"""
CKKS (Cheon-Kim-Kim-Song) homomorphic encryption simulation.

Production uses TenSEAL (Microsoft SEAL bindings). This module provides
an API-compatible simulation that operates on plaintext vectors while
preserving the same interface for development on Windows.

The simulation wraps all vector operations in types that mirror the
ciphertext lifecycle: encode -> encrypt -> operate -> decrypt -> decode.
"""
from __future__ import annotations

import hashlib
import math
import os
import struct
from dataclasses import dataclass, field
from typing import Sequence


# ──────────────────────────────────────────────────────────────
# Types
# ──────────────────────────────────────────────────────────────

@dataclass
class CKKSContext:
    """Simulated CKKS encryption context."""
    poly_modulus_degree: int
    scale: float                       # e.g., 2^40
    secret_key: bytes
    galois_keys: bytes | None = None
    relin_keys: bytes | None = None


@dataclass
class CKKSEncryptedVector:
    """
    Simulated CKKS ciphertext. Wraps a plaintext vector + noise metadata
    so the API surface mirrors TenSEAL's CKKSTensor.
    """
    _data: bytes                    # serialized "ciphertext"
    _shape: tuple[int, ...]
    size: int
    context_id: str                 # hash of context for binding

    @classmethod
    def _from_plaintext(cls, vec: list[float], ctx: CKKSContext,
                        noise_seed: bytes | None = None) -> "CKKSEncryptedVector":
        """Simulate encryption: pack float32s with key-material XOR obfuscation."""
        raw = struct.pack(f"<{len(vec)}f", *vec)
        nonce = noise_seed or os.urandom(12)
        keystream = _derive_keystream(ctx.secret_key, len(raw), ctx.scale, nonce)
        masked = bytes(a ^ b for a, b in zip(raw, keystream))
        # Prepend nonce so decryption can recover it
        return cls(
            _data=nonce + masked,
            _shape=(len(vec),),
            size=len(vec),
            context_id=ctx_id(ctx),
        )

    def _to_plaintext(self, ctx: CKKSContext) -> list[float]:
        """Simulate decryption."""
        nonce = self._data[:12]
        payload = self._data[12:]
        keystream = _derive_keystream(ctx.secret_key, len(payload), ctx.scale, nonce)
        raw = bytes(a ^ b for a, b in zip(payload, keystream))
        count = len(raw) // 4
        return list(struct.unpack(f"<{count}f", raw))


def ctx_id(ctx: CKKSContext) -> str:
    return hashlib.sha256(ctx.secret_key).hexdigest()[:16]


def _derive_keystream(key: bytes, length: int, scale: float,
                      noise: bytes = b"") -> bytes:
    """Expand key to keystream of required length."""
    out = b""
    counter = 0
    while len(out) < length:
        seed = key + struct.pack("<Q", counter) + struct.pack("<d", scale) + noise
        out += hashlib.sha256(seed).digest()
        counter += 1
    return out[:length]


# ──────────────────────────────────────────────────────────────
# CKKS API (TenSEAL-compatible interface)
# ──────────────────────────────────────────────────────────────

def ckks_setup(poly_modulus_degree: int = 8192,
               scale: float = 2.0**40) -> CKKSContext:
    """Generate a CKKS context with fresh secret key."""
    sk = os.urandom(32)
    return CKKSContext(
        poly_modulus_degree=poly_modulus_degree,
        scale=scale,
        secret_key=sk,
        galois_keys=hashlib.sha256(sk + b"galois").digest(),
        relin_keys=hashlib.sha256(sk + b"relin").digest(),
    )


def ckks_encode_encrypt(vec: Sequence[float], ctx: CKKSContext) -> CKKSEncryptedVector:
    """Encode a float vector and encrypt it."""
    return CKKSEncryptedVector._from_plaintext(list(vec), ctx)


def ckks_decrypt_decode(enc: CKKSEncryptedVector, ctx: CKKSContext) -> list[float]:
    """Decrypt and decode a CKKS ciphertext back to float vector."""
    if enc.context_id != ctx_id(ctx):
        raise ValueError("Context mismatch: ciphertext was encrypted with a different key")
    return enc._to_plaintext(ctx)


def ckks_add(a: CKKSEncryptedVector, b: CKKSEncryptedVector,
             ctx: CKKSContext) -> CKKSEncryptedVector:
    """Homomorphic addition: E(a) + E(b) = E(a + b)."""
    if a.size != b.size:
        raise ValueError(f"Size mismatch: {a.size} != {b.size}")
    ctx_id_check(a, b, ctx)
    a_vec = a._to_plaintext(ctx)
    b_vec = b._to_plaintext(ctx)
    result = [x + y for x, y in zip(a_vec, b_vec)]
    return CKKSEncryptedVector._from_plaintext(result, ctx)


def ckks_multiply(a: CKKSEncryptedVector, b: CKKSEncryptedVector,
                  ctx: CKKSContext) -> CKKSEncryptedVector:
    """Homomorphic multiplication: E(a) * E(b) = E(a * b), element-wise."""
    if a.size != b.size:
        raise ValueError(f"Size mismatch: {a.size} != {b.size}")
    ctx_id_check(a, b, ctx)
    a_vec = a._to_plaintext(ctx)
    b_vec = b._to_plaintext(ctx)
    result = [x * y for x, y in zip(a_vec, b_vec)]
    return CKKSEncryptedVector._from_plaintext(result, ctx)


def ckks_inner_product(a: CKKSEncryptedVector, b: CKKSEncryptedVector,
                       ctx: CKKSContext) -> CKKSEncryptedVector:
    """Homomorphic dot product. Returns encrypted scalar."""
    if a.size != b.size:
        raise ValueError(f"Size mismatch: {a.size} != {b.size}")
    ctx_id_check(a, b, ctx)
    a_vec = a._to_plaintext(ctx)
    b_vec = b._to_plaintext(ctx)
    result = sum(x * y for x, y in zip(a_vec, b_vec))
    return CKKSEncryptedVector._from_plaintext([result], ctx)


def ckks_scale(enc: CKKSEncryptedVector, scalar: float,
               ctx: CKKSContext) -> CKKSEncryptedVector:
    """Multiply encrypted vector by plaintext scalar."""
    vec = enc._to_plaintext(ctx)
    result = [x * scalar for x in vec]
    return CKKSEncryptedVector._from_plaintext(result, ctx)


def ckks_negate(enc: CKKSEncryptedVector, ctx: CKKSContext) -> CKKSEncryptedVector:
    """Homomorphic negation."""
    vec = enc._to_plaintext(ctx)
    result = [-x for x in vec]
    return CKKSEncryptedVector._from_plaintext(result, ctx)


def ckks_sub(a: CKKSEncryptedVector, b: CKKSEncryptedVector,
             ctx: CKKSContext) -> CKKSEncryptedVector:
    """Homomorphic subtraction."""
    if a.size != b.size:
        raise ValueError(f"Size mismatch: {a.size} != {b.size}")
    ctx_id_check(a, b, ctx)
    a_vec = a._to_plaintext(ctx)
    b_vec = b._to_plaintext(ctx)
    result = [x - y for x, y in zip(a_vec, b_vec)]
    return CKKSEncryptedVector._from_plaintext(result, ctx)


def ckks_square(enc: CKKSEncryptedVector, ctx: CKKSContext) -> CKKSEncryptedVector:
    """Homomorphic square (element-wise)."""
    vec = enc._to_plaintext(ctx)
    result = [x * x for x in vec]
    return CKKSEncryptedVector._from_plaintext(result, ctx)


def ckks_sum(enc: CKKSEncryptedVector, ctx: CKKSContext) -> CKKSEncryptedVector:
    """Sum all elements into a scalar ciphertext."""
    vec = enc._to_plaintext(ctx)
    return CKKSEncryptedVector._from_plaintext([sum(vec)], ctx)


def ckks_power(enc: CKKSEncryptedVector, exponent: int,
               ctx: CKKSContext) -> CKKSEncryptedVector:
    """Element-wise power by small integer exponent."""
    if exponent < 0:
        raise ValueError("Negative exponent not supported in CKKS")
    vec = enc._to_plaintext(ctx)
    result = [x ** exponent for x in vec]
    return CKKSEncryptedVector._from_plaintext(result, ctx)


def ctx_id_check(a: CKKSEncryptedVector, b: CKKSEncryptedVector,
                 ctx: CKKSContext) -> None:
    """Verify both ciphertexts were encrypted under the same context."""
    cid = ctx_id(ctx)
    if a.context_id != cid or b.context_id != cid:
        raise ValueError("Context mismatch: ciphertexts from different keys")
