"""ABE simulation backend — wraps existing abe.py into the ABEBackend interface.

This is the default on Windows where charm-crypto is unavailable.
The enforcement logic (policy parsing, attribute matching) is identical
to the real CP-ABE; only the cryptographic layer is simulated via AES-GCM.
"""
from __future__ import annotations

from .abe_backend import ABEBackend
from .abe import (
    ABEMasterKey, ABEPublicKey, ABEAttributeKey, Ciphertext,
    abe_setup, abe_issue_key, abe_encrypt, abe_decrypt, policy_satisfied,
)


class ABESimulationBackend(ABEBackend):
    """CP-ABE simulation backend using AES-GCM + software policy checking."""

    def __init__(self) -> None:
        self._mk: ABEMasterKey | None = None
        self._pk: ABEPublicKey | None = None
        self._keys: dict[str, ABEAttributeKey] = {}

    def setup(self) -> None:
        mk, pk = abe_setup()
        self._mk = mk
        self._pk = pk

    def _ensure_setup(self) -> None:
        if self._mk is None or self._pk is None:
            self.setup()

    def issue_key(self, agent_id: str, attributes: list[str],
                  epoch: int = 0) -> ABEAttributeKey:
        self._ensure_setup()
        key = abe_issue_key(self._mk, agent_id, attributes, epoch)  # type: ignore[arg-type]
        self._keys[agent_id] = key
        return key

    def encrypt(self, plaintext: str, policy: str) -> bytes:
        self._ensure_setup()
        ct = abe_encrypt(self._pk, plaintext, policy)  # type: ignore[arg-type]
        return ct.to_bytes()

    def decrypt(self, attrs_key: object, ciphertext: bytes) -> bytes | None:
        if not isinstance(attrs_key, ABEAttributeKey):
            return None
        ct = Ciphertext.from_bytes(ciphertext)
        return abe_decrypt(attrs_key, ct)

    def policy_satisfied(self, policy: str, attributes: list[str]) -> bool:
        return policy_satisfied(policy, attributes)

    def get_public_key(self) -> ABEPublicKey | None:
        return self._pk

    def get_agent_key(self, agent_id: str) -> ABEAttributeKey | None:
        return self._keys.get(agent_id)
