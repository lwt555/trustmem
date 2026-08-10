"""Charm-crypto CP-ABE backend — real bilinear-pairing ABE.

Requires Linux + libpbc-dev + charm-crypto. Graceful import error on Windows.
"""
from __future__ import annotations

from .abe_backend import ABEBackend


class CharmBackend(ABEBackend):
    """Real CP-ABE backend using charm-crypto + bswabe.

    Only importable on Linux with charm-crypto installed.
    """

    def __init__(self) -> None:
        try:
            from charm.toolbox.pairinggroup import PairingGroup, GT
            from charm.schemes.abenc import abenc_bsw07
            self._group = PairingGroup('SS512')
            self._abe = abenc_bsw07
            self._GT = GT
        except ImportError as e:
            raise ImportError(
                "charm-crypto not available. Install it on Linux:\n"
                "  sudo apt install libpbc-dev\n"
                "  pip install charm-crypto\n"
                "Or use ABESimulationBackend on Windows."
            ) from e

        self._mk: object | None = None
        self._pk: object | None = None

    def setup(self) -> None:
        self._mk, self._pk = self._abe.setup(self._group)

    def _ensure_setup(self) -> None:
        if self._mk is None or self._pk is None:
            self.setup()

    def issue_key(self, agent_id: str, attributes: list[str],
                  epoch: int = 0) -> object:
        self._ensure_setup()
        return self._abe.keygen(self._group, self._mk, attributes)  # type: ignore[arg-type]

    def encrypt(self, plaintext: str, policy: str) -> bytes:
        self._ensure_setup()
        msg = self._group.encode(plaintext.encode(), self._GT)
        ct = self._abe.encrypt(self._group, self._pk, msg, policy)  # type: ignore[arg-type]
        import pickle
        return pickle.dumps(ct)

    def decrypt(self, attrs_key: object, ciphertext: bytes) -> bytes | None:
        self._ensure_setup()
        import pickle
        try:
            ct = pickle.loads(ciphertext)
            msg = self._abe.decrypt(self._group, self._pk, attrs_key, ct)  # type: ignore[arg-type]
            decoded = self._group.decode(msg)
            return decoded if isinstance(decoded, bytes) else str(decoded).encode()
        except Exception:
            return None

    def policy_satisfied(self, policy: str, attributes: list[str]) -> bool:
        try:
            from charm.toolbox.secretutil import SecretUtil
            util = SecretUtil(self._group, verbose=False)
            parsed = util.createPolicy(policy)
            return util.prune(parsed, attributes)
        except Exception:
            return False
