"""ABE (Attribute-Based Encryption) backend abstract interface."""
from __future__ import annotations

from abc import ABC, abstractmethod


class ABEBackend(ABC):
    """Abstract CP-ABE backend.

    Simulation (ABESimulationBackend) is the default on Windows.
    CharmBackend requires Linux + libpbc-dev + charm-crypto.
    """

    @abstractmethod
    def setup(self) -> None:
        """Generate master key and public parameters."""
        ...

    @abstractmethod
    def issue_key(self, agent_id: str, attributes: list[str],
                  epoch: int = 0) -> object:
        """Issue an attribute-bound private key to an agent."""
        ...

    @abstractmethod
    def encrypt(self, plaintext: str, policy: str) -> bytes:
        """Encrypt plaintext under a CP-ABE policy string."""
        ...

    @abstractmethod
    def decrypt(self, attrs_key: object, ciphertext: bytes) -> bytes | None:
        """Decrypt ciphertext. Returns None if attributes don't satisfy policy."""
        ...

    @abstractmethod
    def policy_satisfied(self, policy: str, attributes: list[str]) -> bool:
        """Check whether a set of attributes satisfies a CP-ABE policy."""
        ...


def create_abe_backend() -> ABEBackend:
    """Create the appropriate ABE backend for the current platform."""
    try:
        from .charm_backend import CharmBackend
        return CharmBackend()
    except ImportError:
        from .abe_simulation import ABESimulationBackend
        return ABESimulationBackend()
