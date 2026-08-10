"""
Four-value access verdict: ALLOW / HIDE / CONFIRM / DENY.

ALLOW   — full read access, decrypt content
HIDE    — content hidden behind #var# handle, constrained queries allowed
CONFIRM — requires human-in-the-loop confirmation before access
DENY    — completely blocked, no access of any kind
"""
from __future__ import annotations

from enum import Enum


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    HIDE = "HIDE"
    CONFIRM = "CONFIRM"
    DENY = "DENY"

    @property
    def is_accessible(self) -> bool:
        """True if the subject can interact with the object in any form."""
        return self in (Verdict.ALLOW, Verdict.HIDE, Verdict.CONFIRM)

    @property
    def is_blocked(self) -> bool:
        """True if access is completely denied."""
        return self == Verdict.DENY

    @property
    def can_read_content(self) -> bool:
        """True if the full plaintext content is readable."""
        return self == Verdict.ALLOW
