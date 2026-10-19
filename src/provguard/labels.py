"""Trust labels attached to every piece of text an agent sees."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class Trust(IntEnum):
    UNTRUSTED = 0
    TRUSTED = 1


@dataclass(frozen=True)
class Source:
    """Where a piece of text came from.

    ``kind`` is ``"user"``, ``"system"`` or ``"tool"``; ``name`` identifies the
    tool for tool outputs.
    """

    kind: str
    name: str = ""
    trust: Trust = Trust.UNTRUSTED

    def __str__(self) -> str:
        return f"{self.kind}:{self.name}" if self.name else self.kind


USER = Source("user", trust=Trust.TRUSTED)
SYSTEM = Source("system", trust=Trust.TRUSTED)
