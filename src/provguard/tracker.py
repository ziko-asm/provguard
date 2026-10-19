"""Records what entered the agent's context and traces values back to it.

Provenance is established by value matching: a tool-call argument is
attributed to every recorded segment that contains it as a whole token
sequence. This is deliberately a *positive* check. ProvGuard never tries to
decide whether text is malicious; it asks whether a trusted source supplied
the value. A value the model invented or paraphrased has no trusted source,
so rules that require one fail closed.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from .labels import Source, Trust


def normalize(text: str) -> str:
    """Case-fold and collapse whitespace so formatting does not hide a match."""
    return " ".join(str(text).casefold().split())


def to_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(value)


def iter_leaves(value: Any, path: str) -> Iterator[tuple[str, str]]:
    """Yield ``(path, text)`` for every scalar inside a tool-call argument."""
    if isinstance(value, dict):
        for key, item in value.items():
            yield from iter_leaves(item, f"{path}.{key}")
    elif isinstance(value, (list, tuple, set, frozenset)):
        for index, item in enumerate(value):
            yield from iter_leaves(item, f"{path}[{index}]")
    elif value is None or isinstance(value, bool):
        return
    else:
        yield path, str(value)


@dataclass(frozen=True)
class Segment:
    text: str
    source: Source
    normalized: str


@dataclass(frozen=True)
class Provenance:
    value: str
    sources: tuple[Source, ...]

    @property
    def trusted(self) -> bool:
        """True when at least one trusted source supplied the value."""
        return any(s.trust is Trust.TRUSTED for s in self.sources)

    @property
    def unknown(self) -> bool:
        return not self.sources


class ProvenanceTracker:
    def __init__(self) -> None:
        self._segments: list[Segment] = []

    def add(self, text: Any, source: Source) -> None:
        text = to_text(text)
        self._segments.append(Segment(text, source, normalize(text)))

    @property
    def segments(self) -> tuple[Segment, ...]:
        return tuple(self._segments)

    @property
    def tainted(self) -> bool:
        """True once any untrusted text has entered the context."""
        return any(s.source.trust is Trust.UNTRUSTED for s in self._segments)

    def untrusted_sources(self) -> tuple[Source, ...]:
        seen: dict[Source, None] = {}
        for segment in self._segments:
            if segment.source.trust is Trust.UNTRUSTED:
                seen.setdefault(segment.source)
        return tuple(seen)

    def trace(self, value: Any) -> Provenance:
        text = str(value)
        needle = normalize(text)
        if not needle:
            return Provenance(text, ())
        # Whole-token match: "5" must not be attributed to a segment containing "1500".
        pattern = re.compile(rf"(?<!\w){re.escape(needle)}(?!\w)")
        found: dict[Source, None] = {}
        for segment in self._segments:
            if pattern.search(segment.normalized):
                found.setdefault(segment.source)
        return Provenance(text, tuple(found))
