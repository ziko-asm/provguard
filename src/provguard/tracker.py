"""Records what entered the agent's context and traces values back to it.

Provenance is established by value matching: a tool-call argument is
attributed to every recorded segment that contains it as a whole token
sequence. This is deliberately a *positive* check. ProvGuard never tries to
decide whether text is malicious; it asks whether a trusted source supplied
the value. A value the model invented or paraphrased has no trusted source,
so rules that require one fail closed.

Structured tool output (dicts and lists) vouches only for complete field
values. A trusted channel list can vouch for the channel ``general``, but not
for a URL that an outsider embedded inside a channel name. Free text, such as
the user's own request, vouches for any whole-token span within it.

Numbers are compared by value, so ``240``, ``240.0`` and ``240.00`` are the
same amount, and ``1,000`` is ``1000``. Nothing else is canonicalised: a
value the model rewrote in any other way has no trusted source and fails
closed.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any

from .labels import Source, Trust


def normalize(text: str) -> str:
    """Case-fold and collapse whitespace so formatting does not hide a match."""
    return " ".join(str(text).casefold().split())


_NUMBER = re.compile(r"^[-+]?(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?$")
_URL = re.compile(r"(?:https?://|www\.)[^\s<>\"'`()\[\]{}]+", re.IGNORECASE)


def numeric_variants(needle: str) -> frozenset[str]:
    """Spellings of the same number, so ``240`` matches a field holding ``240.0``.

    Returns just ``{needle}`` for anything that is not a plain decimal number.
    """
    if not _NUMBER.match(needle):
        return frozenset({needle})
    try:
        number = Decimal(needle.replace(",", ""))
    except InvalidOperation:  # pragma: no cover - the regex already rules this out
        return frozenset({needle})
    out = {needle}
    if number == number.to_integral_value():
        whole = int(number)
        out |= {str(whole), f"{whole:,}", f"{whole}.0", f"{whole}.00", f"{whole:,}.00"}
    else:
        plain = format(number.normalize(), "f")
        out |= {plain, f"{number:.2f}", f"{number:,.2f}"}
    return frozenset(out)


def find_urls(text: str) -> list[str]:
    """Links inside free text: ``http(s)://`` or ``www.`` forms, trailing punctuation stripped."""
    return [m.group(0).rstrip(".,;:!?") for m in _URL.finditer(str(text))]


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


def _field(path: str) -> str:
    """Last key of a leaf path: ``"[0].passport"`` -> ``"passport"``."""
    return re.sub(r"\[\d+\]$", "", path).rsplit(".", 1)[-1]


def fold_field(name: str) -> str:
    """A field name as a person writes it: case, spaces, underscores, hyphens.

    ``passport_number``, ``Passport Number`` and ``passport-number`` are the same
    field to everyone except a string comparison.
    """
    return " ".join(normalize(name).replace("_", " ").replace("-", " ").split())


@dataclass(frozen=True)
class Segment:
    text: str
    source: Source
    normalized: str
    # Set for structured output: the normalized leaf values, matched exactly.
    values: frozenset[str] | None = None
    # Normalized values that must not leave in outgoing text (secret sources only).
    secrets: frozenset[str] = frozenset()

    def contains(self, needles: frozenset[str], pattern: re.Pattern[str]) -> bool:
        if self.values is not None and self.source.trust is Trust.TRUSTED:
            return not needles.isdisjoint(self.values)
        # Untrusted text is searched loosely: attributing more to it never grants trust.
        return pattern.search(self.normalized) is not None


@dataclass(frozen=True)
class SecretReport:
    """What a declared ``secret: [field, ...]`` actually matched in one output.

    ``matched`` maps each declared name to the output field(s) it covers;
    ``unmatched`` lists names that cover nothing at all, which means the rule
    protects nothing.
    """

    declared: frozenset[str]
    matched: Mapping[str, tuple[str, ...]]
    seen: frozenset[str]

    @property
    def unmatched(self) -> frozenset[str]:
        return frozenset(self.declared - set(self.matched))

    @property
    def folded(self) -> dict[str, tuple[str, ...]]:
        """Declared names that only matched by spelling (``passport_number``)."""
        return {declared: fields for declared, fields in self.matched.items() if fields != (declared,)}


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

    def add(
        self,
        content: Any,
        source: Source,
        secret_fields: frozenset[str] | None = None,
    ) -> SecretReport | None:
        """Record ``content``. For a secret source, ``secret_fields`` limits which
        fields are confidential; ``None`` means all of them.

        Returns a :class:`SecretReport` when ``secret_fields`` was given, so the
        caller can see which declared field names the output did not have.
        """
        values = None
        secrets: frozenset[str] = frozenset()
        report: SecretReport | None = None
        text = to_text(content)
        if isinstance(content, (dict, list, tuple)):
            leaves = list(iter_leaves(content, ""))
            values = frozenset(normalize(v) for _, v in leaves)
            if source.secret:
                if secret_fields is None:
                    secrets = frozenset(normalize(v) for _, v in leaves)
                else:
                    # Only named fields can be declared, so a leaf with no key
                    # (an item of a plain list) names nothing.
                    seen = frozenset(field for field in (_field(path) for path, _ in leaves) if field)
                    matched: dict[str, tuple[str, ...]] = {}
                    for declared in sorted(secret_fields):
                        # Exact spelling first; the way a person writes the same
                        # name second, so passport_number still covers "Passport Number".
                        fields = tuple(sorted(f for f in seen if f == declared)) or tuple(
                            sorted(f for f in seen if fold_field(f) == fold_field(declared))
                        )
                        if fields:
                            matched[declared] = fields
                    protected = {field for fields in matched.values() for field in fields}
                    secrets = frozenset(
                        normalize(v) for path, v in leaves if _field(path) in protected
                    )
                    report = SecretReport(frozenset(secret_fields), matched, seen)
        elif source.secret:
            if secret_fields is None:
                secrets = frozenset({normalize(text)})
            else:
                # Field names on output that is not structured cannot match anything.
                report = SecretReport(frozenset(secret_fields), {}, frozenset())
        self._segments.append(Segment(text, source, normalize(text), values, secrets))
        return report

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
        needles = numeric_variants(needle)
        # Whole-token match: "5" must not be attributed to a segment containing "1500".
        alternatives = "|".join(re.escape(n) for n in sorted(needles, key=len, reverse=True))
        pattern = re.compile(rf"(?<![\w.,])(?:{alternatives})(?![\w]|[.,]\d)")
        found: dict[Source, None] = {}
        for segment in self._segments:
            if segment.contains(needles, pattern):
                found.setdefault(segment.source)
        return Provenance(text, tuple(found))

    def secrets_in(self, text: Any, min_length: int = 4) -> list[tuple[str, Source]]:
        """Confidential field values that occur inside ``text``.

        Only structured output from a ``secret`` source is considered, field by
        field, so a passport number or IBAN is caught but a whole document is
        not matched as one blob. A value the user typed themselves is theirs to
        send and is not reported.
        """
        haystack = normalize(to_text(text))
        if not haystack:
            return []
        typed = [s.normalized for s in self._segments if s.source.kind in ("user", "system")]
        hits: dict[str, Source] = {}
        for segment in self._segments:
            for value in segment.secrets:
                if len(value) < min_length or value in hits:
                    continue
                pattern = re.compile(rf"(?<!\w){re.escape(value)}(?!\w)")
                if pattern.search(haystack) and not any(pattern.search(t) for t in typed):
                    hits[value] = segment.source
        return sorted(hits.items())
