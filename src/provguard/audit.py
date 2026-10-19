"""Append-only JSON Lines record of every decision, for review and incident response."""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .guard import Decision


class AuditLog:
    def __init__(self, path: str | Path, include_args: bool = False) -> None:
        # Arguments can hold personal data, so they are only logged on request.
        self.path = Path(path)
        self.include_args = include_args
        self._lock = threading.Lock()

    def write(self, decision: Decision, args: dict[str, Any]) -> None:
        record: dict[str, Any] = {
            "time": datetime.now(timezone.utc).isoformat(),
            "tool": decision.tool,
            "action": decision.action.name.lower(),
            "findings": [
                {"rule": f.rule, "action": f.action.name.lower(), "arg": f.arg, "message": f.message}
                for f in decision.findings
            ],
        }
        if self.include_args:
            record["args"] = args
        line = json.dumps(record, ensure_ascii=False, default=str)
        with self._lock, self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
