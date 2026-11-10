"""ProvGuard in front of any MCP server, with no code changes.

    provguard-mcp --policy policy.yaml -- npx -y @modelcontextprotocol/server-filesystem ~/docs

Put that command where your MCP client (Claude Desktop, Claude Code, Cursor...)
would normally start the server. The proxy speaks MCP over stdio on both
sides, forwards everything unchanged, and steps in at two points:

* ``tools/call`` from the client is checked against the policy first.
  ALLOW is forwarded. BLOCK is answered by the proxy with a tool error that
  explains why, so the model sees an ordinary failed call. CONFIRM asks the
  user through MCP elicitation when the client supports it, and is refused
  when it does not; the approved call is forwarded, nothing more. A
  ``tools/call`` sent as a notification (no id, so no reply is possible) is
  still checked, and refused rather than forwarded when the policy objects.
* every ``tools/call`` result is recorded with the trust label the policy
  gives that tool, so later calls are judged against it.

What an MCP server never sees is the user's own message, so values the user
typed cannot be recognised as trusted here. Supply them with ``--trust``
(repeatable) or ``--trust-file``, mark the tools that return the user's own
data as ``output: trusted``, or list fixed values under ``allow:``. Anything
else that a policy protects goes to the user for confirmation, or is refused.

One proxy guards one server: outputs of other servers in the same client are
not visible to it.
"""

from __future__ import annotations

import argparse
import itertools
import json
import subprocess
import sys
import threading
from pathlib import Path
from typing import IO, Any

from .audit import AuditLog
from .guard import Decision, Guard
from .policy import Action, Policy

APPROVE_SCHEMA = {
    "type": "object",
    "properties": {"approve": {"type": "boolean", "title": "Allow this tool call?"}},
    "required": ["approve"],
}


def _result_payload(result: Any) -> Any:
    """What the model actually reads from a tools/call result."""
    if not isinstance(result, dict):
        return result
    if result.get("structuredContent") is not None:
        return result["structuredContent"]
    texts = [c.get("text", "") for c in result.get("content") or [] if isinstance(c, dict) and c.get("type") == "text"]
    text = "\n".join(texts)
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError):
        return text
    return parsed if isinstance(parsed, (dict, list)) else text


def _denied(decision: Decision, note: str = "") -> dict:
    text = "Blocked by ProvGuard security policy. " + decision.explain() + (f"\n{note}" if note else "")
    return {"content": [{"type": "text", "text": text}], "isError": True}


class Proxy:
    def __init__(self, guard: Guard, client_out: IO[str], server_in: IO[str], log: IO[str] | None = None) -> None:
        self.guard = guard
        self.client_out = client_out
        self.server_in = server_in
        self.log = log
        self._client_lock = threading.Lock()
        self._server_lock = threading.Lock()
        self._state = threading.Lock()
        self.can_elicit = False
        self._calls: dict[Any, str] = {}             # request id -> tool name, awaiting result
        self._pending: dict[str, tuple[dict, Decision]] = {}  # our elicitation id -> held request
        self._ids = itertools.count(1)

    # ---- plumbing ---------------------------------------------------------

    def _send(self, out: IO[str], lock: threading.Lock, message: dict) -> None:
        line = json.dumps(message, ensure_ascii=False)
        with lock:
            out.write(line + "\n")
            out.flush()

    def to_client(self, message: dict) -> None:
        self._send(self.client_out, self._client_lock, message)

    def to_server(self, message: dict) -> None:
        self._send(self.server_in, self._server_lock, message)

    def _note(self, text: str) -> None:
        if self.log:
            print(f"[provguard] {text}", file=self.log, flush=True)

    # ---- client -> server -------------------------------------------------

    def from_client(self, message: dict) -> None:
        method = message.get("method")
        if method == "initialize":
            caps = (message.get("params") or {}).get("capabilities") or {}
            self.can_elicit = "elicitation" in caps
        elif method == "tools/call":
            # Every tools/call is checked, with or without an id: a notification
            # is still a call that runs the tool.
            self._tool_call(message)
            return
        elif method is None and str(message.get("id", "")) in self._pending:
            self._elicitation_answer(message)
            return
        self.to_server(message)

    def _tool_call(self, message: dict) -> None:
        params = message.get("params") or {}
        tool = str(params.get("name", ""))
        args = params.get("arguments") or {}
        decision = self.guard.check(tool, args)
        self._note(decision.explain())
        if decision.action is Action.ALLOW:
            self._forward_call(message, tool, decision)
        elif "id" not in message:
            # A notification cannot carry a refusal, and forwarding it unchecked
            # would be the bypass this proxy exists to prevent. Drop it, loudly.
            self._note(f"refused {tool}: a tools/call without an id cannot be answered")
        elif decision.action is Action.CONFIRM and self.can_elicit:
            eid = f"provguard-{next(self._ids)}"
            with self._state:
                self._pending[eid] = (message, decision)
            self.to_client({
                "jsonrpc": "2.0", "id": eid, "method": "elicitation/create",
                "params": {"message": "ProvGuard needs your approval.\n" + decision.explain(),
                           "requestedSchema": APPROVE_SCHEMA},
            })
        else:
            note = "" if decision.action is Action.BLOCK else "Confirmation needed, but this client cannot ask the user."
            self.to_client({"jsonrpc": "2.0", "id": message["id"], "result": _denied(decision, note)})

    def _forward_call(self, message: dict, tool: str, decision: Decision) -> None:
        if "id" in message:  # a notification has no result to record
            with self._state:
                self._calls[message["id"]] = tool
        self.guard.commit(decision)
        self.to_server(message)

    def _elicitation_answer(self, message: dict) -> None:
        with self._state:
            request, decision = self._pending.pop(str(message["id"]))
        result = message.get("result") or {}
        approved = result.get("action") == "accept" and (result.get("content") or {}).get("approve") is True
        self._note(f"user {'approved' if approved else 'declined'}: {decision.tool}")
        if approved:
            self._forward_call(request, decision.tool, decision)
        else:
            self.to_client({"jsonrpc": "2.0", "id": request["id"], "result": _denied(decision, "The user declined.")})

    # ---- server -> client -------------------------------------------------

    def from_server(self, message: dict) -> None:
        if "method" not in message and "id" in message:
            with self._state:
                tool = self._calls.pop(message["id"], None)
            if tool is not None and "result" in message:
                self.guard.record_result(tool, _result_payload(message["result"]))
                for warning in self.guard.take_warnings():
                    self._note(warning)
        self.to_client(message)


def _pump(source: IO[str], handle, on_bad) -> None:
    for line in source:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except ValueError:
            on_bad(line)
            continue
        if isinstance(message, dict):
            handle(message)
        else:
            on_bad(line)  # JSON-RPC batches are not part of current MCP


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="provguard-mcp", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--policy", required=True, type=Path, help="YAML policy file")
    parser.add_argument("--trust", action="append", default=[], help="text to treat as typed by the user")
    parser.add_argument("--trust-file", type=Path, help="file whose content is treated as typed by the user")
    parser.add_argument("--audit", type=Path, help="append decisions to this JSON Lines file")
    parser.add_argument("--quiet", action="store_true", help="do not log decisions to stderr")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="-- server command and arguments")
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("give the MCP server command after --")

    guard = Guard(Policy.from_yaml(args.policy), audit=AuditLog(args.audit) if args.audit else None)
    for text in args.trust:
        guard.user(text)
    if args.trust_file:
        guard.user(args.trust_file.read_text(encoding="utf-8"))

    server = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              text=True, encoding="utf-8", bufsize=1)
    assert server.stdin and server.stdout
    proxy = Proxy(guard, sys.stdout, server.stdin, None if args.quiet else sys.stderr)

    def bad(line: str) -> None:
        print(f"[provguard] ignoring non-JSON line: {line[:200]}", file=sys.stderr, flush=True)

    reader = threading.Thread(target=_pump, args=(server.stdout, proxy.from_server, bad), daemon=True)
    reader.start()
    try:
        _pump(sys.stdin, proxy.from_client, bad)
    finally:
        try:
            server.stdin.close()
        except OSError:
            pass
    try:
        server.wait(timeout=5)
    except subprocess.TimeoutExpired:
        server.terminate()
    reader.join(timeout=2)
    return server.returncode or 0


if __name__ == "__main__":
    sys.exit(main())
