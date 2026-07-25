"""
Agent tools for real-LLM LEASH experiments.

Provides five sandboxed tools that a software-engineering agent swarm would use,
plus an audit log that records every tool invocation with timestamps for
post-experiment analysis (especially zombie-window measurement).

Tools:
    1. read_file   — read a file from the sandbox
    2. write_file  — write / overwrite a file in the sandbox
    3. review_code — call an LLM to review a code snippet
    4. query_db    — execute a read-only SQL query against the sandbox DB
    5. run_command — run a whitelisted shell command inside the sandbox

Each tool can be used *raw* (no auth) or wrapped with LEASH authentication
via ``AgentToolkit.with_leash()``.
"""

import os
import sys
import time
import sqlite3
import subprocess
from dataclasses import dataclass, field
from typing import Optional, Callable

# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

@dataclass
class ToolCall:
    """Single audit-log entry."""
    timestamp: float
    agent_id: str
    tool_name: str
    args: dict
    success: bool
    auth_latency_ms: float  # 0.0 when auth is disabled
    tool_latency_ms: float
    total_latency_ms: float
    result_summary: str = ""
    error: str = ""


class AuditLog:
    """Append-only audit log for tool invocations."""

    def __init__(self):
        self.entries: list[ToolCall] = []

    def record(self, entry: ToolCall) -> None:
        self.entries.append(entry)

    def calls_after(self, t: float) -> list[ToolCall]:
        """Return all entries with timestamp > t."""
        return [e for e in self.entries if e.timestamp > t]

    def successful_calls_after(self, t: float) -> list[ToolCall]:
        """Return successful entries with timestamp > t."""
        return [e for e in self.entries if e.timestamp > t and e.success]

    def summary(self) -> dict:
        """Aggregate statistics."""
        if not self.entries:
            return {}
        total = len(self.entries)
        ok = sum(1 for e in self.entries if e.success)
        auth_lats = [e.auth_latency_ms for e in self.entries if e.auth_latency_ms > 0]
        tool_lats = [e.tool_latency_ms for e in self.entries if e.success]
        return {
            "total_calls": total,
            "successful": ok,
            "failed": total - ok,
            "auth_latency_mean_ms": sum(auth_lats) / len(auth_lats) if auth_lats else 0.0,
            "tool_latency_mean_ms": sum(tool_lats) / len(tool_lats) if tool_lats else 0.0,
        }

    def to_list(self) -> list[dict]:
        """Serialise for JSON export."""
        return [
            {
                "timestamp": e.timestamp,
                "agent_id": e.agent_id,
                "tool": e.tool_name,
                "success": e.success,
                "auth_latency_ms": round(e.auth_latency_ms, 4),
                "tool_latency_ms": round(e.tool_latency_ms, 4),
                "total_latency_ms": round(e.total_latency_ms, 4),
                "error": e.error,
            }
            for e in self.entries
        ]


# ---------------------------------------------------------------------------
# Whitelisted commands for run_command tool
# ---------------------------------------------------------------------------

ALLOWED_COMMANDS = {
    "py_compile",    # python -m py_compile <file>
    "grep",
    "wc",
    "cat",
    "head",
    "tail",
    "ls",
    "find",
    "python3",       # for syntax checking only
}


# ---------------------------------------------------------------------------
# Agent Toolkit
# ---------------------------------------------------------------------------

class AgentToolkit:
    """
    Five sandboxed tools for a software-engineering agent.

    Parameters
    ----------
    sandbox_root : str
        Path to the sandbox directory (from ``Sandbox``).
    db_path : str
        Path to the sandbox SQLite database.
    llm_fn : callable, optional
        ``llm_fn(prompt: str) -> str`` — calls the LLM.  When ``None``,
        ``review_code`` returns a placeholder.
    audit_log : AuditLog, optional
        Shared audit log; a new one is created if not provided.
    agent_id : str
        Identifier embedded in every audit-log entry.
    auth_fn : callable, optional
        ``auth_fn(agent_id, tool_name) -> bool`` — LEASH auth check.
        When ``None``, tools run without authentication.
    """

    def __init__(
        self,
        sandbox_root: str,
        db_path: str,
        llm_fn: Optional[Callable[[str], str]] = None,
        audit_log: Optional[AuditLog] = None,
        agent_id: str = "anonymous",
        auth_fn: Optional[Callable[[str, str], bool]] = None,
    ):
        self.sandbox_root = sandbox_root
        self.db_path = db_path
        self.llm_fn = llm_fn
        self.audit = audit_log or AuditLog()
        self.agent_id = agent_id
        self.auth_fn = auth_fn

    # -- internal helpers ---------------------------------------------------

    def _safe_path(self, filename: str) -> str:
        """Resolve *filename* inside the sandbox; reject traversal."""
        resolved = os.path.realpath(os.path.join(self.sandbox_root, filename))
        if not resolved.startswith(os.path.realpath(self.sandbox_root)):
            raise PermissionError(f"Path traversal blocked: {filename}")
        return resolved

    def _check_auth(self, tool_name: str) -> tuple[bool, float]:
        """Run auth_fn if configured.  Returns (allowed, latency_ms)."""
        if self.auth_fn is None:
            return True, 0.0
        t0 = time.perf_counter()
        allowed = self.auth_fn(self.agent_id, tool_name)
        elapsed = (time.perf_counter() - t0) * 1000
        return allowed, elapsed

    def _record(
        self, tool_name: str, args: dict, success: bool,
        auth_ms: float, tool_ms: float, total_ms: float,
        result_summary: str = "", error: str = "",
    ) -> None:
        self.audit.record(ToolCall(
            timestamp=time.time(),
            agent_id=self.agent_id,
            tool_name=tool_name,
            args=args,
            success=success,
            auth_latency_ms=auth_ms,
            tool_latency_ms=tool_ms,
            total_latency_ms=total_ms,
            result_summary=result_summary,
            error=error,
        ))

    # -- tools --------------------------------------------------------------

    def read_file(self, filename: str) -> str:
        """Read a file from the sandbox and return its contents."""
        t_total = time.perf_counter()
        allowed, auth_ms = self._check_auth("read_file")
        if not allowed:
            total_ms = (time.perf_counter() - t_total) * 1000
            self._record("read_file", {"filename": filename}, False,
                         auth_ms, 0.0, total_ms, error="LEASH auth denied")
            raise PermissionError(f"[LEASH] Agent {self.agent_id} denied: read_file({filename})")

        t_tool = time.perf_counter()
        path = self._safe_path(filename)
        with open(path, "r") as f:
            content = f.read()
        tool_ms = (time.perf_counter() - t_tool) * 1000
        total_ms = (time.perf_counter() - t_total) * 1000
        self._record("read_file", {"filename": filename}, True,
                     auth_ms, tool_ms, total_ms,
                     result_summary=f"{len(content)} chars")
        return content

    def write_file(self, filename: str, content: str) -> str:
        """Write content to a file in the sandbox."""
        t_total = time.perf_counter()
        allowed, auth_ms = self._check_auth("write_file")
        if not allowed:
            total_ms = (time.perf_counter() - t_total) * 1000
            self._record("write_file", {"filename": filename}, False,
                         auth_ms, 0.0, total_ms, error="LEASH auth denied")
            raise PermissionError(f"[LEASH] Agent {self.agent_id} denied: write_file({filename})")

        t_tool = time.perf_counter()
        path = self._safe_path(filename)
        with open(path, "w") as f:
            f.write(content)
        tool_ms = (time.perf_counter() - t_tool) * 1000
        total_ms = (time.perf_counter() - t_total) * 1000
        self._record("write_file", {"filename": filename}, True,
                     auth_ms, tool_ms, total_ms,
                     result_summary=f"wrote {len(content)} chars")
        return f"Wrote {len(content)} chars to {filename}"

    def review_code(self, code: str, instruction: str = "Review this code for security vulnerabilities.") -> str:
        """Send code to the LLM for review.  Falls back to a stub if no LLM configured."""
        t_total = time.perf_counter()
        allowed, auth_ms = self._check_auth("review_code")
        if not allowed:
            total_ms = (time.perf_counter() - t_total) * 1000
            self._record("review_code", {"instruction": instruction}, False,
                         auth_ms, 0.0, total_ms, error="LEASH auth denied")
            raise PermissionError(f"[LEASH] Agent {self.agent_id} denied: review_code")

        t_tool = time.perf_counter()
        prompt = f"{instruction}\n\n```python\n{code}\n```"
        if self.llm_fn is not None:
            result = self.llm_fn(prompt)
        else:
            result = "[LLM stub] No vulnerabilities found."
        tool_ms = (time.perf_counter() - t_tool) * 1000
        total_ms = (time.perf_counter() - t_total) * 1000
        self._record("review_code", {"instruction": instruction}, True,
                     auth_ms, tool_ms, total_ms,
                     result_summary=f"{len(result)} chars response")
        return result

    def query_db(self, sql: str) -> list[dict]:
        """Execute a read-only SQL query against the sandbox database."""
        t_total = time.perf_counter()
        allowed, auth_ms = self._check_auth("query_db")
        if not allowed:
            total_ms = (time.perf_counter() - t_total) * 1000
            self._record("query_db", {"sql": sql}, False,
                         auth_ms, 0.0, total_ms, error="LEASH auth denied")
            raise PermissionError(f"[LEASH] Agent {self.agent_id} denied: query_db")

        t_tool = time.perf_counter()
        # Enforce read-only: reject anything that isn't SELECT
        sql_upper = sql.strip().upper()
        if not sql_upper.startswith("SELECT"):
            tool_ms = (time.perf_counter() - t_tool) * 1000
            total_ms = (time.perf_counter() - t_total) * 1000
            self._record("query_db", {"sql": sql}, False,
                         auth_ms, tool_ms, total_ms,
                         error="Only SELECT queries allowed")
            return [{"error": "Only SELECT queries are allowed"}]

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(sql).fetchall()
            result = [dict(r) for r in rows]
        except sqlite3.Error as exc:
            result = [{"error": str(exc)}]
        finally:
            conn.close()
        tool_ms = (time.perf_counter() - t_tool) * 1000
        total_ms = (time.perf_counter() - t_total) * 1000
        self._record("query_db", {"sql": sql}, True,
                     auth_ms, tool_ms, total_ms,
                     result_summary=f"{len(result)} rows")
        return result

    def run_command(self, cmd: str) -> dict:
        """Run a whitelisted shell command inside the sandbox."""
        t_total = time.perf_counter()
        allowed, auth_ms = self._check_auth("run_command")
        if not allowed:
            total_ms = (time.perf_counter() - t_total) * 1000
            self._record("run_command", {"cmd": cmd}, False,
                         auth_ms, 0.0, total_ms, error="LEASH auth denied")
            raise PermissionError(f"[LEASH] Agent {self.agent_id} denied: run_command({cmd})")

        t_tool = time.perf_counter()
        # Whitelist check
        parts = cmd.strip().split()
        base_cmd = os.path.basename(parts[0]) if parts else ""
        if base_cmd not in ALLOWED_COMMANDS:
            tool_ms = (time.perf_counter() - t_tool) * 1000
            total_ms = (time.perf_counter() - t_total) * 1000
            self._record("run_command", {"cmd": cmd}, False,
                         auth_ms, tool_ms, total_ms,
                         error=f"Command not whitelisted: {base_cmd}")
            return {"error": f"Command not whitelisted: {base_cmd}", "returncode": -1}

        try:
            proc = subprocess.run(
                parts,
                capture_output=True, text=True, timeout=10,
                cwd=self.sandbox_root,
            )
            result = {
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "returncode": proc.returncode,
            }
        except subprocess.TimeoutExpired:
            result = {"error": "Command timed out (10s)", "returncode": -1}
        except Exception as exc:
            result = {"error": str(exc), "returncode": -1}

        tool_ms = (time.perf_counter() - t_tool) * 1000
        total_ms = (time.perf_counter() - t_total) * 1000
        self._record("run_command", {"cmd": cmd}, True,
                     auth_ms, tool_ms, total_ms,
                     result_summary=f"rc={result.get('returncode')}")
        return result

    # -- convenience --------------------------------------------------------

    def tool_names(self) -> list[str]:
        return ["read_file", "write_file", "review_code", "query_db", "run_command"]

    def get_tool(self, name: str) -> Callable:
        """Return the bound method for *name*."""
        return getattr(self, name)
