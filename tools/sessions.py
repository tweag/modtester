"""
Interactive Session Manager
Manages persistent, multi-turn sessions for tools that require back-and-forth
interaction: msfconsole, SSH shells, netcat, etc.

Architecture:
    - Each session spawns a process via pexpect
    - Commands sent over multiple HTTP calls
    - Output buffered and returned per-command
    - Sessions auto-expire after inactivity timeout
    - AI sees these as regular tools: session_create → session_exec → session_close
"""
import os
import re
import time
import uuid
import threading
from typing import Optional, Dict
from datetime import datetime, timedelta

import pexpect

from config import SESSIONS_DIR


# =============================================================================
# SESSION CLASS
# =============================================================================

class Session:
    """A single interactive process session."""

    def __init__(self, session_id: str, tool: str, command: str, prompt_pattern: str,
                 timeout: int = 30, startup_wait: int = 5):
        self.id = session_id
        self.tool = tool
        self.command = command
        self.prompt_pattern = prompt_pattern
        self.timeout = timeout
        self.created_at = datetime.now()
        self.last_activity = datetime.now()
        self.history = []
        self.process = None
        self.alive = False
        self._lock = threading.Lock()

        # Spawn the process
        try:
            self.process = pexpect.spawn(
                command,
                timeout=timeout,
                encoding="utf-8",
                maxread=65536,
                env=os.environ.copy(),
            )
            # Wait for initial prompt
            self.process.expect(prompt_pattern, timeout=startup_wait + 30)
            self.startup_output = self.process.before + self.process.after
            self.alive = True
        except pexpect.TIMEOUT:
            # Process started but prompt not detected — still usable
            self.startup_output = self.process.before if self.process else ""
            self.alive = True
        except pexpect.EOF:
            self.startup_output = self.process.before if self.process else ""
            self.alive = False
        except Exception as e:
            self.startup_output = f"Error spawning {tool}: {e}"
            self.alive = False

    def execute(self, command: str, timeout: Optional[int] = None) -> str:
        """Send a command and return output up to the next prompt."""
        if not self.alive or not self.process or not self.process.isalive():
            self.alive = False
            return "Error: Session is not active."

        wait = timeout or self.timeout

        with self._lock:
            try:
                self.process.sendline(command)
                self.process.expect(self.prompt_pattern, timeout=wait)
                output = self.process.before

                # Clean up: remove the echoed command from output
                lines = output.split("\n")
                if lines and command.strip() in lines[0]:
                    lines = lines[1:]
                output = "\n".join(lines).strip()

                self.last_activity = datetime.now()
                self.history.append({
                    "timestamp": datetime.now().isoformat(),
                    "command": command,
                    "output": output[:10000],  # Cap stored output
                })
                return output

            except pexpect.TIMEOUT:
                # Grab whatever output is available
                output = self.process.before.strip() if self.process.before else ""
                self.last_activity = datetime.now()
                self.history.append({
                    "timestamp": datetime.now().isoformat(),
                    "command": command,
                    "output": f"(timeout after {wait}s)\n{output}"[:10000],
                })
                return f"{output}\n\n[Command timed out after {wait}s — output may be incomplete. Send another command or increase timeout.]"

            except pexpect.EOF:
                self.alive = False
                output = self.process.before.strip() if self.process.before else ""
                return f"{output}\n\n[Session ended — process exited.]"

            except Exception as e:
                return f"Error executing command: {e}"

    def read_output(self) -> str:
        """Read any pending output without sending a command."""
        if not self.alive or not self.process:
            return "Session is not active."

        with self._lock:
            try:
                # Non-blocking read
                self.process.expect(self.prompt_pattern, timeout=2)
                return self.process.before.strip()
            except pexpect.TIMEOUT:
                return self.process.before.strip() if self.process.before else "(no new output)"
            except pexpect.EOF:
                self.alive = False
                return self.process.before.strip() if self.process.before else "(session ended)"

    def close(self) -> str:
        """Terminate the session."""
        if self.process and self.process.isalive():
            try:
                self.process.sendline("exit")
                time.sleep(1)
                if self.process.isalive():
                    self.process.terminate(force=True)
            except Exception:
                pass
        self.alive = False
        return f"Session {self.id} ({self.tool}) closed. Commands executed: {len(self.history)}"

    def status(self) -> dict:
        """Return session status."""
        return {
            "id": self.id,
            "tool": self.tool,
            "alive": self.alive and (self.process.isalive() if self.process else False),
            "created_at": self.created_at.isoformat(),
            "last_activity": self.last_activity.isoformat(),
            "commands_executed": len(self.history),
            "uptime_seconds": int((datetime.now() - self.created_at).total_seconds()),
        }


# =============================================================================
# SESSION MANAGER
# =============================================================================

# Pre-configured session templates
SESSION_TEMPLATES = {
    "msfconsole": {
        "command": "msfconsole -q",
        "prompt": r"msf[0-9]?\s*[\(>]|msf\d?\s*>",
        "timeout": 60,
        "startup_wait": 15,
    },
    "bash": {
        "command": "/bin/bash --norc --noprofile",
        "prompt": r"[\$#]\s*$",
        "timeout": 30,
        "startup_wait": 2,
    },
    "ssh": {
        # command is built dynamically in session_create
        "command": None,
        "prompt": r"[\$#>]\s*$",
        "timeout": 30,
        "startup_wait": 5,
    },
    "mysql": {
        "command": None,
        "prompt": r"mysql>|MariaDB\s*\[",
        "timeout": 15,
        "startup_wait": 3,
    },
    "python": {
        "command": "python3 -i",
        "prompt": r">>>",
        "timeout": 15,
        "startup_wait": 2,
    },
    "custom": {
        "command": None,
        "prompt": r"[\$#>]\s*$",
        "timeout": 30,
        "startup_wait": 5,
    },
}


class SessionManager:
    """Manages all active sessions with auto-cleanup."""

    MAX_SESSIONS = 10
    IDLE_TIMEOUT_MINUTES = 30

    def __init__(self):
        self._sessions: Dict[str, Session] = {}
        self._lock = threading.Lock()

        # Start cleanup thread
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()

    def create(self, tool: str, command: Optional[str] = None,
               prompt_pattern: Optional[str] = None,
               timeout: Optional[int] = None) -> dict:
        """Create a new interactive session."""

        # Enforce session limit
        self._prune_dead()
        if len(self._sessions) >= self.MAX_SESSIONS:
            return {"error": f"Maximum {self.MAX_SESSIONS} concurrent sessions. Close one first.",
                    "active_sessions": self.list_all()}

        template = SESSION_TEMPLATES.get(tool, SESSION_TEMPLATES["custom"])

        # Build command
        cmd = command or template["command"]
        if not cmd:
            return {"error": f"No command specified. For '{tool}', provide a command parameter."}

        prompt = prompt_pattern or template["prompt"]
        wait = timeout or template["timeout"]
        startup = template.get("startup_wait", 5)

        session_id = str(uuid.uuid4())[:8]

        with self._lock:
            session = Session(
                session_id=session_id,
                tool=tool,
                command=cmd,
                prompt_pattern=prompt,
                timeout=wait,
                startup_wait=startup,
            )
            self._sessions[session_id] = session

        if not session.alive:
            return {
                "error": f"Failed to start {tool} session.",
                "details": session.startup_output,
            }

        return {
            "session_id": session_id,
            "tool": tool,
            "status": "active",
            "startup_output": session.startup_output[:3000],
            "hint": f"Use session_exec with session_id='{session_id}' to send commands.",
        }

    def execute(self, session_id: str, command: str, timeout: Optional[int] = None) -> dict:
        """Execute a command in an existing session."""
        session = self._sessions.get(session_id)
        if not session:
            return {"error": f"Session '{session_id}' not found.", "active_sessions": self.list_all()}

        output = session.execute(command, timeout)
        return {
            "session_id": session_id,
            "command": command,
            "output": output[:50000],  # Cap response size
            "alive": session.alive,
        }

    def read(self, session_id: str) -> dict:
        """Read pending output from a session."""
        session = self._sessions.get(session_id)
        if not session:
            return {"error": f"Session '{session_id}' not found."}

        output = session.read_output()
        return {
            "session_id": session_id,
            "output": output[:50000],
            "alive": session.alive,
        }

    def close(self, session_id: str) -> dict:
        """Close a session."""
        session = self._sessions.get(session_id)
        if not session:
            return {"error": f"Session '{session_id}' not found."}

        result = session.close()
        with self._lock:
            del self._sessions[session_id]

        return {"result": result}

    def get_status(self, session_id: str) -> dict:
        """Get status of a specific session."""
        session = self._sessions.get(session_id)
        if not session:
            return {"error": f"Session '{session_id}' not found."}
        return session.status()

    def list_all(self) -> list:
        """List all active sessions."""
        self._prune_dead()
        return [s.status() for s in self._sessions.values()]

    def get_history(self, session_id: str) -> dict:
        """Get command history for a session."""
        session = self._sessions.get(session_id)
        if not session:
            return {"error": f"Session '{session_id}' not found."}
        return {
            "session_id": session_id,
            "tool": session.tool,
            "history": session.history[-50:],  # Last 50 commands
        }

    def _prune_dead(self):
        """Remove dead sessions."""
        with self._lock:
            dead = [sid for sid, s in self._sessions.items()
                    if not s.alive or (s.process and not s.process.isalive())]
            for sid in dead:
                self._sessions[sid].close()
                del self._sessions[sid]

    def _cleanup_loop(self):
        """Background thread: close idle sessions."""
        while True:
            time.sleep(60)
            cutoff = datetime.now() - timedelta(minutes=self.IDLE_TIMEOUT_MINUTES)
            with self._lock:
                expired = [sid for sid, s in self._sessions.items()
                           if s.last_activity < cutoff]
                for sid in expired:
                    self._sessions[sid].close()
                    del self._sessions[sid]


# =============================================================================
# TOOL FUNCTIONS (called by AI via tool registry)
# =============================================================================

# Global session manager instance
_manager = SessionManager()


def session_create(
    tool: str = "bash",
    command: Optional[str] = None,
    timeout: Optional[int] = None,
) -> str:
    """
    Start an interactive session with a tool.

    Args:
        tool: Session type — msfconsole, bash, ssh, mysql, python, custom
        command: Command to spawn. Required for ssh/mysql/custom.
                 Examples:
                   ssh: "sshpass -p 'password' ssh -o StrictHostKeyChecking=no user@target"
                   mysql: "mysql -h target -u root -ppassword"
                   custom: any command that gives an interactive prompt
        timeout: Seconds to wait for command output (default varies by tool)

    Returns:
        Session ID and startup output. Use session_exec to send commands.
    """
    result = _manager.create(tool=tool, command=command, timeout=timeout)
    if "error" in result:
        return f"Error: {result['error']}\n{result.get('details', '')}"

    output = f"Session started: {result['session_id']} ({tool})\n"
    if result.get("startup_output"):
        output += f"\n{result['startup_output']}\n"
    output += f"\nUse session_exec with session_id='{result['session_id']}' to send commands."
    return output


def session_exec(
    session_id: str,
    command: str,
    timeout: Optional[int] = None,
) -> str:
    """
    Send a command to an active session and get the output.

    Args:
        session_id: Session ID from session_create
        command: Command to execute in the session
        timeout: Seconds to wait for output (default: session's configured timeout)

    Returns:
        Command output from the session
    """
    result = _manager.execute(session_id=session_id, command=command, timeout=timeout)
    if "error" in result:
        return f"Error: {result['error']}"

    output = result.get("output", "")
    if not result.get("alive", True):
        output += "\n\n[Session has ended.]"
    return output


def session_read(session_id: str) -> str:
    """
    Read any pending output from a session without sending a command.

    Args:
        session_id: Session ID from session_create

    Returns:
        Any pending output
    """
    result = _manager.read(session_id=session_id)
    if "error" in result:
        return f"Error: {result['error']}"
    return result.get("output", "(no output)")


def session_close(session_id: str) -> str:
    """
    Close an interactive session and terminate its process.

    Args:
        session_id: Session ID to close

    Returns:
        Confirmation message
    """
    result = _manager.close(session_id=session_id)
    if "error" in result:
        return f"Error: {result['error']}"
    return result.get("result", "Session closed.")


def session_list() -> str:
    """
    List all active interactive sessions.

    Returns:
        List of active sessions with status
    """
    sessions = _manager.list_all()
    if not sessions:
        return "No active sessions."

    lines = [f"Active sessions ({len(sessions)}):\n"]
    for s in sessions:
        alive_str = "ACTIVE" if s["alive"] else "DEAD"
        lines.append(
            f"  [{alive_str}] {s['id']} — {s['tool']} "
            f"(commands: {s['commands_executed']}, "
            f"uptime: {s['uptime_seconds']}s)"
        )
    return "\n".join(lines)


def session_history(session_id: str) -> str:
    """
    Get command history for a session.

    Args:
        session_id: Session ID

    Returns:
        List of commands and their outputs
    """
    result = _manager.get_history(session_id=session_id)
    if "error" in result:
        return f"Error: {result['error']}"

    history = result.get("history", [])
    if not history:
        return f"No commands executed in session {session_id}."

    lines = [f"Session {session_id} ({result.get('tool', '?')}) — {len(history)} commands:\n"]
    for i, entry in enumerate(history, 1):
        cmd = entry.get("command", "")
        out = entry.get("output", "")
        # Truncate long outputs in history view
        if len(out) > 500:
            out = out[:500] + f"\n... ({len(out)} chars total)"
        lines.append(f"[{i}] $ {cmd}")
        lines.append(f"{out}\n")
    return "\n".join(lines)
