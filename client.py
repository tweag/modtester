#!/usr/bin/env python
"""
ModTester CLI Client
Penetration testing powered by LLM + MCP tools.

Usage:
    python client.py                    # Interactive mode
    python client.py "scan example.com" # Single query

Supports: AWS Bedrock (Claude) and Ollama-compatible APIs.
"""
import boto3
import httpx
import sys
import os
import json
import time
import threading
import argparse
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from botocore.config import Config

from tools.display import get_action_message
from config import (
    MCP_SERVER_URL,
    AI_BACKEND,
    AWS_REGION,
    BEDROCK_MODEL,
    BEDROCK_FALLBACK_MODELS,
    OLLAMA_URL,
    OLLAMA_MODEL,
    OLLAMA_API_KEY,
    OLLAMA_IS_CLOUD,
    SYSTEM_PROMPT,
    SHOW_TOOL_NAMES,
)

# =============================================================================
# TERMINAL COLORS
# =============================================================================

CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"
MAGENTA = "\033[35m"

# =============================================================================
# STATUS DISPLAY
# =============================================================================


class StatusLine:
    """Animated spinner showing what the AI is doing."""

    FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self, phase: str, message: str):
        self.phase = phase
        self.message = message
        self._running = False
        self._thread = None
        self._start_time = 0

    def start(self):
        self._running = True
        self._start_time = time.time()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=1)
        # Clear the spinner line
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()

    def _spin(self):
        i = 0
        while self._running:
            elapsed = time.time() - self._start_time
            frame = self.FRAMES[i % len(self.FRAMES)]
            phase_str = f"[{self.phase}] " if self.phase else ""
            line = f"\r  {CYAN}{frame} {phase_str}{self.message} [{elapsed:.0f}s]{RESET}"
            sys.stdout.write(line)
            sys.stdout.flush()
            time.sleep(0.1)
            i += 1


def print_status(phase: str, message: str, result: str = ""):
    p = f"{CYAN}[{phase}]{RESET}" if phase else f"{CYAN}•{RESET}"
    if result:
        print(f"  {p} {message} {DIM}→ {result}{RESET}", flush=True)
    else:
        print(f"  {p} {message}", flush=True)


# =============================================================================
# MCP TOOL CALLING
# =============================================================================


def call_mcp_tool(tool_name: str, arguments: dict) -> str:
    """Call an MCP tool on the server and return the result as text."""
    url = f"{MCP_SERVER_URL}/mcp/v1/tools/{tool_name}"
    try:
        r = httpx.post(url, json=arguments, timeout=600.0)
        if r.status_code == 200:
            data = r.json()
            return data.get("result", json.dumps(data))
        return f"Error {r.status_code}: {r.text[:500]}"
    except httpx.TimeoutException:
        return f"Timeout calling {tool_name}"
    except Exception as e:
        return f"Error: {e}"


def get_tools_from_server() -> list:
    """Fetch tool definitions from server."""
    try:
        r = httpx.get(f"{MCP_SERVER_URL}/tools", timeout=10.0)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return []


# =============================================================================
# AI BACKENDS
# =============================================================================


def _format_tools_bedrock(tools: list) -> dict:
    """Convert server tools to Bedrock toolConfig format."""
    tool_specs = []
    for t in tools:
        tool_specs.append({
            "toolSpec": {
                "name": t["name"],
                "description": t["description"],
                "inputSchema": {"json": t["input_schema"]},
            }
        })
    return {"tools": tool_specs}


def _format_tools_ollama(tools: list) -> list:
    """Convert server tools to Ollama/OpenAI format."""
    result = []
    for t in tools:
        result.append({
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t["description"],
                "parameters": t["input_schema"],
            },
        })
    return result


def chat_bedrock(user_message: str, conversation: list, tools: list) -> tuple:
    """Send a message via AWS Bedrock and handle tool calls."""
    config = Config(region_name=AWS_REGION, retries={"max_attempts": 3, "mode": "adaptive"})
    client = boto3.client("bedrock-runtime", config=config)

    tc = _format_tools_bedrock(tools)
    system = [{"text": SYSTEM_PROMPT}]

    conversation.append({"role": "user", "content": [{"text": user_message}]})

    sl = StatusLine("THINKING", "Analyzing request...")
    sl.start()

    model = BEDROCK_MODEL
    try:
        resp = client.converse(
            modelId=model, system=system, messages=conversation,
            toolConfig=tc, inferenceConfig={"maxTokens": 8192},
        )
        sl.stop()
    except Exception as e:
        sl.stop()
        # Try fallbacks
        for fallback in BEDROCK_FALLBACK_MODELS:
            try:
                resp = client.converse(
                    modelId=fallback, system=system, messages=conversation,
                    toolConfig=tc, inferenceConfig={"maxTokens": 8192},
                )
                model = fallback
                break
            except Exception:
                continue
        else:
            return f"Error: {e}", conversation

    # Process response loop (handle tool use)
    while resp.get("stopReason") == "tool_use":
        am = resp["output"]["message"]
        conversation.append(am)

        # Print any text before tool calls
        for b in am["content"]:
            if "text" in b:
                t = b["text"].strip()
                if t:
                    print(f"\n{t}", flush=True)

        tr = []
        for b in am["content"]:
            if "toolUse" in b:
                tu = b["toolUse"]
                tn, ti, tid = tu["name"], tu["input"], tu["toolUseId"]

                # Display action message (never tool names)
                action_msg = get_action_message(tn, ti)
                print_status("", action_msg)
                sl = StatusLine("", action_msg)
                sl.start()

                result = call_mcp_tool(tn, ti)
                sl.stop()

                # Show truncated result
                rp = result[:3000]
                print(f"{DIM}{rp}{RESET}", flush=True)
                if len(result) > 3000:
                    print(f"{DIM}  ... ({len(result)} chars total){RESET}", flush=True)

                tr.append({"toolResult": {"toolUseId": tid, "content": [{"text": result}]}})

        conversation.append({"role": "user", "content": tr})

        sl = StatusLine("ANALYZING", "Processing results...")
        sl.start()
        try:
            resp = client.converse(
                modelId=model, system=system, messages=conversation,
                toolConfig=tc, inferenceConfig={"maxTokens": 8192},
            )
            sl.stop()
        except Exception as e:
            sl.stop()
            return f"Error during analysis: {e}", conversation

    # Extract final text
    fm = resp["output"]["message"]
    conversation.append(fm)
    rt = ""
    for b in fm["content"]:
        if "text" in b:
            rt += b["text"]
    return rt, conversation


def chat_ollama(user_message: str, conversation: list, tools: list) -> tuple:
    """Send a message via Ollama-compatible API and handle tool calls."""
    headers = {"Content-Type": "application/json"}
    if OLLAMA_API_KEY:
        headers["Authorization"] = f"Bearer {OLLAMA_API_KEY}"

    ollama_tools = _format_tools_ollama(tools)
    om = [{"role": "system", "content": SYSTEM_PROMPT}]

    # Convert conversation to Ollama format
    for msg in conversation:
        if msg["role"] == "user":
            text = ""
            for c in msg.get("content", []):
                if isinstance(c, dict) and "text" in c:
                    text += c["text"]
                elif isinstance(c, str):
                    text = c
            if text:
                om.append({"role": "user", "content": text})
        elif msg["role"] == "assistant":
            text = ""
            for c in msg.get("content", []):
                if isinstance(c, dict) and "text" in c:
                    text += c["text"]
                elif isinstance(c, str):
                    text = c
            if text:
                om.append({"role": "assistant", "content": text})

    om.append({"role": "user", "content": user_message})

    sl = StatusLine("THINKING", "Analyzing request...")
    sl.start()
    try:
        r = httpx.post(
            f"{OLLAMA_URL}/api/chat", headers=headers,
            json={"model": OLLAMA_MODEL, "messages": om, "tools": ollama_tools,
                  "stream": False, "options": {"temperature": 0.1}},
            timeout=600.0,
        )
        sl.stop()
        if r.status_code != 200:
            return f"Ollama error: {r.text}", conversation
        result = r.json()
        message = result.get("message", {})
    except Exception as e:
        sl.stop()
        return f"Error: {e}", conversation

    conversation.append({"role": "user", "content": [{"text": user_message}]})
    tc = message.get("tool_calls", [])

    while tc:
        trt = []
        for t in tc:
            fn = t.get("function", {})
            tn, ta = fn.get("name"), fn.get("arguments", {})

            action_msg = get_action_message(tn, ta)
            print_status("", action_msg)
            sl = StatusLine("", action_msg)
            sl.start()
            rt = call_mcp_tool(tn, ta)
            sl.stop()

            print(f"{DIM}{rt[:3000]}{RESET}", flush=True)
            trt.append(f"[{tn}]: {rt}")

        om.append({"role": "assistant", "content": message.get("content", "")})
        om.append({"role": "user", "content": "Tool results:\n" + "\n".join(trt)})

        sl = StatusLine("ANALYZING", "Processing results...")
        sl.start()
        try:
            r = httpx.post(
                f"{OLLAMA_URL}/api/chat", headers=headers,
                json={"model": OLLAMA_MODEL, "messages": om, "tools": ollama_tools,
                      "stream": False, "options": {"temperature": 0.1}},
                timeout=600.0,
            )
        except Exception:
            sl.stop()
            return "Ollama timed out.", conversation
        sl.stop()
        result = r.json()
        message = result.get("message", {})
        tc = message.get("tool_calls", [])

    ft = message.get("content", "")
    conversation.append({"role": "assistant", "content": [{"text": ft}]})
    return ft, conversation


# =============================================================================
# MAIN LOOP
# =============================================================================


def main():
    parser = argparse.ArgumentParser(description="MCP Offensive Security Demo")
    parser.add_argument("query", nargs="*", help="Single query to execute")
    args = parser.parse_args()

    # Check server
    try:
        r = httpx.get(f"{MCP_SERVER_URL}/health", timeout=5.0)
        if r.status_code != 200:
            print(f"{RED}Server not healthy at {MCP_SERVER_URL}{RESET}")
            sys.exit(1)
    except Exception:
        print(f"{RED}Cannot connect to server at {MCP_SERVER_URL}{RESET}")
        print(f"Start the server first: python server.py")
        sys.exit(1)

    tools = get_tools_from_server()
    if not tools:
        print(f"{RED}No tools loaded from server{RESET}")
        sys.exit(1)

    chat_fn = chat_bedrock if AI_BACKEND == "bedrock" else chat_ollama
    conversation = []

    print(f"\n{BOLD}ModTester{RESET}")
    print(f"{DIM}Backend: {AI_BACKEND.upper()} | Tools: {len(tools)} | Server: {MCP_SERVER_URL}{RESET}")
    print(f"{DIM}Type 'quit' to exit{RESET}\n")

    # Single query mode
    if args.query:
        query = " ".join(args.query)
        response, conversation = chat_fn(query, conversation, tools)
        print(f"\n{response}")
        return

    # Interactive mode
    while True:
        try:
            user_input = input(f"{GREEN}ModTester ▶{RESET} ").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{DIM}Goodbye.{RESET}")
            break

        if not user_input:
            continue
        if user_input.lower() in ("quit", "exit", "q"):
            print(f"{DIM}Goodbye.{RESET}")
            break
        if user_input.lower() == "clear":
            conversation = []
            print(f"{DIM}Conversation cleared.{RESET}")
            continue

        response, conversation = chat_fn(user_input, conversation, tools)
        print(f"\n{response}\n")


if __name__ == "__main__":
    main()
