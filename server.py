"""
MCP Offensive Security Demo — Server
Auto-registers all tools from TOOL_REGISTRY and exposes them via MCP + REST.

Endpoints:
    GET  /health              → Server health
    GET  /tools               → Tool list (Bedrock/Ollama format)
    POST /mcp/v1/tools/{name} → Execute a tool
    GET  /sse                 → MCP SSE endpoint
"""
import os
from dotenv import load_dotenv
load_dotenv()

from contextlib import asynccontextmanager
from fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.responses import JSONResponse
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware

from tools import TOOL_REGISTRY, TOOL_FUNCTIONS, TOOL_CATEGORIES
from config import MCP_PORT, SYSTEM_PROMPT
from db import init_db
from chat_api import api_ai_chat, api_ai_cancel
from auth import api_login, api_logout, api_me

# =============================================================================
# FastMCP SETUP
# =============================================================================

mcp = FastMCP(
    name="security-tools",
    instructions=SYSTEM_PROMPT,
)

for tool_name, tool_info in TOOL_REGISTRY.items():
    fn = tool_info["fn"]
    desc = tool_info["description"]
    mcp.tool(name=tool_name, description=desc)(fn)

# =============================================================================
# REST API
# =============================================================================

async def health_check(request):
    return JSONResponse({"status": "healthy", "tools_available": len(TOOL_FUNCTIONS)})


async def get_tools_for_clients(request):
    """Return tools in Bedrock/Ollama format for the CLI client only.
    Requires auth — never exposes tool names to unauthenticated users."""
    from auth import require_auth
    if not require_auth(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    tools = []
    for name, info in TOOL_REGISTRY.items():
        tools.append({
            "name": name,
            "description": info["description"],
            "input_schema": info["schema"],
        })
    return JSONResponse(tools)


async def execute_tool(request):
    """Execute a tool via REST. Requires authentication."""
    from auth import require_auth
    if not require_auth(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    tool_name = request.path_params["tool_name"]
    if tool_name not in TOOL_FUNCTIONS:
        return JSONResponse({"error": f"Unknown tool: {tool_name}"}, status_code=404)

    try:
        body = await request.json()
    except Exception:
        body = {}

    fn = TOOL_FUNCTIONS[tool_name]
    try:
        result = fn(**body)
        return JSONResponse({"result": result})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


# =============================================================================
# ASSESSMENT / CHAT / REPORT ENDPOINTS
# =============================================================================

import db

async def api_assessments_list(request):
    status = request.query_params.get("status")
    return JSONResponse(db.assessment_list(status))

async def api_assessment_create(request):
    body = await request.json()
    name = body.get("name", "Unnamed Assessment")
    target = body.get("target", "")
    if not target:
        return JSONResponse({"error": "target is required"}, status_code=400)
    a = db.assessment_create(
        name=name,
        target=target,
        scope_type=body.get("scope_type", "web"),
        scope=body.get("scope"),
        roe=body.get("roe"),
    )
    return JSONResponse(a, status_code=201)

async def api_assessment_get(request):
    aid = request.path_params["id"]
    a = db.assessment_get(aid)
    if not a:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse(a)

async def api_assessment_update(request):
    aid = request.path_params["id"]
    body = await request.json()
    a = db.assessment_update(aid, **body)
    if not a:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse(a)

async def api_assessment_delete(request):
    aid = request.path_params["id"]
    db.assessment_delete(aid)
    return JSONResponse({"deleted": aid})

async def api_chat_list(request):
    aid = request.path_params["id"]
    limit = int(request.query_params.get("limit", "100"))
    return JSONResponse(db.chat_list(aid, limit=limit))

async def api_chat_send(request):
    aid = request.path_params["id"]
    body = await request.json()
    role = body.get("role", "user")
    content = body.get("content", "")
    if not content:
        return JSONResponse({"error": "content is required"}, status_code=400)
    msg = db.chat_add(aid, role, content, metadata=body.get("metadata"))
    return JSONResponse(msg, status_code=201)

async def api_reports_list(request):
    aid = request.path_params["id"]
    return JSONResponse(db.report_list(aid))

async def api_report_latest(request):
    aid = request.path_params["id"]
    r = db.report_get_latest(aid)
    if not r:
        return JSONResponse({"error": "no reports"}, status_code=404)
    return JSONResponse(r)


# =============================================================================
# APP ASSEMBLY
# =============================================================================

@asynccontextmanager
async def lifespan(app):
    # Initialize DynamoDB tables + seed data in background
    import asyncio
    seed = os.environ.get("SEED_DB", "true").lower() in ("1", "true", "yes")

    async def _init():
        try:
            loop = asyncio.get_event_loop()
            assessments = await loop.run_in_executor(None, lambda: init_db(seed=seed))
            print(f"[*] DynamoDB initialized — {len(assessments)} assessments")
        except Exception as e:
            print(f"[!] DynamoDB init failed (will retry on first request): {e}")

    asyncio.create_task(_init())
    yield

routes = [
    Route("/health", health_check),
    Route("/tools", get_tools_for_clients),
    Route("/mcp/v1/tools/{tool_name}", execute_tool, methods=["POST"]),
    # Auth
    Route("/api/auth/login", api_login, methods=["POST"]),
    Route("/api/auth/logout", api_logout, methods=["POST"]),
    Route("/api/auth/me", api_me, methods=["GET"]),
    # Assessment CRUD
    Route("/api/assessments", api_assessments_list, methods=["GET"]),
    Route("/api/assessments", api_assessment_create, methods=["POST"]),
    Route("/api/assessments/{id}", api_assessment_get, methods=["GET"]),
    Route("/api/assessments/{id}", api_assessment_update, methods=["PUT", "PATCH"]),
    Route("/api/assessments/{id}", api_assessment_delete, methods=["DELETE"]),
    # Chat
    Route("/api/assessments/{id}/chat", api_chat_list, methods=["GET"]),
    Route("/api/assessments/{id}/chat", api_chat_send, methods=["POST"]),
    # Reports
    Route("/api/assessments/{id}/reports", api_reports_list, methods=["GET"]),
    Route("/api/assessments/{id}/reports/latest", api_report_latest, methods=["GET"]),
    # AI Chat (SSE stream)
    Route("/api/assessments/{id}/ai/chat", api_ai_chat, methods=["POST"]),
    Route("/api/assessments/{id}/ai/cancel", api_ai_cancel, methods=["POST"]),
    # MCP SSE
    Mount("/mcp", app=mcp.http_app()),
]

middleware = [
    Middleware(CORSMiddleware,
              allow_origins=["http://localhost:4000", "http://127.0.0.1:4000", "http://localhost:3000"],
              allow_methods=["*"],
              allow_headers=["*"],
              allow_credentials=True),
]

app = Starlette(routes=routes, middleware=middleware, lifespan=lifespan)


if __name__ == "__main__":
    import uvicorn
    print(f"[*] MCP Security Server starting on port {MCP_PORT}")
    print(f"[*] {len(TOOL_REGISTRY)} tools registered")
    uvicorn.run(app, host="0.0.0.0", port=MCP_PORT)
