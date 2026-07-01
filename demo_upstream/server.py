"""
Toy upstream 'MCP-style' tool server. Represents the real MCP servers that
sit behind the gateway (e.g. a filesystem server, an email server, a DB
query server). It has zero security of its own on purpose - it fully
trusts whatever the gateway forwards, exactly like a real MCP server would
trust its client. All the enforcement lives in the gateway in front of it.

Run standalone:  uvicorn demo_upstream.server:app --port 9000
"""
from fastapi import FastAPI
from pydantic import BaseModel
from typing import Any

app = FastAPI(title="Demo Upstream Tool Server")

_FAKE_FILES = {
    "/data/public/readme.txt": "Welcome to the public data share.",
    "/data/shared/quarterly_report.txt": "Q2 revenue: $4.2M (demo data).",
    "/data/private/secrets.txt": "AKIAIOSFODNN7EXAMPLE - do not read this",
}


class ToolInvocation(BaseModel):
    tool_name: str
    arguments: dict[str, Any] = {}


@app.get("/tools")
def list_tools():
    return {
        "tools": [
            {"name": "read_file", "description": "Read a file by path", "args": ["path"]},
            {"name": "send_email", "description": "Send an email", "args": ["to", "subject", "body"]},
            {"name": "run_query", "description": "Run a read-only SQL-like query", "args": ["query"]},
        ]
    }


@app.post("/invoke")
def invoke(call: ToolInvocation):
    if call.tool_name == "read_file":
        path = call.arguments.get("path", "")
        if path in _FAKE_FILES:
            return {"success": True, "result": _FAKE_FILES[path]}
        return {"success": False, "error": f"File not found: {path}"}

    if call.tool_name == "send_email":
        to = call.arguments.get("to")
        subject = call.arguments.get("subject")
        return {"success": True, "result": f"Email queued to {to} (subject={subject!r})"}

    if call.tool_name == "run_query":
        query = call.arguments.get("query", "")
        return {"success": True, "result": f"[demo] executed query: {query}", "rows": 0}

    return {"success": False, "error": f"Unknown tool: {call.tool_name}"}
