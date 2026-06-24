"""FastAPI REST API — health, diagnostics, tools, chat."""

from __future__ import annotations

import json
import logging

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from packetsniffer_mcp import __version__
from packetsniffer_mcp.config import get_llm_config
from packetsniffer_mcp.llm_client import LLMClient

logger = logging.getLogger(__name__)

app = FastAPI(
    title="PacketsnifferMcp",
    version=__version__,
    description="MCP server for local network packet capture and PCAP file analysis",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Health ──

@app.get("/health")
async def health():
    """Basic health check."""
    return {"status": "ok", "server": "packetsniffer-mcp", "version": __version__}


@app.get("/api/v1/diagnostics")
async def diagnostics():
    """Full system diagnostics — LLM, tools, system info."""
    llm_config = get_llm_config()
    client = LLMClient(llm_config)
    llm_health = await client.health()

    # Discover tools from the MCP singleton
    tool_names: list[str] = []
    try:
        from packetsniffer_mcp.mcp_instance import get_mcp
        mcp = get_mcp()
        tools_list = await mcp.list_tools()
        tool_names = [t.name for t in tools_list] if tools_list else []
    except Exception:
        pass

    return {
        "server": "packetsniffer-mcp",
        "version": __version__,
        "status": "ok",
        "llm": {
            "provider": llm_config.provider,
            "model": llm_config.model,
            "is_local": llm_config.is_local,
            **llm_health,
        },
        "tools": tool_names,
        "tool_count": len(tool_names),
    }


@app.get("/api/v1/tools")
async def list_tools():
    """List all registered MCP tools with their schemas."""
    try:
        from packetsniffer_mcp.mcp_instance import get_mcp
        mcp = get_mcp()
        tools = await mcp.list_tools()
        return {
            "success": True,
            "tools": [{"name": t.name, "description": t.description} for t in tools] if tools else [],
            "count": len(tools) if tools else 0,
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── Chat ──

class ChatRequest(BaseModel):
    prompt: str
    system: str | None = None
    history: list[dict[str, str]] = Field(default_factory=list)
    temperature: float = 0.7
    max_tokens: int = 2048
    provider: str | None = None
    model: str | None = None
    stream: bool = False


@app.post("/api/v1/chat")
async def chat(req: ChatRequest):
    """Chat with the configured LLM provider."""
    config = get_llm_config()
    if req.provider and req.provider != config.provider:
        from packetsniffer_mcp.config import LLMProvider, PRESETS  # noqa: I001
        preset = PRESETS.get(req.provider)
        if not preset:
            raise HTTPException(400, f"Unknown provider: {req.provider}")
        config = LLMProvider(
            provider=req.provider,
            base_url=preset.base_url,
            model=req.model or preset.model,
        )
    elif req.model:
        config = LLMProvider(provider=config.provider, base_url=config.base_url, model=req.model)

    client = LLMClient(config)

    if req.stream:
        async def _stream():
            async for token in client.chat_stream(
                req.prompt, system=req.system, history=req.history,
                temperature=req.temperature, max_tokens=req.max_tokens,
            ):
                yield f"data: {json.dumps({'token': token})}\n\n"
            yield "data: [DONE]\n\n"
        return StreamingResponse(_stream(), media_type="text/event-stream")

    result = await client.chat(
        req.prompt, system=req.system, history=req.history,
        temperature=req.temperature, max_tokens=req.max_tokens,
    )
    return result


@app.get("/api/v1/providers")
async def list_providers():
    """List available LLM providers with their presets."""
    from packetsniffer_mcp.config import PRESETS, detect_local_provider
    local = detect_local_provider()
    return {
        "providers": [
            {"name": k, "base_url": v.base_url, "model": v.model, "is_local": v.is_local}
            for k, v in PRESETS.items()
        ],
        "active": get_llm_config().provider,
        "local_detected": local.provider if local else None,
    }
