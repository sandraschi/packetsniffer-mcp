"""SEP-1577 agentic workflow via client sampling."""

from __future__ import annotations

import logging

from fastmcp import Context

from packetsniffer_mcp.mcp_instance import mcp

logger = logging.getLogger(__name__)


@mcp.tool()
async def agentic_packetsniffer_mcp_workflow(
    workflow_prompt: str,
    available_tools: list[str] | None = None,
    max_iterations: int = 5,
    ctx: Context | None = None,
) -> dict:
    """Run a multi-step workflow using FastMCP sampling when the client supports it."""
    if not workflow_prompt.strip():
        return {
            "success": False,
            "message": "Operation failed",
            "error": "workflow_prompt is required",
            "sampling_used": False,
        }

    tools = available_tools or ["help", "status"]
    if ctx is not None and hasattr(ctx, "sample"):
        try:
            response = await ctx.sample(
                messages=[{"role": "user", "content": workflow_prompt}],
                tools=tools,
                max_tokens=2048,
            )
            return {
                "success": True,
                "message": "Agentic workflow completed via sampling",
                "sampling_used": True,
                "result": response,
            }
        except Exception as exc:
            logger.warning("Sampling failed: %s", exc)

    return {
        "success": True,
        "message": "Structured fallback - use a sampling-capable MCP host for full agentic loops",
        "sampling_used": False,
        "suggested_tools": tools,
        "workflow_prompt": workflow_prompt,
        "max_iterations": max_iterations,
    }
