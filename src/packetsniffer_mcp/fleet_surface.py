"""MCP prompts, skills resource, and prefab tools."""

from __future__ import annotations

import logging
from typing import Annotated

from pydantic import Field

logger = logging.getLogger(__name__)

SKILLS_MD = """# PacketsnifferMcp skills (fleet 2026)

## When to use
- Day-to-day operations via portmanteau tools
- Multi-step flows: prefer `agentic_packetsniffer_mcp_workflow` when sampling is available

## Workflows
1. **Health**: `packetsniffer-mcp_status_card` or `status`
2. **Discovery**: `help`
3. **Agentic**: `agentic_packetsniffer_mcp_workflow` for natural-language orchestration
"""


def register_fleet_surface(mcp) -> None:
    @mcp.prompt()
    def packetsniffer_mcp_session(goal: Annotated[str, Field(description="What to accomplish")] = "inspect") -> str:
        return (
            f"Using packetsniffer-mcp: {goal}. Start with status or prefab cards, "
            "then chain portmanteau tools. Use agentic workflow for multi-step tasks."
        )

    @mcp.resource("resource://packetsniffer-mcp/skills")
    def packetsniffer_mcp_skills() -> str:
        return SKILLS_MD

    @mcp.resource("resource://packetsniffer-mcp/capabilities")
    def packetsniffer_mcp_capabilities() -> str:
        return (
            "packetsniffer-mcp: FastMCP 3.4+, sampling (Ollama/LM Studio), "
            "agentic_packetsniffer_mcp_workflow, prefab cards, MCP prompts/skills. "
            "CodeMode: --agentic flag."
        )

    @mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False})
    async def packetsniffer_mcp_status_card():
        """Server health as a Prefab card."""
        from packetsniffer_mcp.prefabs import build_status_card
        from packetsniffer_mcp.tools.help_tools import status

        result = await status()
        payload = result if isinstance(result, dict) else {"message": str(result)}
        payload.setdefault("version", "0.1.0")
        return build_status_card(payload)

    logger.info("Fleet surface registered: prompts, skills, prefab")
