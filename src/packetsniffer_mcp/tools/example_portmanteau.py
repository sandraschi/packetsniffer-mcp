"""Example portmanteau tool — demonstrates the fleet 2026 pattern."""

from __future__ import annotations

import logging
from typing import Annotated, Literal

from pydantic import Field

from packetsniffer_mcp.mcp_instance import mcp  # noqa: F811  — replaced at scaffold time

logger = logging.getLogger(__name__)


@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False})
async def example_portmanteau(
    operation: Annotated[
        Literal["list", "get", "search"],
        Field(description="Operation to perform."),
    ],
    query: Annotated[str | None, Field(description="Search query for 'search' operation.")] = None,
    item_id: Annotated[str | None, Field(description="Item ID for 'get' operation.")] = None,
) -> dict:
    """Demonstrate the SOTA 2026 portmanteau pattern.

    [RATIONALE] Consolidates 3 related example operations into a single tool
    to demonstrate the fleet pattern without polluting the tool namespace.

    Operations:
    - list: Return example items.
    - get: Get a single example item by ID.
    - search: Search example items by query.

    ## Return Format
    {"success": bool, "operation": str, "data": [...]}

    ## Examples
    await example_portmanteau(operation="list")
    await example_portmanteau(operation="search", query="test")
    await example_portmanteau(operation="get", item_id="example-1")
    """
    if operation == "list":
        return {
            "success": True,
            "operation": "list",
            "data": [{"id": "example-1", "name": "First example"}],
        }
    if operation == "get":
        return {
            "success": True,
            "operation": "get",
            "data": {"id": item_id or "unknown", "name": "Example item"},
        }
    return {
        "success": True,
        "operation": "search",
        "data": [{"id": "example-1", "name": f"Result for: {query}"}],
    }
