"""Dual transport + optional CodeMode (--agentic)."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os

logger = logging.getLogger(__name__)


def _parse_args(server_name: str) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=f"{server_name} - FastMCP 3.4")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--stdio", action="store_true", help="STDIO mode (default)")
    group.add_argument("--http", action="store_true", help="HTTP streamable mode")
    parser.add_argument("--host", default=os.getenv("MCP_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("MCP_PORT", "10920")))
    parser.add_argument("--path", default=os.getenv("MCP_PATH", "/mcp"))
    parser.add_argument(
        "--agentic",
        action="store_true",
        help="Enable CodeMode agentic discovery",
    )
    parser.add_argument("--debug", action="store_true")
    return parser.parse_args()


async def run_async(mcp_app, server_name: str) -> None:
    args = _parse_args(server_name)
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    agentic = args.agentic or os.getenv("MCP_AGENTIC", "").lower() in ("true", "1", "yes")
    if agentic:
        try:
            from fastmcp.experimental.transforms.code_mode import CodeMode

            CodeMode().attach(mcp_app)
            logger.info("CodeMode enabled")
        except ImportError as exc:
            logger.warning("CodeMode unavailable: %s", exc)

    if args.http:
        await mcp_app.run_http_async(
            host=args.host,
            port=args.port,
            path=args.path,
            show_banner=False,
        )
    else:
        await mcp_app.run_stdio_async(show_banner=False)


def run(mcp_app, server_name: str) -> None:
    asyncio.run(run_async(mcp_app, server_name))
