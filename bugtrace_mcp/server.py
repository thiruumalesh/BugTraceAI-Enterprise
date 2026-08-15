import asyncio
import contextlib
import io

from mcp.server.fastmcp import FastMCP
from bugtrace.engine.scan_engine import ScanEngine

# Create MCP server
mcp = FastMCP("BugTraceAI")


@mcp.tool()
def hello() -> str:
    """Test tool."""
    return "BugTraceAI MCP Server is working!"


@mcp.tool()
async def bugtrace_scan(target: str) -> dict:
    """
    Run BugTraceAI scan against an authorized target.
    """

    engine = ScanEngine()

    # Prevent ScanEngine print() calls from breaking MCP JSON
    with contextlib.redirect_stdout(io.StringIO()):
        findings = await asyncio.to_thread(engine.run, target)

    return {
        "status": "completed",
        "target": target,
        "findings": findings,
    }


if __name__ == "__main__":
    mcp.run()
