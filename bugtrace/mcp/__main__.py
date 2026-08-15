"""BugTraceAI MCP server launcher."""

from bugtrace.mcp.app import mcp_server

from bugtrace.mcp import tools
from bugtrace.mcp import resources
from bugtrace.mcp import explain


if __name__ == "__main__":
    mcp_server.run(transport="stdio")
