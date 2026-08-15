"""BugTraceAI MCP server launcher."""

from bugtrace.mcp.app import mcp_server

# Import modules so their tools/resources are registered.
from bugtrace.mcp import tools  # noqa: F401
from bugtrace.mcp import resources  # noqa: F401
from bugtrace.mcp import explain  # noqa: F401


if _name_ == "_main_":
    mcp_server.run(transport="stdio")
