# t-airs/src/mcp_server_simple.py
import hmac
import os
import sqlite3
import uvicorn
from mcp.server.mcpserver import MCPServer

try:
    from mcp.server.transport_security import TransportSecuritySettings
    HAS_TRANSPORT_SECURITY = True
except ImportError:
    HAS_TRANSPORT_SECURITY = False

mcp = MCPServer("sqlite-server")

DB_PATH = os.getenv("MCP_DB_PATH", "/opt/t-airs/src/customers.db")
MCP_HOST = os.getenv("MCP_HOST", "0.0.0.0")
MCP_PORT = int(os.getenv("MCP_PORT", "8080"))
MCP_AUTH_TOKEN = os.getenv("MCP_AUTH_TOKEN", "").strip()


@mcp.tool()
def read_query(query: str) -> str:
    """Execute a read-only SQL query (SELECT) on the database."""
    upper_query = query.upper()
    if any(keyword in upper_query for keyword in ["INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER"]):
        return "Error: write operations not allowed via read_query"
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        columns = [description[0] for description in cursor.description]
        conn.close()
        return str([dict(zip(columns, row)) for row in rows])
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
def write_query(query: str) -> str:
    """Execute a state-changing SQL query (INSERT, UPDATE, DELETE, CREATE) on the database."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(query)
        conn.commit()
        changes = conn.total_changes
        conn.close()
        return f"Success: {changes} rows modified."
    except Exception as e:
        return f"Error: {str(e)}"


class BearerAuthASGIMiddleware:
    """Enforces Bearer token auth on /mcp while exposing /healthz for readiness checks."""

    def __init__(self, app, token: str):
        self.app = app
        self.token = token

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path == "/healthz":
            await send({
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/json")],
            })
            await send({
                "type": "http.response.body",
                "body": b'{"status":"ok","service":"t-airs-mcp"}',
            })
            return

        if self.token:
            headers = dict(scope.get("headers", []))
            auth_header = headers.get(b"authorization", b"").decode("utf-8", errors="ignore")
            expected = f"Bearer {self.token}"
            if not hmac.compare_digest(auth_header, expected):
                await send({
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [(b"content-type", b"application/json")],
                })
                await send({
                    "type": "http.response.body",
                    "body": b'{"error":"Unauthorized: invalid or missing Bearer token"}',
                })
                return

        await self.app(scope, receive, send)


def create_app():
    if HAS_TRANSPORT_SECURITY:
        # Disable strict loopback Host-header rejection so Prisma AIRS AI Gateway and VPC IPs can connect
        sec_settings = TransportSecuritySettings(enable_dns_rebinding_protection=False)
        base_app = mcp.streamable_http_app(transport_security=sec_settings)
    else:
        base_app = mcp.streamable_http_app()

    return BearerAuthASGIMiddleware(base_app, MCP_AUTH_TOKEN)


if __name__ == "__main__":
    auth_mode = "Bearer Token Enabled" if MCP_AUTH_TOKEN else "WARNING: No Auth Token Set"
    print(f"🚀 Starting T-AIRS Remote SQLite MCP Server on {MCP_HOST}:{MCP_PORT}/mcp ({auth_mode})", flush=True)
    uvicorn.run(create_app(), host=MCP_HOST, port=MCP_PORT)