# t-airs/src/mcp_server_simple.py
import sqlite3
from mcp.server.mcpserver import MCPServer

mcp = MCPServer("sqlite-server")
DB_PATH = "/opt/t-airs/src/customers.db"

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

if __name__ == "__main__":
    mcp.run()