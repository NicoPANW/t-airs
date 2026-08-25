import sqlite3
import asyncio
from mcp.server import Server
from mcp.types import Tool, TextContent
import mcp.server.stdio

server = Server("sqlite-server")
DB_PATH = "/opt/t-airs/src/customers.db"

@server.list_tools()
async def handle_list_tools() -> list[Tool]:
    return [
        Tool(
            name="read_query",
            description="Execute a read-only SQL query (SELECT) on the database.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "The SQL query to run"}
                },
                "required": ["query"]
            }
        ),
        Tool(
            name="write_query",
            description="Execute a state-changing SQL query (INSERT, UPDATE, DELETE, CREATE) on the database.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "The SQL query to run"}
                },
                "required": ["query"]
            }
        )
    ]

@server.call_tool()
async def handle_call_tool(name: str, arguments: dict | None) -> list[TextContent]:
    if not arguments:
        return [TextContent(type="text", text="Error: missing arguments")]
    
    query = arguments.get("query", "")
    
    if name == "read_query":
        upper_query = query.upper()
        if any(keyword in upper_query for keyword in ["INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER"]):
            return [TextContent(type="text", text="Error: write operations not allowed via read_query")]
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(query)
            rows = cursor.fetchall()
            columns = [description[0] for description in cursor.description]
            conn.close()
            res = str([dict(zip(columns, row)) for row in rows])
            return [TextContent(type="text", text=res)]
        except Exception as e:
            return [TextContent(type="text", text=f"Error: {str(e)}")]
            
    elif name == "write_query":
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(query)
            conn.commit()
            changes = conn.total_changes
            conn.close()
            return [TextContent(type="text", text=f"Success: {changes} rows modified.")]
        except Exception as e:
            return [TextContent(type="text", text=f"Error: {str(e)}")]
    
    return [TextContent(type="text", text=f"Error: unknown tool {name}")]

async def main():
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )

if __name__ == "__main__":
    asyncio.run(main())