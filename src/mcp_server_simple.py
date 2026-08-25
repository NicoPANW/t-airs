import sqlite3
import asyncio
from mcp.server import Server
from mcp.types import Tool, TextContent
import mcp.types as types
import mcp.server.stdio

server = Server("sqlite-server")
DB_PATH = "/opt/t-airs/src/customers.db"

@server.request_handler(types.ListToolsRequest)
async def handle_list_tools(request: types.ListToolsRequest) -> types.ListToolsResult:
    return types.ListToolsResult(
        tools=[
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
    )

@server.request_handler(types.CallToolRequest)
async def handle_call_tool(request: types.CallToolRequest) -> types.CallToolResult:
    name = request.params.name
    arguments = request.params.arguments

    if not arguments:
        return types.CallToolResult(
            content=[TextContent(type="text", text="Error: missing arguments")],
            isError=True
        )
    
    query = arguments.get("query", "")
    
    if name == "read_query":
        upper_query = query.upper()
        if any(keyword in upper_query for keyword in ["INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER"]):
            return types.CallToolResult(
                content=[TextContent(type="text", text="Error: write operations not allowed via read_query")],
                isError=True
            )
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(query)
            rows = cursor.fetchall()
            columns = [description[0] for description in cursor.description]
            conn.close()
            res = str([dict(zip(columns, row)) for row in rows])
            return types.CallToolResult(content=[TextContent(type="text", text=res)])
        except Exception as e:
            return types.CallToolResult(content=[TextContent(type="text", text=f"Error: {str(e)}")], isError=True)
            
    elif name == "write_query":
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(query)
            conn.commit()
            changes = conn.total_changes
            conn.close()
            return types.CallToolResult(content=[TextContent(type="text", text=f"Success: {changes} rows modified.")])
        except Exception as e:
            return types.CallToolResult(content=[TextContent(type="text", text=f"Error: {str(e)}")], isError=True)
    
    return types.CallToolResult(content=[TextContent(type="text", text=f"Error: unknown tool {name}")], isError=True)

async def main():
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )

if __name__ == "__main__":
    asyncio.run(main())