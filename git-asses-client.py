import asyncio
import sys
import json
from typing import Optional, List, Dict, Any
from contextlib import AsyncExitStack

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()  # load environment variables from .env

class MCPClient:
    def __init__(self):
        # Initialize session and client objects
        self.session: Optional[ClientSession] = None
        self.exit_stack = AsyncExitStack()
        self.openai_client = OpenAI()
        self.available_tools: List[Dict[str, Any]] = []

    async def connect_to_server(self, server_script_path: str):
        """Connect to an MCP server

        Args:
            server_script_path: Path to the server script (.py or .js)
        """
        is_python = server_script_path.endswith('.py')
        is_js = server_script_path.endswith('.js')
        if not (is_python or is_js):
            raise ValueError("Server script must be a .py or .js file")

        command = "python" if is_python else "node"
        server_params = StdioServerParameters(
            command=command,
            args=[server_script_path],
            env=None
        )

        stdio_transport = await self.exit_stack.enter_async_context(stdio_client(server_params))
        self.stdio, self.write = stdio_transport
        self.session = await self.exit_stack.enter_async_context(ClientSession(self.stdio, self.write))

        await self.session.initialize()

        # List available tools and convert to OpenAI format
        response = await self.session.list_tools()
        tools = response.tools
        
        # Convert MCP tools to OpenAI function format
        self.available_tools = []
        for tool in tools:
            openai_tool = {
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.inputSchema
                }
            }
            self.available_tools.append(openai_tool)
        
        print(f"\nConnected to server with tools: {[tool.name for tool in tools]}")

    async def process_query(self, query: str) -> str:
        """Process a query using OpenAI and available tools"""
        messages = [
            {
                "role": "user",
                "content": query
            }
        ]

        final_text = []
        max_iterations = 5  # Prevent infinite loops
        iteration = 0

        while iteration < max_iterations:
            iteration += 1
            
            # Make OpenAI API call
            response = self.openai_client.chat.completions.create(
                model="gpt-4-turbo",
                messages=messages,
                tools=self.available_tools if self.available_tools else None,
                tool_choice="auto" if self.available_tools else None,
                temperature=0.3
            )

            message = response.choices[0].message
            
            # Add assistant message to conversation
            messages.append({
                "role": "assistant",
                "content": message.content,
                "tool_calls": message.tool_calls
            })

            # Handle text response
            if message.content:
                final_text.append(message.content)

            # Handle tool calls
            if message.tool_calls:
                for tool_call in message.tool_calls:
                    function_name = tool_call.function.name
                    function_args = json.loads(tool_call.function.arguments)
                    
                    try:
                        # Execute MCP tool call
                        result = await self.session.call_tool(function_name, function_args)
                        
                        final_text.append(f"[Calling tool {function_name} with args {function_args}]")
                        
                        # Add tool result to conversation
                        messages.append({
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "content": str(result.content)
                        })
                        
                    except Exception as e:
                        error_msg = f"Tool call failed: {str(e)}"
                        final_text.append(f"[Error: {error_msg}]")
                        
                        # Add error result to conversation
                        messages.append({
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "content": error_msg
                        })
                
                # Continue the conversation to get the final response
                continue
            else:
                # No more tool calls, we're done
                break

        return "\n".join(final_text)

    async def chat_loop(self):
        """Run an interactive chat loop"""
        print("\nMCP Client with OpenAI Started!")
        print("Type your queries or 'quit' to exit.")
        print("Available commands:")
        print("  - Your natural language queries")
        print("  - 'tools' to list available tools")
        print("  - 'quit' to exit")

        while True:
            try:
                query = input("\nQuery: ").strip()

                if query.lower() == 'quit':
                    break
                
                if query.lower() == 'tools':
                    if self.available_tools:
                        print("\nAvailable tools:")
                        for tool in self.available_tools:
                            func = tool["function"]
                            print(f"  - {func['name']}: {func['description']}")
                    else:
                        print("\nNo tools available")
                    continue

                if not query:
                    continue

                print("\n🤖 Processing...")
                response = await self.process_query(query)
                print(f"\n{response}")

            except KeyboardInterrupt:
                print("\n\nExiting...")
                break
            except Exception as e:
                print(f"\nError: {str(e)}")

    async def cleanup(self):
        """Clean up resources"""
        await self.exit_stack.aclose()

async def main():
    if len(sys.argv) < 2:
        print("Usage: python client.py <path_to_server_script>")
        print("Example: python client.py github_assessor_server.py")
        sys.exit(1)

    client = MCPClient()
    try:
        await client.connect_to_server(sys.argv[1])
        await client.chat_loop()
    finally:
        await client.cleanup()

if __name__ == "__main__":
    asyncio.run(main())
