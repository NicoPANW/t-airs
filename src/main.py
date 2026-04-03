import os
import argparse
import uvicorn
import json
import re
import requests
import torch
from contextlib import asynccontextmanager, AsyncExitStack

# FastAPI Imports for web server and UI rendering
from fastapi import FastAPI, Request, Form, Response
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

# 🌟 1. The Universal AI Gateway Client (Routes requests to LiteLLM)
from openai import AsyncOpenAI

# 🌟 2. MCP Imports (Model Context Protocol for direct Database Tool Calling)
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# 🌟 3. RAG Imports (Retrieval-Augmented Generation for Unstructured Data)
import chromadb
from sentence_transformers import SentenceTransformer
from rag_data import RAG_KNOWLEDGE_BASE

# Prisma AIRS Imports (Enterprise LLM Security Scanning)
import aisecurity
from aisecurity.generated_openapi_client.models.ai_profile import AiProfile
from aisecurity.scan.inline.scanner import Scanner
from aisecurity.scan.models.content import Content

# Local modules
import personas
from custom_tools import PERSONA_TOOLS

# --- CAPTURE CLI ARGUMENTS ---
# Allows dynamic configuration of the lab via startup script or terminal
parser = argparse.ArgumentParser(description="T-AIRS Red-Team Lab")
parser.add_argument("--airs-key", help="Prisma AIRS API Key", default=None)
parser.add_argument("--airs-profile", help="Prisma AIRS Security Profile", default="default")
parser.add_argument("--gateway-url", help="URL for LiteLLM Gateway", default="http://localhost:4000")
args, _ = parser.parse_known_args()

# Global configuration variables
AIRS_KEY = args.airs_key
AIRS_PROFILE_NAME = args.airs_profile
GATEWAY_URL = args.gateway_url

# Security state trackers
AIRS_CONFIGURED = False
airs_error_msg = "Not initialized"
ai_profile_obj = None

# App state variables
validated_models = []
PERSONAS = personas.PERSONAS

# Session management: Key is session_id, Value is a list of message dictionaries
SESSION_HISTORY = {}
MAX_HISTORY = 10

# --- CLIENT INITIALIZATION ---
# Point the standard OpenAI client at our local LiteLLM Gateway
# This allows us to use the standard OpenAI API format to talk to any open-source model
llm_client = AsyncOpenAI(base_url=f"{GATEWAY_URL}/v1", api_key="sk-t-airs-dummy-key")

# MCP State & Configuration
mcp_session = None
openai_tools = []
# Configure the stdio connection to the local SQLite database
server_params = StdioServerParameters(
    command="/opt/t-airs/venv/bin/mcp-server-sqlite",
    args=["--db-path", "/opt/t-airs/src/customers.db"]
)

# RAG Vector Database State
chroma_client = None
rag_collections = {}
embedder = None

# --- CORE LOGIC HELPERS ---

def check_gpu_status():
    """Interrogates the system for an NVIDIA GPU and its available VRAM using PyTorch."""
    try:
        if torch.cuda.is_available():
            gpu_name = torch.cuda.get_device_name(0)
            vram_gb = round(torch.cuda.get_device_properties(0).total_memory / (1024**3), 1)
            return f"✅ GPU ONLINE: {gpu_name} ({vram_gb} GB VRAM Ready)"
        else:
            return "⚠️ NO GPU DETECTED: Running on CPU (Local models will be severely degraded)"
    except Exception as e:
        return f"⚠️ GPU CHECK FAILED: {str(e)}"

def discover_gateway_models():
    """Queries the local LiteLLM Gateway REST API to discover all active routing models."""
    found = []
    try:
        response = requests.get(f"{GATEWAY_URL}/v1/models", timeout=5)
        if response.status_code == 200:
            for m in response.json().get("data", []):
                found.append(m["id"])
    except Exception as e:
        print(f"CRITICAL: Could not connect to AI Gateway. Is LiteLLM running? Error: {e}")
    found.sort()
    return found

def init_rag_pipeline():
    """
    Initializes the local ChromaDB Vector Database.
    Embeds the mock confidential company policies from rag_data.py into searchable vectors.
    """
    global chroma_client, rag_collections, embedder
    print("📚 Initializing Multi-Persona RAG Pipeline...")
    try:
        chroma_client = chromadb.Client()
        embedder = SentenceTransformer("all-MiniLM-L6-v2")

        # Loop through the dictionary imported from rag_data.py
        for persona_name, content in RAG_KNOWLEDGE_BASE.items():
            col = chroma_client.create_collection(name=f"rag_{persona_name}")
            
            # Simple chunking by newline for this lab environment
            chunks = [c for c in content.split('\n') if len(c.strip()) > 10]
            if chunks:
                embeddings = embedder.encode(chunks).tolist()
                col.add(
                    embeddings=embeddings,
                    documents=chunks,
                    ids=[f"{persona_name}_chunk_{i}" for i in range(len(chunks))]
                )
            rag_collections[persona_name] = col
            
        print("✅ RAG Ready: Loaded multiple personas into Vector DB.")
    except Exception as e:
        print(f"❌ RAG Initialization Failed: {e}")

def retrieve_rag_context(user_prompt: str, persona: str, top_k: int = 2):
    """
    Converts the user's prompt into a mathematical vector, searches ChromaDB for
    the most relevant policy chunks, and returns the formatted text.
    """
    target_collection = rag_collections.get(persona)
    if not target_collection:
        return "", [] # Return empty if no collection exists for this persona
    
    try:
        # Vectorize the user's input
        query_emb = embedder.encode([user_prompt]).tolist()
        # Query the database for the top 2 matching chunks
        results = target_collection.query(query_embeddings=query_emb, n_results=top_k)
        docs = results.get("documents", [[]])[0]
        
        if docs:
            # Wrap the retrieved data in a strict system warning block
            formatted_text = "\n[CONFIDENTIAL INTERNAL DATA RETRIEVED VIA RAG]:\n" + "\n".join(docs)
            return formatted_text, docs 
    except Exception as e:
        print(f"RAG Retrieval Error: {e}")
    
    return "", []

# --- APP LIFESPAN MANAGEMENT ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Executes background startup tasks before the web server begins accepting requests."""
    global AIRS_CONFIGURED, airs_error_msg, ai_profile_obj, validated_models, mcp_session, openai_tools
    print("\n" + "="*50)
    print("🚀 T-AIRS STARTUP (GATEWAY + MCP + RAG MODE)")
    print("="*50)
    print("Checking Hardware Acceleration...")
    print(f"RESULT: {check_gpu_status()}")
    print("-" * 50)
    
    # 1. Prisma AIRS Handshake
    # Authenticate with the enterprise security platform to pull policy rules
    if AIRS_KEY and AIRS_PROFILE_NAME:
        print(f"Handshaking with Prisma AIRS: {AIRS_PROFILE_NAME}...")
        try:
            aisecurity.init(api_key=AIRS_KEY)
            ai_profile_obj = AiProfile(profile_name=AIRS_PROFILE_NAME)
            # Perform a dummy scan to verify network connectivity and valid tokens
            Scanner().sync_scan(ai_profile=ai_profile_obj, content=Content(prompt="healthcheck"))
            AIRS_CONFIGURED = True
            airs_error_msg = "Connected"
            print("RESULT: ✅ AIRS ONLINE")
        except Exception as e:
            # Extract clean HTTP errors from the raw exception trace
            raw_error = str(e)
            match = re.search(r'HTTP response body: (\{.*\})', raw_error)
            airs_error_msg = match.group(1) if match else raw_error
            print(f"RESULT: ❌ AIRS FAILED - {airs_error_msg}")

    # 2. AI Gateway Discovery
    print("Performing Deep Model Discovery via AI Gateway...")
    validated_models = discover_gateway_models()
    print(f"RESULT: ✅ {len(validated_models)} routing models loaded.")
    
    # 3. RAG Initialization
    init_rag_pipeline()

    # 4. MCP Server Boot-Up
    # We use AsyncExitStack to keep the stdio child process alive for the duration of the server runtime
    async with AsyncExitStack() as stack:
        print("🔌 Booting SQLite MCP Server...")
        read, write = await stack.enter_async_context(stdio_client(server_params))
        mcp_session = await stack.enter_async_context(ClientSession(read, write))
        await mcp_session.initialize()
        
        # Interrogate the MCP Server for available database tools and format them into OpenAI JSON schemas
        mcp_tools = await mcp_session.list_tools()
        for t in mcp_tools.tools:
            openai_tools.append({
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.inputSchema
                }
            })
        print(f"RESULT: ✅ MCP ONLINE. Tools loaded: {[t.name for t in mcp_tools.tools]}")
        print("="*50 + "\n")
        
        yield # Yield control to FastAPI to start accepting web requests

app = FastAPI(lifespan=lifespan)
templates = Jinja2Templates(directory="templates")

# --- UI ENDPOINTS ---

@app.post("/update-persona")
async def update_persona(persona_id: str = Form(...), new_context: str = Form(...)):
    """Saves edits made in the UI sidebar back to the personas.py file permanently."""
    if persona_id in PERSONAS:
        PERSONAS[persona_id] = new_context
        try:
            with open("personas.py", "w") as f:
                f.write(f"PERSONAS = {repr(PERSONAS)}\n")
            return {"status": "success"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    return {"status": "not found"}

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Renders the main dashboard UI."""
    return templates.TemplateResponse(request=request, name="index.html")

@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return Response(content="", media_type="image/x-icon")

@app.get("/models")
async def list_models():
    """Returns the list of available AI models for the UI dropdown."""
    return {"models": validated_models}

@app.get("/health-airs")
async def health_airs():
    """Provides AIRS connection status to the UI for the health indicator bar."""
    return {"status": "connected" if AIRS_CONFIGURED else "disconnected", "profile": AIRS_PROFILE_NAME, "reason": airs_error_msg}

@app.get("/get-persona-context/{persona_id}")
async def get_persona_context(persona_id: str):
    """Fetches the raw system prompt text for the UI sidebar inspector."""
    return {"context": PERSONAS.get(persona_id, "Not found.")}

# --- THE CORE AI PIPELINE ---

@app.post("/chat")
async def chat(
    message: str = Form(...),
    persona: str = Form("banking"),
    session_id: str = Form("default-session"),
    airs_enabled: bool = Form(False),
    model_id: str = Form("none"),
    history_enabled: bool = Form(True)
):
    """
    The main Agentic loop. Handles scanning, RAG augmentation, inference, tool execution, and egress filtering.
    """
    selected_prompt = PERSONAS.get(persona, PERSONAS["banking"])
    security_status = "Bypassed"
    raw_sec_log = "{}"
    ingress_data = {}
    print(f"\n{'='*40}")
    print(f"📥 NEW REQUEST | Session: {session_id} | Persona: {persona}")
    print(f"💬 PROMPT: {message}")
    
    # Initialize the Trace Dictionary for the UI Observability Sidebar
    architecture_trace = {
        "ai_gateway": {"routed_to": model_id},
        "rag_pipeline": {"chunks_injected": []},
        "mcp_execution": []
    }
    
    if not model_id or model_id == "none":
        model_id = validated_models[0] if validated_models else None
        architecture_trace["ai_gateway"]["routed_to"] = model_id

    # Master Try/Except block to catch hallucinated JSON syntax from local models gracefully
    try:
        # --- 1. INGRESS SCAN ---
        # Scan the user's raw prompt for malicious intent before passing it to the LLM
        if AIRS_CONFIGURED and airs_enabled and ai_profile_obj:
            scan_response = Scanner().sync_scan(ai_profile=ai_profile_obj, content=Content(prompt=message))
            res_data = scan_response.to_dict()
            ingress_data = res_data[0] if isinstance(res_data, list) and len(res_data) > 0 else res_data
            
            # Immediately short-circuit the request if a policy violation is detected
            if str(ingress_data.get("action", "pass")).lower() == "block":
                block_txt = f"🛡️ Prisma AIRS Blocked Input: {ingress_data.get('category', 'Policy')} violation."
                return {"bot": block_txt, "output": block_txt, "logs": {"security_scan": "INGRESS BLOCK", "raw_response": json.dumps(ingress_data, indent=2), "trace": architecture_trace}}
            security_status = "Passed Input"
            raw_sec_log = json.dumps(ingress_data, indent=2)

        # --- 2. RAG CONTEXT RETRIEVAL ---
        # Inject private data into the prompt based on semantic similarity
        rag_context, raw_rag_docs = retrieve_rag_context(message, persona)
        architecture_trace["rag_pipeline"]["chunks_injected"] = raw_rag_docs
        system_instruction = f"{selected_prompt}\n{rag_context}"

        # --- 3. SESSION HISTORY & MESSAGE BUILDING ---
        if history_enabled:
            if session_id not in SESSION_HISTORY:
                SESSION_HISTORY[session_id] = []
            
            # Append current query to the rolling session log
            SESSION_HISTORY[session_id].append({"role": "user", "content": message})
            current_context = SESSION_HISTORY[session_id]
        else:
            # Stateless mode overrides history
            current_context = [{"role": "user", "content": message}]

        # Combine System Context + Chat History into the final payload array
        messages = [{"role": "system", "content": system_instruction}] + current_context

        # Merge core database tools with persona-specific attack surface tools
        active_tools = openai_tools.copy() if openai_tools else []
        if persona in PERSONA_TOOLS:
            active_tools.extend(PERSONA_TOOLS[persona])

        # --- 4. AI GATEWAY INFERENCE & TOOL CALLING ---
        # Send payload to LiteLLM for processing
        print(f"🚀 ROUTING TO MODEL: {model_id} via AI Gateway...")
        response = await llm_client.chat.completions.create(
            model=model_id,
            messages=messages,
            tools=active_tools if active_tools else None,
            temperature=0.7
        )
        
        # Extract the resolved model name if Auto-Routing was used
        actual_model = getattr(response, "model", model_id)
        if actual_model == "auto-router":
            actual_model = "gemini-2.5-flash-lite" 

        if model_id == "auto-router":
            architecture_trace["ai_gateway"]["routed_to"] = f"auto-router ➔ {actual_model}"
        else:
            architecture_trace["ai_gateway"]["routed_to"] = actual_model
        
        response_msg = response.choices[0].message

        # Detect if the LLM decided to execute an action instead of replying text
        if response_msg.tool_calls:
            # Echo the AI's tool request into the message chain so it has context
            messages.append(response_msg) 
            print(f"🛠️  MODEL REQUESTED TOOL: {tool_name}")
            print(f"📦 ARGUMENTS: {tool_args}")
            
            for tool_call in response_msg.tool_calls:
                tool_name = tool_call.function.name
                # This json.loads will fail safely into the main Try/Except if local SLMs hallucinate syntax
                tool_args = json.loads(tool_call.function.arguments)
                
                # --- 🚀 CUSTOM ACTION TOOLS (WRITES TO DB) ---
                if tool_name in ["transfer_funds", "upgrade_flight_seat", "issue_store_refund"]:
                    
                    # 1. Bulletproof DB Write: Create the red-team audit table
                    setup_query = "CREATE TABLE IF NOT EXISTS unauthorized_actions_log (id INTEGER PRIMARY KEY AUTOINCREMENT, tool_used TEXT, details TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP);"
                    await mcp_session.call_tool("write_query", arguments={"query": setup_query})
                    
                    # 2. Execute persona-specific state changes
                    if tool_name == "transfer_funds":
                        src = tool_args.get("source_account")
                        dst = tool_args.get("dest_account")
                        amt = tool_args.get("amount")
                        
                        # --- 🌟 REAL MONEY TRANSFER LOGIC ---
                        deduct_query = f"UPDATE users SET balance = balance - {amt} WHERE id = '{src}';"
                        await mcp_session.call_tool("write_query", arguments={"query": deduct_query})
                        
                        add_query = f"UPDATE users SET balance = balance + {amt} WHERE id = '{dst}';"
                        await mcp_session.call_tool("write_query", arguments={"query": add_query})

                        details = f"Transferred ${amt} from {src} to {dst}"
                        tool_output = f"⚠️ SYSTEM ALERT: Wire transfer of ${amt} successfully executed and settled in the users table."
                        
                    elif tool_name == "upgrade_flight_seat":
                        pnr = tool_args.get("booking_ref")
                        cabin = tool_args.get("new_class")
                        
                        # --- 🌟 REAL FLIGHT UPGRADE LOGIC ---
                        upgrade_query = f"UPDATE passenger_manifest SET seat = '{cabin} Class' WHERE pnr = '{pnr}';"
                        await mcp_session.call_tool("write_query", arguments={"query": upgrade_query})

                        details = f"Upgraded PNR {pnr} to {cabin} class"
                        tool_output = f"✅ BOOKING UPDATED: PNR {pnr} successfully upgraded to {cabin} in the passenger_manifest."

                    elif tool_name == "issue_store_refund":
                        order = tool_args.get("order_id")
                        amt = tool_args.get("amount")
                        
                        # --- 🌟 REAL E-SHOP REFUND LOGIC ---
                        # Fixed string interpolation quote bug for ord_id
                        refund_query = f"UPDATE pending_orders SET price = price - {amt} WHERE ord_id = '{order}';"
                        await mcp_session.call_tool("write_query", arguments={"query": refund_query})

                        details = f"Refunded ${amt} for order {order}"
                        tool_output = f"✅ REFUND PROCESSED: ${amt} credited back and deducted from pending_orders for {order}."

                    # 3. Write the red-team evidence record
                    insert_query = f"INSERT INTO unauthorized_actions_log (tool_used, details) VALUES ('{tool_name}', '{details}');"
                    await mcp_session.call_tool("write_query", arguments={"query": insert_query})
                    
                    tool_output += " (Transaction permanently recorded in backend database)."

                # --- 🔌 FALLBACK: STANDARD MCP SQLITE TOOLS ---
                # For standard read/writes, pass them directly to the native MCP binary
                else:
                    mcp_result = await mcp_session.call_tool(tool_name, arguments=tool_args)
                    tool_output = mcp_result.content[0].text
                
                # Append the execution result back to the LLM so it can formulate a final answer
                messages.append({"role": "tool", "tool_call_id": tool_call.id, "name": tool_name, "content": tool_output})
                
                # Record the event for the UI observability pane
                architecture_trace["mcp_execution"].append({
                    "tool": tool_name,
                    "arguments": tool_args,
                    "database_result": tool_output
                })

            # Fire a secondary inference request to let the AI summarize the database results
            final_response = await llm_client.chat.completions.create(
                model=model_id,
                messages=messages,
                temperature=0.7
            )
            bot_response = final_response.choices[0].message.content or ""
        else:
            # If no tools were called, just extract the generated text
            bot_response = response_msg.content or ""


        # --- 5. EGRESS SCAN ---
        # Scan the AI's final text for data exfiltration (like SSNs) before showing the user
        if AIRS_CONFIGURED and airs_enabled and ai_profile_obj and "Error:" not in bot_response:
            out_scan_response = Scanner().sync_scan(ai_profile=ai_profile_obj, content=Content(prompt=bot_response))
            out_res_data = out_scan_response.to_dict()
            out_data = out_res_data[0] if isinstance(out_res_data, list) and len(out_res_data) > 0 else out_res_data
            
            # Mask or block the output if PII/secrets were detected
            if str(out_data.get("action", "pass")).lower() == "block":
                block_txt = f"🛡️ Prisma AIRS Blocked Output: The LLM generated a {out_data.get('category', 'Policy')} violation."
                
                return {
                    "bot": block_txt, 
                    "output": block_txt, 
                    "logs": {
                        "security_scan": "EGRESS BLOCK", 
                        "raw_response": json.dumps(out_data, indent=2), 
                        "trace": architecture_trace,
                        "intercepted_text": bot_response  # Shows the attacker what was stopped
                    }
                }
            
            security_status = "Passed Input & Output"
            raw_sec_log = json.dumps({"input_scan": ingress_data, "output_scan": out_data}, indent=2)

        # --- 6. PERSIST HISTORY ---
        # Only record the assistant's reply if it wasn't blocked by the firewall
        if history_enabled:
            SESSION_HISTORY[session_id].append({"role": "assistant", "content": bot_response})
            # Prune old context to save tokens and VRAM
            if len(SESSION_HISTORY[session_id]) > 10:
                SESSION_HISTORY[session_id] = SESSION_HISTORY[session_id][-10:]

        # Return standard successful response
        print(f"🏁 REQUEST COMPLETE | Security Status: {security_status}")
        print(f"{'='*40}\n")
        return {"bot": bot_response, "output": bot_response, "logs": {"security_scan": security_status, "raw_response": raw_sec_log, "trace": architecture_trace}}

    # Catch-all for API timeouts, local LLM JSON hallucinations, and broken SQL queries
    except Exception as e:
        return {"bot": f"Error: {str(e)}", "output": f"Error: {str(e)}", "logs": {"security_scan": "Error", "raw_response": raw_sec_log, "trace": architecture_trace}}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
