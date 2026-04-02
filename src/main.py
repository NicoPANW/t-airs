import os
import argparse
import uvicorn
import json
import re
import requests
from contextlib import asynccontextmanager, AsyncExitStack

# FastAPI Imports
from fastapi import FastAPI, Request, Form, Response
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

# 🌟 1. The Universal AI Gateway Client
from openai import AsyncOpenAI

# 🌟 2. MCP Imports (For Database Tool Calling)
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# 🌟 3. RAG Imports (For Unstructured Data)
import chromadb
from sentence_transformers import SentenceTransformer

# Prisma AIRS Imports
import aisecurity
from aisecurity.generated_openapi_client.models.ai_profile import AiProfile
from aisecurity.scan.inline.scanner import Scanner
from aisecurity.scan.models.content import Content

import personas

# --- CAPTURE CLI ARGUMENTS ---
parser = argparse.ArgumentParser(description="T-AIRS Red-Team Lab")
parser.add_argument("--airs-key", help="Prisma AIRS API Key", default=None)
parser.add_argument("--airs-profile", help="Prisma AIRS Security Profile", default="default")
parser.add_argument("--gateway-url", help="URL for LiteLLM Gateway", default="http://localhost:4000")
args, _ = parser.parse_known_args()

AIRS_KEY = args.airs_key
AIRS_PROFILE_NAME = args.airs_profile
GATEWAY_URL = args.gateway_url

AIRS_CONFIGURED = False
airs_error_msg = "Not initialized"

validated_models = []
ai_profile_obj = None
PERSONAS = personas.PERSONAS

# --- CLIENT INITIALIZATION ---
# Point the standard OpenAI client at our local LiteLLM Gateway
llm_client = AsyncOpenAI(base_url=f"{GATEWAY_URL}/v1", api_key="sk-t-airs-dummy-key")

# MCP State
mcp_session = None
openai_tools = []
server_params = StdioServerParameters(
    command="/opt/t-airs/venv/bin/mcp-server-sqlite",
    args=["--db-path", "/opt/t-airs/src/customers.db"]
)

# RAG State
chroma_client = None
rag_collection = None
embedder = None

# --- CORE LOGIC HELPERS ---

def discover_gateway_models():
    """Queries the local AI Gateway for all active routing models."""
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
    """Initializes the Vector DB and loads the mock confidential company policy."""
    global chroma_client, rag_collection, embedder
    print("📚 Initializing RAG Pipeline...")
    try:
        chroma_client = chromadb.Client()
        rag_collection = chroma_client.create_collection(name="internal_knowledge")
        embedder = SentenceTransformer("all-MiniLM-L6-v2")

        # Load the mock document created by our bootstrap script
        if os.path.exists("company_policy.txt"):
            with open("company_policy.txt", "r") as f:
                text = f.read()
            
            # Simple chunking by newline for this lab
            chunks = [c for c in text.split('\n') if c.strip()]
            embeddings = embedder.encode(chunks).tolist()
            
            rag_collection.add(
                embeddings=embeddings,
                documents=chunks,
                ids=[f"doc_{i}" for i in range(len(chunks))]
            )
            print(f"✅ RAG Ready: Loaded {len(chunks)} confidential chunks into Vector DB.")
        else:
            print("⚠️ RAG Warning: company_policy.txt not found. RAG will be empty.")
    except Exception as e:
        print(f"❌ RAG Initialization Failed: {e}")

def retrieve_rag_context(user_prompt: str, top_k: int = 2) -> str:
    """Converts user prompt to vector, searches DB, and returns matching context."""
    if not rag_collection:
        return ""
    
    try:
        query_emb = embedder.encode([user_prompt]).tolist()
        results = rag_collection.query(query_embeddings=query_emb, n_results=top_k)
        docs = results.get("documents", [[]])[0]
        
        if docs:
            # Format the retrieved text so the LLM knows it is secure internal context
            return "\n[CONFIDENTIAL INTERNAL DATA RETRIEVED VIA RAG]:\n" + "\n".join(docs)
    except Exception as e:
        print(f"RAG Retrieval Error: {e}")
    
    return ""


@asynccontextmanager
async def lifespan(app: FastAPI):
    global AIRS_CONFIGURED, airs_error_msg, ai_profile_obj, validated_models, mcp_session, openai_tools
    print("\n" + "="*50)
    print("🚀 T-AIRS STARTUP (GATEWAY + MCP + RAG MODE)")
    print("="*50)
    
    # 1. Prisma AIRS Handshake
    if AIRS_KEY and AIRS_PROFILE_NAME:
        print(f"Handshaking with Prisma AIRS: {AIRS_PROFILE_NAME}...")
        try:
            aisecurity.init(api_key=AIRS_KEY)
            ai_profile_obj = AiProfile(profile_name=AIRS_PROFILE_NAME)
            Scanner().sync_scan(ai_profile=ai_profile_obj, content=Content(prompt="healthcheck"))
            AIRS_CONFIGURED = True
            airs_error_msg = "Connected"
            print("RESULT: ✅ AIRS ONLINE")
        except Exception as e:
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
    # We use an AsyncExitStack to keep the stdio connection alive while the FastAPI server runs
    async with AsyncExitStack() as stack:
        print("🔌 Booting SQLite MCP Server...")
        read, write = await stack.enter_async_context(stdio_client(server_params))
        mcp_session = await stack.enter_async_context(ClientSession(read, write))
        await mcp_session.initialize()
        
        # Ask the SQLite MCP Server what it can do, and format it for the AI Gateway
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

# --- UI ROUTES ---

@app.post("/update-persona")
async def update_persona(persona_id: str = Form(...), new_context: str = Form(...)):
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
    return templates.TemplateResponse(request=request, name="index.html")

@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return Response(content="", media_type="image/x-icon")

@app.get("/models")
async def list_models():
    return {"models": validated_models}

@app.get("/health-airs")
async def health_airs():
    return {"status": "connected" if AIRS_CONFIGURED else "disconnected", "profile": AIRS_PROFILE_NAME, "reason": airs_error_msg}

@app.get("/get-persona-context/{persona_id}")
async def get_persona_context(persona_id: str):
    return {"context": PERSONAS.get(persona_id, "Not found.")}

# --- THE CORE AI PIPELINE ---

@app.post("/chat")
async def chat(
    message: str = Form(...),
    persona: str = Form("banking"),
    session_id: str = Form("default-session"),
    airs_enabled: bool = Form(False),
    model_id: str = Form("none")
):
    selected_prompt = PERSONAS.get(persona, PERSONAS["banking"])
    security_status = "Bypassed"
    raw_sec_log = "{}"
    ingress_data = {}
    
    if not model_id or model_id == "none":
        model_id = validated_models[0] if validated_models else None

    try:
        # =================================================================
        # STAGE 1: INGRESS SECURITY SCAN
        # Check if the user is attempting Prompt Injection before we do anything
        # =================================================================
        if AIRS_CONFIGURED and airs_enabled and ai_profile_obj:
            scan_response = Scanner().sync_scan(ai_profile=ai_profile_obj, content=Content(prompt=message))
            res_data = scan_response.to_dict()
            ingress_data = res_data[0] if isinstance(res_data, list) and len(res_data) > 0 else res_data
            
            if str(ingress_data.get("action", "pass")).lower() == "block":
                block_txt = f"🛡️ Prisma AIRS Blocked Input: {ingress_data.get('category', 'Policy')} violation."
                return {"bot": block_txt, "output": block_txt, "logs": {"security_scan": "INGRESS BLOCK", "raw_response": json.dumps(ingress_data, indent=2)}}
            security_status = "Passed Input"
            raw_sec_log = json.dumps(ingress_data, indent=2)

        # =================================================================
        # STAGE 2: RAG CONTEXT RETRIEVAL
        # Fetch relevant secret documents to append to the system prompt
        # =================================================================
        rag_context = retrieve_rag_context(message)
        
        # We instruct the AI to actively use its MCP tools and RAG data
        system_instruction = f"""{selected_prompt}
{rag_context}
You also have access to a SQL database via your tools. Always query the database to find facts instead of guessing."""

        # =================================================================
        # STAGE 3: AI GATEWAY & MCP TOOL CALLING LOOP
        # =================================================================
        messages = [
            {"role": "system", "content": system_instruction},
            {"role": "user", "content": message}
        ]

        # Call the AI Gateway
        response = await llm_client.chat.completions.create(
            model=model_id,
            messages=messages,
            tools=openai_tools if openai_tools else None,
            temperature=0.7
        )
        
        response_msg = response.choices[0].message

        # Does the AI want to query the SQLite Database?
        if response_msg.tool_calls:
            messages.append(response_msg) 
            
            for tool_call in response_msg.tool_calls:
                tool_name = tool_call.function.name
                tool_args = json.loads(tool_call.function.arguments)
                print(f"🤖 AI executing tool: {tool_name} with args {tool_args}")
                
                # Execute the SQL Query via the MCP Server!
                mcp_result = await mcp_session.call_tool(tool_name, arguments=tool_args)
                db_output = mcp_result.content[0].text
                
                # Append the DB output back to the chat history
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "name": tool_name,
                    "content": db_output
                })

            # Call the AI Gateway ONE MORE TIME so it can summarize the Database output
            final_response = await llm_client.chat.completions.create(
                model=model_id,
                messages=messages,
                temperature=0.7
            )
            bot_response = final_response.choices[0].message.content
        else:
            bot_response = response_msg.content

        # =================================================================
        # STAGE 4: EGRESS SECURITY SCAN
        # Ensure the AI didn't leak PII (from the DB) or Passwords (from RAG)
        # =================================================================
        if AIRS_CONFIGURED and airs_enabled and ai_profile_obj and "Error:" not in bot_response:
            out_scan_response = Scanner().sync_scan(ai_profile=ai_profile_obj, content=Content(prompt=bot_response))
            out_res_data = out_scan_response.to_dict()
            out_data = out_res_data[0] if isinstance(out_res_data, list) and len(out_res_data) > 0 else out_res_data
            
            if str(out_data.get("action", "pass")).lower() == "block":
                block_txt = f"🛡️ Prisma AIRS Blocked Output: The LLM generated a {out_data.get('category', 'Policy')} violation."
                return {"bot": block_txt, "output": block_txt, "logs": {"security_scan": "EGRESS BLOCK", "raw_response": json.dumps(out_data, indent=2)}}
            
            security_status = "Passed Input & Output"
            raw_sec_log = json.dumps({"input_scan": ingress_data, "output_scan": out_data}, indent=2)

        return {"bot": bot_response, "output": bot_response, "logs": {"security_scan": security_status, "raw_response": raw_sec_log}}

    except Exception as e:
        return {"bot": f"Error: {str(e)}", "output": f"Error: {str(e)}", "logs": {"security_scan": "Error", "raw_response": raw_sec_log}}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
