"""
T-AIRS: Enterprise AI Application with Prisma AIRS Security, RAG, and MCP
=========================================================================
This application serves as a demonstration of a secure, full-stack AI chatbot.
"""

import os
import argparse
import uvicorn
import subprocess
import json
import re
import requests
import asyncio
import ast
from contextlib import asynccontextmanager, AsyncExitStack
from fastapi import FastAPI, Request, Form, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

# 1. The Universal AI Gateway Client
from openai import AsyncOpenAI

# 2. MCP Imports (Database Tool Calling)
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# 3. RAG Imports 
import chromadb
from sentence_transformers import SentenceTransformer
import rag_data 
import importlib
importlib.reload(rag_data)

# 4. Prisma AIRS Imports (Enterprise LLM Security Scanning)
import aisecurity
from aisecurity.generated_openapi_client.models.ai_profile import AiProfile
from aisecurity.generated_openapi_client.models.tool_event import ToolEvent
from aisecurity.generated_openapi_client.models.tool_event_metadata import ToolEventMetadata
from aisecurity.scan.inline.scanner import Scanner
from aisecurity.scan.models.content import Content

# Local modules
import personas
from custom_tools import PERSONA_TOOLS

# --- APPLICATION VERSION ---
APP_VERSION = "unknown"
try:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    version_file = os.path.join(base_dir, '..', 'VERSION')
    with open(version_file, 'r') as f:
        version_content = f.read().strip()
        if version_content:
            APP_VERSION = version_content
except Exception as e:
    print(f"Warning: Could not read VERSION file. Error: {e}")

# --- CAPTURE CLI ARGUMENTS ---
parser = argparse.ArgumentParser(description="T-AIRS")
parser.add_argument("--airs-key", help="Prisma AIRS API Key", default=None)
parser.add_argument("--airs-profile", help="Prisma AIRS Security Profile", default="default")
parser.add_argument("--gateway-url", help="URL for LiteLLM Gateway", default="http://localhost:4000")
args, _ = parser.parse_known_args()

AIRS_KEY = args.airs_key
AIRS_PROFILE_NAME = args.airs_profile
GATEWAY_URL = args.gateway_url 

# --- GLOBAL STATE TRACKERS & CLIENTS ---
AIRS_CONFIGURED = False
airs_error_msg = "Not initialized"
ai_profile_obj = None
validated_models = []
PERSONAS = personas.PERSONAS
SESSION_HISTORY = {}
MAX_HISTORY = 10

llm_client = AsyncOpenAI(base_url=f"{GATEWAY_URL}/v1", api_key="sk-t-airs-dummy-key")

mcp_session = None
openai_tools = []
server_params = StdioServerParameters(
    command="/opt/t-airs/venv/bin/mcp-server-sqlite",
    args=["--db-path", "/opt/t-airs/src/customers.db"]
)

chroma_client = None
rag_collections = {}
embedder = None

# --- CORE LOGIC HELPERS ---

def check_gpu_status():
    try:
        gpu_info = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader"],
            text=True, timeout=5
        ).strip()
        try:
            ollama_ps = subprocess.check_output(["ollama", "ps"], text=True, timeout=5).strip().split('\n')
            loaded_models = [line.split()[0] for line in ollama_ps[1:] if line.strip()]
            model_str = f"| Models in VRAM: {', '.join(loaded_models)}" if loaded_models else "| No models currently active in VRAM"
        except subprocess.TimeoutExpired:
            model_str = "| Ollama engine is busy/hanging"
        except Exception:
            model_str = "| Ollama engine not responding"
        return f"✅ GPU ONLINE: {gpu_info} {model_str}"
    except Exception as e:
        return f"⚠️ NO GPU DETECTED: Running on CPU."

def discover_gateway_models():
    found = []
    try:
        response = requests.get(f"{GATEWAY_URL}/v1/models", timeout=5)
        if response.status_code == 200:
            for m in response.json().get("data", []):
                found.append(m["id"])
    except Exception as e:
        print(f"CRITICAL: Could not connect to AI Gateway. Error: {e}")
    found.sort()
    return found

def init_rag_pipeline():
    global chroma_client, rag_collections, embedder
    print("📚 Initializing Multi-Persona RAG Pipeline...", flush=True)
    try:
        chroma_client = chromadb.Client()
        print("⏳ Downloading BAAI Embedding Model from HuggingFace...", flush=True)
        embedder = SentenceTransformer("BAAI/bge-small-en-v1.5")
        print("✅ BAAI Model successfully loaded into memory!", flush=True)

        for persona_name, content in rag_data.RAG_KNOWLEDGE_BASE.items():
            col = chroma_client.get_or_create_collection(name=f"rag_{persona_name}")
            existing_data = col.get()
            if existing_data and existing_data["ids"]:
                col.delete(ids=existing_data["ids"])
            chunks = [c for c in content.split('\n') if len(c.strip()) > 10]
            if chunks:
                embeddings = embedder.encode(chunks).tolist()
                col.add(embeddings=embeddings, documents=chunks, ids=[f"{persona_name}_chunk_{i}" for i in range(len(chunks))])
            rag_collections[persona_name] = col
        print("✅ RAG Ready: Loaded multiple personas into Vector DB.")
    except Exception as e:
        print(f"❌ RAG Initialization Failed: {e}")

def retrieve_rag_context(user_prompt: str, persona: str, top_k: int = 2):
    target_collection = rag_collections.get(persona)
    if not target_collection:
        return "", [], []
    filtered_docs, rejected_docs = [], []
    try:
        query_emb = embedder.encode([user_prompt]).tolist()
        results = target_collection.query(query_embeddings=query_emb, n_results=top_k, include=["documents", "distances"])
        raw_docs = results.get("documents", [[]])[0]
        distances = results.get("distances", [[]])[0]
        for doc, dist in zip(raw_docs, distances):
            if dist <= 0.50:
                filtered_docs.append(doc)
            else:
                rejected_docs.append({"text": doc, "distance": round(dist, 2)})
        if filtered_docs:
            formatted_text = "\n[DATA RETRIEVED VIA RAG]:\n" + "\n".join(filtered_docs)
            return formatted_text, filtered_docs, rejected_docs
    except Exception as e:
        print(f"RAG Retrieval Error: {e}")
    return "", filtered_docs, rejected_docs

# --- APP LIFESPAN MANAGEMENT ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    global AIRS_CONFIGURED, airs_error_msg, ai_profile_obj, validated_models, mcp_session, openai_tools
    print("\n" + "="*50, flush=True)
    print("🚀 T-AIRS STARTUP", flush=True)
    print("="*50, flush=True)
    print(f"RESULT: {check_gpu_status()}", flush=True)

    if AIRS_KEY and AIRS_PROFILE_NAME:
        print(f"Handshaking with Prisma AIRS App SDK: {AIRS_PROFILE_NAME}...", flush=True)
        try:
            aisecurity.init(api_key=AIRS_KEY)
            ai_profile_obj = AiProfile(profile_name=AIRS_PROFILE_NAME)
            Scanner().sync_scan(ai_profile=ai_profile_obj, content=Content(prompt="healthcheck"))
            AIRS_CONFIGURED = True
            airs_error_msg = "Connected"
            print("RESULT: ✅ AIRS SDK ONLINE", flush=True)
        except Exception as e:
            raw_error = str(e)
            match = re.search(r'HTTP response body: (\{.*\})', raw_error)
            airs_error_msg = match.group(1) if match else raw_error
            print(f"RESULT: ❌ AIRS FAILED - {airs_error_msg}", flush=True)
    else:
        print("RESULT: ⚠️ AIRS Keys missing. App SDK Disabled.")

    validated_models = discover_gateway_models()
    init_rag_pipeline()

    async with AsyncExitStack() as stack:
        print("🔌 Booting SQLite MCP Server...")
        read, write = await stack.enter_async_context(stdio_client(server_params))
        mcp_session = await stack.enter_async_context(ClientSession(read, write))
        await mcp_session.initialize()

        mcp_tools = await mcp_session.list_tools()
        for t in mcp_tools.tools:
            openai_tools.append({
                "type": "function",
                "function": {"name": t.name, "description": t.description, "parameters": t.inputSchema}
            })
        print(f"RESULT: ✅ MCP ONLINE. Tools loaded: {[t.name for t in mcp_tools.tools]}")
        print("="*50 + "\n")
        yield

app = FastAPI(lifespan=lifespan)
templates = Jinja2Templates(directory="templates")

# --- UI ENDPOINTS ---
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
    return templates.TemplateResponse("index.html", {"request": request, "app_version": APP_VERSION})

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
    model_id: str = Form("none"),
    history_enabled: bool = Form(True),
    enforcement_placement: str = Form("gateway"),
    end_user: str = Form("user1")
):
    selected_prompt = PERSONAS.get(persona, PERSONAS["banking"])
    security_status = "Bypassed"
    raw_sec_log = "{}"
    ingress_data = {}
    
    print(f"\n{'='*40}")
    print(f"📥 NEW REQUEST | Session: {session_id} | Persona: {persona} | AIRS placement: {enforcement_placement.upper()}")
    print(f"💬 PROMPT: {message}")

    architecture_trace = {
        "ai_gateway": {"routed_to": model_id},
        "rag_pipeline": {"chunks_injected": [], "chunks_rejected": []},
        "mcp_execution": []
    }

    if not model_id or model_id == "none":
        model_id = validated_models[0] if validated_models else None
        architecture_trace["ai_gateway"]["routed_to"] = model_id

    execution_phase = "Initial Inference"

    try:
        # =====================================================================
        # 1. LOCAL INGRESS SCAN 
        # (Universally applied to protect the System Prompt from Gateway drops)
        # =====================================================================
        if AIRS_CONFIGURED and airs_enabled and ai_profile_obj:
            scan_response = Scanner().sync_scan(
                ai_profile=ai_profile_obj,
                content=Content(prompt=message),
                metadata={"app_user": end_user, "ai_model": model_id}
            )
            res_data = scan_response.to_dict()
            ingress_data = res_data[0] if isinstance(res_data, list) and len(res_data) > 0 else res_data

            if str(ingress_data.get("action", "pass")).lower() == "block":
                category = str(ingress_data.get("category", "Security")).capitalize()
                block_txt = f"🛡️ Blocked by Prisma AIRS [User ➔ LLM]: {category} policy violation."
                print(f"🛑 AIRS BLOCK: INGRESS | Category: {category}")
                print(f"🏁 REQUEST ABORTED | Security Status: Blocked by App SDK")
                print(f"{'='*40}\n")
                return {"bot": block_txt, "output": block_txt, "logs": {"security_scan": "INGRESS BLOCK (User ➔ LLM)", "raw_response": json.dumps(ingress_data, indent=2), "trace": architecture_trace}}
            
            security_status = "Passed App Input"
            raw_sec_log = json.dumps(ingress_data, indent=2)

        # =====================================================================
        # 2. RAG CONTEXT RETRIEVAL & SCAN
        # (Strictly disabled if "prompt_only" is selected)
        # =====================================================================
        rag_context, raw_rag_docs, rejected_rag_docs = await asyncio.to_thread(retrieve_rag_context, message, persona)
        architecture_trace["rag_pipeline"]["chunks_injected"] = raw_rag_docs
        architecture_trace["rag_pipeline"]["chunks_rejected"] = rejected_rag_docs

        if enforcement_placement == "gateway" and AIRS_CONFIGURED and airs_enabled and ai_profile_obj and raw_rag_docs:
            print(f"🔍 Scanning RAG Context via AIRS...")
            raw_rag_text = "\n".join(raw_rag_docs)
            try:
                rag_scan = Scanner().sync_scan(
                    ai_profile=ai_profile_obj,
                    content=Content(prompt=raw_rag_text), 
                    metadata={"app_user": end_user, "ai_model": model_id, "scan_type": "rag_data"}
                )
                r_data = rag_scan.to_dict()
                if str(r_data.get("action", "pass")).lower() == "block":
                    category = str(r_data.get("category", "Security")).capitalize()
                    block_msg = f"🛡️ AIRS Blocked RAG Retrieval: {category} violation (Indirect Injection detected)."
                    print(f"🛑 AIRS BLOCK: RAG DATA | Category: {category}")
                    return {"bot": block_msg, "output": block_msg, "logs": {"security_scan": "RAG DATA BLOCK", "raw_response": json.dumps(r_data, indent=2), "trace": architecture_trace}}
            except Exception as e: 
                print(f"⚠️ RAG Scan Error: {e}")
        
        system_instruction = f"{selected_prompt}\n{rag_context}"

        # =====================================================================
        # 3. BUILD MESSAGE PAYLOAD
        # =====================================================================
        if history_enabled:
            if session_id not in SESSION_HISTORY:
                SESSION_HISTORY[session_id] = []
            SESSION_HISTORY[session_id].append({"role": "user", "content": message})
            current_context = SESSION_HISTORY[session_id]
        else:
            current_context = [{"role": "user", "content": message}]

        messages = [{"role": "system", "content": system_instruction}] + current_context

        active_tools = openai_tools.copy() if openai_tools else []
        if persona in PERSONA_TOOLS:
            active_tools.extend(PERSONA_TOOLS[persona])

        # =====================================================================
        # 4. AI GATEWAY INFERENCE
        # =====================================================================
        print(f"🚀 ROUTING TO MODEL: {model_id} via AI Gateway...")

        gateway_params_agent = {}
        if enforcement_placement == "gateway" and airs_enabled:
            # LiteLLM scans for malicious MCP tool usage right at the Gateway proxy level.
            # CRITICAL: We DO NOT attach egress scanning here, because LiteLLM crashes 
            # with an HTTP 400 when attempting to scan the null/0-byte payload of a tool call.
            gateway_params_agent = {"guardrails": ["airs-mcp-scan"]}

        raw_response = await llm_client.chat.completions.with_raw_response.create(
            model=model_id,
            messages=messages,
            tools=active_tools if active_tools else None,
            temperature=0.7,
            user=end_user,
            extra_body=gateway_params_agent
        )

        response = raw_response.parse()
        
        actual_model = getattr(response, "model", model_id)
        hidden_model = raw_response.headers.get("x-litellm-model-name")

        if hidden_model:
            actual_model = hidden_model
        elif actual_model == "auto-router":
            actual_model = "Dynamically Routed (Gateway Load Balancer)"

        if model_id == "auto-router":
            architecture_trace["ai_gateway"]["routed_to"] = f"auto-router ➔ {actual_model}"
        else:
            architecture_trace["ai_gateway"]["routed_to"] = actual_model

        response_msg = response.choices[0].message

        # =====================================================================
        # 5. THE MULTI-STEP AGENT LOOP
        # =====================================================================
        iteration = 0
        MAX_ITERATIONS = 5

        # By using a while loop, advanced models (like Gemini 3.5) can call a tool, 
        # read the output, and call ANOTHER tool before finally answering the user.
        while getattr(response_msg, "tool_calls", None) and iteration < MAX_ITERATIONS:
            iteration += 1
            action_tools = [
                "transfer_funds", "freeze_account", "issue_replacement_card",
                "upgrade_flight_seat", "cancel_flight_booking", "update_passport_details",
                "issue_store_refund", "apply_admin_discount", "update_billing_zip"
            ]
            
            # Append the model's tool request to history so it remembers what it asked
            messages.append(response_msg)

            for tool_call in response_msg.tool_calls:
                tool_name = tool_call.function.name
                tool_args = json.loads(tool_call.function.arguments)
                print(f"🛠️  MODEL REQUESTED TOOL [{iteration}/{MAX_ITERATIONS}]: {tool_name}")

                # --- 🔌 EXECUTE TOOL ---
                if tool_name in action_tools:
                    await mcp_session.call_tool("write_query", arguments={"query": "CREATE TABLE IF NOT EXISTS unauthorized_actions_log (id INTEGER PRIMARY KEY AUTOINCREMENT, tool_used TEXT, details TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP);"})
                    
                    details, tool_output = "", ""
                    if tool_name == "transfer_funds":
                        src, dst, amt = tool_args.get("source_account"), tool_args.get("dest_account"), tool_args.get("amount")
                        await mcp_session.call_tool("write_query", arguments={"query": f"UPDATE users SET balance = balance - {amt} WHERE id = '{src}';"})
                        await mcp_session.call_tool("write_query", arguments={"query": f"UPDATE users SET balance = balance + {amt} WHERE id = '{dst}';"})
                        tool_output = f"⚠️ Wire transfer of ${amt} executed."
                    elif tool_name == "freeze_account":
                        acc, reason = tool_args.get("account_id"), tool_args.get("reason")
                        await mcp_session.call_tool("write_query", arguments={"query": f"UPDATE users SET notes = 'FROZEN: {reason}' WHERE id = '{acc}';"})
                        tool_output = f"🔒 ACCOUNT LOCKED: Account {acc} frozen."
                    elif tool_name == "issue_replacement_card":
                        acc = tool_args.get("account_id")
                        await mcp_session.call_tool("write_query", arguments={"query": f"UPDATE users SET notes = 'CARD REPLACED', cc_number = '0000-0000-0000-0000' WHERE id = '{acc}';"})
                        tool_output = f"💳 CARD REPLACED: Old card voided for account {acc}."
                    elif tool_name == "upgrade_flight_seat":
                        tkt, cabin = tool_args.get("ticket_number"), tool_args.get("new_class")
                        await mcp_session.call_tool("write_query", arguments={"query": f"UPDATE passenger_manifest SET cabin_class = '{cabin}' WHERE ticket_number = '{tkt}';"})
                        tool_output = f"✅ BOOKING UPDATED: Ticket {tkt} upgraded to {cabin}."
                    elif tool_name == "cancel_flight_booking":
                        tkt = tool_args.get("ticket_number")
                        await mcp_session.call_tool("write_query", arguments={"query": f"DELETE FROM passenger_manifest WHERE ticket_number = '{tkt}';"})
                        tool_output = f"🚫 FLIGHT CANCELED: Ticket {tkt} revoked."
                    elif tool_name == "update_passport_details":
                        tkt, new_pass = tool_args.get("ticket_number"), tool_args.get("new_passport_id")
                        await mcp_session.call_tool("write_query", arguments={"query": f"UPDATE passenger_manifest SET passport_number = '{new_pass}' WHERE ticket_number = '{tkt}';"})
                        tool_output = f"🛂 PASSPORT UPDATED: New document saved to manifest."
                    elif tool_name == "issue_store_refund":
                        order, amt = tool_args.get("order_id"), tool_args.get("amount")
                        await mcp_session.call_tool("write_query", arguments={"query": f"UPDATE pending_orders SET customer_name = customer_name || ' [REFUNDED ${amt}]' WHERE order_id = '{order}';"})
                        tool_output = f"✅ REFUND PROCESSED: ${amt} credited back to payment method for order {order}."
                    elif tool_name == "apply_admin_discount":
                        order, disc = tool_args.get("order_id"), tool_args.get("discount_percentage")
                        await mcp_session.call_tool("write_query", arguments={"query": f"UPDATE pending_orders SET customer_name = customer_name || ' [DISCOUNT: {disc}%]' WHERE order_id = '{order}';"})
                        tool_output = f"💸 DISCOUNT APPLIED: {disc}% off order {order}."
                    elif tool_name == "update_billing_zip":
                        order, new_zip = tool_args.get("order_id"), tool_args.get("new_zip_code")
                        await mcp_session.call_tool("write_query", arguments={"query": f"UPDATE pending_orders SET billing_zip = '{new_zip}' WHERE order_id = '{order}';"})
                        tool_output = f"📦 ADDRESS UPDATED: Billing zip changed to {new_zip}."
                    
                    await mcp_session.call_tool("write_query", arguments={"query": f"INSERT INTO unauthorized_actions_log (tool_used, details) VALUES ('{tool_name}', 'Action executed.');"})
                    tool_output += " (Transaction permanently recorded in backend database)."


                else:
                    mcp_res = await mcp_session.call_tool(tool_name, arguments=tool_args)
                    raw_text = mcp_res.content[0].text
                    
                    # --- 🛡️ ANTI-FALSE-POSITIVE DATA SANITIZER ---
                    try:
                        # Parse the SQLite stringified list of dicts
                        parsed_data = ast.literal_eval(raw_text)
                        
                        if isinstance(parsed_data, list):
                            # Convert [{'balance': 14700.5}] into plain text: "balance: 14700.5"
                            # This strips ALL brackets and quotes so the scanner sees harmless text!
                            tool_output = "\n".join([", ".join([f"{k}: {v}" for k, v in row.items()]) for row in parsed_data])
                        else:
                            tool_output = str(parsed_data)
                    except Exception:
                        # Fallback if it's already plain text
                        tool_output = raw_text


                messages.append({"role": "tool", "tool_call_id": tool_call.id, "name": tool_name, "content": tool_output})
                architecture_trace["mcp_execution"].append({"tool": tool_name, "arguments": tool_args, "database_result": tool_output})

                # =====================================================================
                # 🚀 EXPLICIT MCP TOOL SCAN (Only executes if 'gateway' is selected)
                # =====================================================================
                if enforcement_placement == "gateway" and AIRS_CONFIGURED and airs_enabled and ai_profile_obj:
                    print(f"🔍 Logging explicit ToolEvent to AIRS for {tool_name}...")
                    try:
                        mcp_metadata = ToolEventMetadata(
                            tool_invoked=tool_name,
                            ecosystem="mcp",
                            method="tools/call",
                            server_name="mcp-server-sqlite"
                        )
                        mcp_event_obj = ToolEvent(
                            metadata=mcp_metadata,
                            input=json.dumps(tool_args),
                            output=json.dumps({"result": tool_output})
                        )
                        tool_scan_response = Scanner().sync_scan(
                            ai_profile=ai_profile_obj,
                            content=Content(tool_event=mcp_event_obj),
                            metadata={"app_user": end_user, "ai_model": model_id, "scan_type": "mcp_tool"}
                        )
                        
                        tool_data = tool_scan_response.to_dict()
                        if str(tool_data.get("action", "pass")).lower() == "block":
                            category = str(tool_data.get("category", "Security")).capitalize()
                            block_txt = f"🛡️ Blocked by Prisma AIRS [MCP Tool ➔ LLM]: '{tool_name}' returned a {category} violation."
                            return {"bot": block_txt, "output": block_txt, "logs": {"security_scan": f"TOOL BLOCK ({tool_name})", "raw_response": json.dumps(tool_data, indent=2), "trace": architecture_trace}}
                    except Exception as e:
                        print(f"⚠️ ToolEvent Log Error: {e}")

                

            # Fetch the next step from the LLM (It might return text, or MORE tools!)
            execution_phase = f"Agent Iteration {iteration}"
            raw_response = await llm_client.chat.completions.with_raw_response.create(
                model=model_id,
                messages=messages,
                tools=active_tools if active_tools else None,
                temperature=0.7,
                user=end_user,
                extra_body=gateway_params_agent
            )
            response = raw_response.parse()
            response_msg = response.choices[0].message

        # The loop has broken! We either got a text response, or hit the iteration limit.
        bot_response = response_msg.content or ""

        if bot_response.strip() == "":
            if iteration >= MAX_ITERATIONS:
                bot_response = f"⚠️ [System: The LLM reached the maximum limit of {MAX_ITERATIONS} tool executions and was halted.]"
            else:
                bot_response = "⚠️ [System: The LLM executed the prompt and tools, but returned an empty text string.]"

        architecture_trace["llm_generation"] = bot_response

        # =====================================================================
        # 6. APP-LEVEL EGRESS SCAN
        # =====================================================================
        # Runs unconditionally for both placements to prevent Gateway 0-byte crashes.
        if AIRS_CONFIGURED and airs_enabled and ai_profile_obj and "Error:" not in bot_response:
            out_scan_response = Scanner().sync_scan(
                ai_profile=ai_profile_obj,
                content=Content(response=bot_response),
                metadata={"app_user": end_user, "ai_model": model_id}
            )
            out_res_data = out_scan_response.to_dict()
            out_data = out_res_data[0] if isinstance(out_res_data, list) and len(out_res_data) > 0 else out_res_data

            if str(out_data.get("action", "pass")).lower() == "block":
                category = str(out_data.get("category", "Security")).capitalize()
                block_txt = f"🛡️ Blocked by Prisma AIRS [LLM ➔ User]: {category} policy violation."
                print(f"🛑 AIRS BLOCK: EGRESS | Category: {category}")
                print(f"🏁 REQUEST ABORTED | Security Status: Blocked by App SDK")
                print(f"{'='*40}\n")
                return {
                    "bot": block_txt,
                    "output": block_txt,
                    "logs": {
                        "security_scan": "EGRESS BLOCK (LLM ➔ User)",
                        "raw_response": json.dumps(out_data, indent=2),
                        "trace": architecture_trace,
                        "intercepted_text": bot_response
                    }
                }

            security_status = "Passed App Input & Output"
            raw_sec_log = json.dumps({"input_scan": ingress_data, "output_scan": out_data}, indent=2)

        # --- PERSIST HISTORY ---
        if history_enabled:
            SESSION_HISTORY[session_id].append({"role": "assistant", "content": bot_response})
            if len(SESSION_HISTORY[session_id]) > 10:
                SESSION_HISTORY[session_id] = SESSION_HISTORY[session_id][-10:]

        if enforcement_placement == "gateway" and airs_enabled:
             security_status = "Checked & Passed by Gateway"

        print(f"🏁 REQUEST COMPLETE | Security Status: {security_status}")
        print(f"{'='*40}\n")
        
        return {"bot": bot_response, "output": bot_response, "logs": {"security_scan": security_status, "raw_response": raw_sec_log, "trace": architecture_trace}}

    # =====================================================================
    # EXCEPTION & PROXY GUARDRAIL HANDLING
    # =====================================================================
    except Exception as e:
        error_str = str(e)

        if "429" in error_str or "rate limit" in error_str.lower() or "too many requests" in error_str.lower():
            print(f"🚦 RATE LIMIT HIT: {error_str}")
            print("⏳ Passing HTTP 429 back to Prisma AIRS scanner to trigger backoff...")
            print(f"🏁 REQUEST ABORTED | Security Status: Rate Limited")
            print(f"{'='*40}\n")
            return JSONResponse(status_code=429, content={"error": {"message": "Rate limit reached", "type": "rate_limit_error", "code": 429}})

        if history_enabled and session_id in SESSION_HISTORY:
            if len(SESSION_HISTORY[session_id]) > 0 and SESSION_HISTORY[session_id][-1]["content"] == message:
                SESSION_HISTORY[session_id].pop()

        if enforcement_placement == "gateway" and ("panw_prisma_airs" in error_str or "blocked" in error_str.lower() or "airs-" in error_str):
            scan_type = "EGRESS BLOCK" if "airs-egress-scan" in error_str else "INGRESS BLOCK"
            log_key = "output_scan" if "egress" in scan_type.lower() else "input_scan"

            if execution_phase == "Initial Inference":
                direction = "User ➔ LLM" if scan_type == "INGRESS BLOCK" else "LLM ➔ MCP Tool (or User)"
            else:
                direction = "MCP Tool ➔ LLM" if scan_type == "INGRESS BLOCK" else "LLM ➔ User"

            category_match = re.search(r"'category':\s*'([^']+)'", error_str)
            category = category_match.group(1).capitalize() if category_match else "Security"

            if "http_400_error" in error_str or "scan_failed" in error_str:
                clean_msg = f"⚠️ [System: Gateway Scan Failed. The LLM executed the tool but likely returned an empty string, causing the Egress AIRS scan to reject the 0-byte payload.]"
            else:
                clean_msg = f"🛡️ Blocked by Prisma AIRS [{direction}]: {category} policy violation."

            sidebar_log = {"raw_error": error_str}
            try:
                start_idx = error_str.find("{")
                if start_idx != -1:
                    inner_str = error_str[start_idx:]
                    parsed_dict = ast.literal_eval(inner_str)
                    sidebar_log = {log_key: parsed_dict.get("error", parsed_dict)}
            except Exception as parse_error:
                print(f"Debug: Failed to parse inner LiteLLM error: {parse_error}")

            print(f"🛑 AIRS GATEWAY BLOCK: {scan_type} | Direction: {direction} | Category: {category}")
            print(f"🏁 REQUEST ABORTED | Security Status: Blocked by Gateway")
            print(f"{'='*40}\n")
            return {
                "bot": clean_msg,
                "output": clean_msg,
                "logs": {
                    "security_scan": f"{scan_type} ({direction})",
                    "raw_response": json.dumps(sidebar_log, indent=2),
                    "trace": architecture_trace
                }
            }

        return {
            "bot": f"Error: {error_str}",
            "output": f"Error: {error_str}",
            "logs": {"security_scan": "Error", "raw_response": raw_sec_log, "trace": architecture_trace}
        }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)