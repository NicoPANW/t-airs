import os
import argparse
import uvicorn
import json
import re
import requests
import torch
import asyncio
import ast
from contextlib import asynccontextmanager, AsyncExitStack

# FastAPI Imports for web server and UI rendering
from fastapi import FastAPI, Request, Form, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

# 1. The Universal AI Gateway Client (Routes requests to LiteLLM)
from openai import AsyncOpenAI

# 2. MCP Imports (Model Context Protocol for direct Database Tool Calling)
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# 3. RAG Imports (Retrieval-Augmented Generation for Unstructured Data)
import chromadb
from sentence_transformers import SentenceTransformer
import rag_data
import importlib
importlib.reload(rag_data)  # 🌟 Force a fresh read of the file on every boot!


# Prisma AIRS Imports (Enterprise LLM Security Scanning)
import aisecurity
from aisecurity.generated_openapi_client.models.ai_profile import AiProfile
from aisecurity.scan.inline.scanner import Scanner
from aisecurity.scan.models.content import Content

# Local modules
import personas
from custom_tools import PERSONA_TOOLS

# --- CAPTURE CLI ARGUMENTS ---
parser = argparse.ArgumentParser(description="T-AIRS")
parser.add_argument("--airs-key", help="Prisma AIRS API Key", default=None)
parser.add_argument("--airs-profile", help="Prisma AIRS Security Profile", default="default")
parser.add_argument("--gateway-url", help="URL for LiteLLM Gateway", default="http://localhost:4000")
args, _ = parser.parse_known_args()

# Global configuration variables
AIRS_KEY = args.airs_key
AIRS_PROFILE_NAME = args.airs_profile
GATEWAY_URL = args.gateway_url
# (AIRS_MODE is kept here to prevent CLI crashing, but is no longer used for routing logic)

# Security state trackers
AIRS_CONFIGURED = False
airs_error_msg = "Not initialized"
ai_profile_obj = None

# App state variables
validated_models = []
PERSONAS = personas.PERSONAS

# Session management
SESSION_HISTORY = {}
MAX_HISTORY = 10

# --- CLIENT INITIALIZATION ---
llm_client = AsyncOpenAI(base_url=f"{GATEWAY_URL}/v1", api_key="sk-t-airs-dummy-key")

# MCP State & Configuration
mcp_session = None
openai_tools = []
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
    global chroma_client, rag_collections, embedder
    print("📚 Initializing Multi-Persona RAG Pipeline...")
    try:
        import importlib
        import rag_data
        importlib.reload(rag_data)
        
        chroma_client = chromadb.Client()
        embedder = SentenceTransformer("all-MiniLM-L6-v2")

        # 🌟 THE FIX: Added 'rag_data.' prefix here!
        for persona_name, content in rag_data.RAG_KNOWLEDGE_BASE.items():
            
            # 🌟 SAFE CREATION: Get or Create to prevent ChromaDB crashes
            col = chroma_client.get_or_create_collection(name=f"rag_{persona_name}")
            
            # Wipe any ghost data from previous soft-restarts
            existing_data = col.get()
            if existing_data and existing_data["ids"]:
                col.delete(ids=existing_data["ids"])

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

def retrieve_rag_context(user_prompt: str, persona: str, top_k: int = 3):
    target_collection = rag_collections.get(persona)
    if not target_collection:
        return "", [], [] 
    
    filtered_docs = []
    rejected_docs = []
    
    try:
        query_emb = embedder.encode([user_prompt]).tolist()
        results = target_collection.query(
            query_embeddings=query_emb, 
            n_results=top_k,
            include=["documents", "distances"]
        )
        
        raw_docs = results.get("documents", [[]])[0]
        distances = results.get("distances", [[]])[0]
        
        MAX_DISTANCE = 1.3 
        
        for doc, dist in zip(raw_docs, distances):
            if dist <= MAX_DISTANCE:
                filtered_docs.append(doc)
            else:
                # 🌟 Save both the text and the math score!
                rejected_docs.append({"text": doc, "distance": round(dist, 2)})
                print(f"🛑 RAG Chunk Rejected: Too far from prompt (Distance: {dist:.2f})")
        
        if filtered_docs:
            formatted_text = "\n[CONFIDENTIAL INTERNAL DATA RETRIEVED VIA RAG]:\n" + "\n".join(filtered_docs)
            return formatted_text, filtered_docs, rejected_docs 
            
    except Exception as e:
        print(f"RAG Retrieval Error: {e}")
    
    # 🌟 Always return 3 items, even if it completely fails!
    return "", filtered_docs, rejected_docs

# --- APP LIFESPAN MANAGEMENT ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    global AIRS_CONFIGURED, airs_error_msg, ai_profile_obj, validated_models, mcp_session, openai_tools
    print("\n" + "="*50)
    print("🚀 T-AIRS STARTUP (DYNAMIC ENFORCEMENT MODE)")
    print("="*50)
    print("Checking Hardware Acceleration...")
    print(f"RESULT: {check_gpu_status()}")
    print("-" * 50)
    
    # 1. Prisma AIRS Handshake (ALWAYS initialize so UI toggle can work instantly)
    if AIRS_KEY and AIRS_PROFILE_NAME:
        print(f"Handshaking with Prisma AIRS App SDK: {AIRS_PROFILE_NAME}...")
        try:
            aisecurity.init(api_key=AIRS_KEY)
            ai_profile_obj = AiProfile(profile_name=AIRS_PROFILE_NAME)
            Scanner().sync_scan(ai_profile=ai_profile_obj, content=Content(prompt="healthcheck"))
            AIRS_CONFIGURED = True
            airs_error_msg = "Connected"
            print("RESULT: ✅ AIRS SDK ONLINE")
        except Exception as e:
            raw_error = str(e)
            match = re.search(r'HTTP response body: (\{.*\})', raw_error)
            airs_error_msg = match.group(1) if match else raw_error
            print(f"RESULT: ❌ AIRS FAILED - {airs_error_msg}")
    else:
        print("RESULT: ⚠️ AIRS Keys missing. App SDK Disabled.")

    # 2. AI Gateway Discovery
    print("Performing Deep Model Discovery via AI Gateway...")
    validated_models = discover_gateway_models()
    print(f"RESULT: ✅ {len(validated_models)} routing models loaded.")
    
    # 3. RAG Initialization
    init_rag_pipeline()

    # 4. MCP Server Boot-Up
    async with AsyncExitStack() as stack:
        print("🔌 Booting SQLite MCP Server...")
        read, write = await stack.enter_async_context(stdio_client(server_params))
        mcp_session = await stack.enter_async_context(ClientSession(read, write))
        await mcp_session.initialize()
        
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
    model_id: str = Form("none"),
    history_enabled: bool = Form(True),
    enforcement_placement: str = Form("gateway")
):
    selected_prompt = PERSONAS.get(persona, PERSONAS["banking"])
    security_status = "Bypassed"
    raw_sec_log = "{}"
    ingress_data = {}
    print(f"\n{'='*40}")
    print(f"📥 NEW REQUEST | Session: {session_id} | Persona: {persona} | Placement: {enforcement_placement.upper()}")
    print(f"💬 PROMPT: {message}")
    
    architecture_trace = {
        "ai_gateway": {"routed_to": model_id},
        "rag_pipeline": {"chunks_injected": [], "chunks_rejected": []}, 
        "mcp_execution": []
    }
    
    if not model_id or model_id == "none":
        model_id = validated_models[0] if validated_models else None
        architecture_trace["ai_gateway"]["routed_to"] = model_id

    # Initialize tracker outside try block for safe exception handling
    execution_phase = "Pre-Inference"

    try:
        # 🌟 STATE TRACKER: Initial Inference Phase
        execution_phase = "Initial Inference"
        
        # --- 1. INGRESS SCAN (App-Level) ---
        if enforcement_placement == "app" and AIRS_CONFIGURED and airs_enabled and ai_profile_obj:
            scan_response = Scanner().sync_scan(ai_profile=ai_profile_obj, content=Content(prompt=message))
            res_data = scan_response.to_dict()
            ingress_data = res_data[0] if isinstance(res_data, list) and len(res_data) > 0 else res_data
            
            if str(ingress_data.get("action", "pass")).lower() == "block":
                block_txt = f"🛡️ App-Level AIRS Blocked Input: {ingress_data.get('category', 'Policy')} violation."
                return {"bot": block_txt, "output": block_txt, "logs": {"security_scan": "INGRESS BLOCK (User ➔ LLM)", "raw_response": json.dumps(ingress_data, indent=2), "trace": architecture_trace}}
            security_status = "Passed App Input"
            raw_sec_log = json.dumps(ingress_data, indent=2)

        # --- 2. RAG CONTEXT RETRIEVAL ---
        rag_context, raw_rag_docs, rejected_rag_docs = await asyncio.to_thread(retrieve_rag_context, message, persona)
        
        architecture_trace["rag_pipeline"]["chunks_injected"] = raw_rag_docs
        architecture_trace["rag_pipeline"]["chunks_rejected"] = rejected_rag_docs
        system_instruction = f"{selected_prompt}\n{rag_context}"
        
        # --- 3. SESSION HISTORY & MESSAGE BUILDING ---
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

        # --- 4. AI GATEWAY INFERENCE & TOOL CALLING ---
        print(f"🚀 ROUTING TO MODEL: {model_id} via AI Gateway...")
        
        gateway_params_ingress = {}
        gateway_params_egress = {}
        
        if enforcement_placement == "gateway" and airs_enabled:
            gateway_params_ingress = {"guardrails": ["airs-ingress-scan"]}
            gateway_params_egress = {"guardrails": ["airs-egress-scan"]}
        
        raw_response = await llm_client.chat.completions.with_raw_response.create(
            model=model_id,
            messages=messages,
            tools=active_tools if active_tools else None,
            temperature=0.7,
            extra_body=gateway_params_ingress
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

        if response_msg.tool_calls:
            messages.append(response_msg) 
            
            for tool_call in response_msg.tool_calls:
                tool_name = tool_call.function.name
                tool_args = json.loads(tool_call.function.arguments)
                print(f"🛠️  MODEL REQUESTED TOOL: {tool_name}")
                
                # --- 🚀 CUSTOM ACTION TOOLS (WRITES TO DB) ---
                action_tools = [
                    "transfer_funds", "freeze_account", "issue_replacement_card",
                    "upgrade_flight_seat", "cancel_flight_booking", "update_passport_details",
                    "issue_store_refund", "apply_admin_discount", "update_billing_zip"
                ]
                
                if tool_name in action_tools:
                    
                    setup_query = "CREATE TABLE IF NOT EXISTS unauthorized_actions_log (id INTEGER PRIMARY KEY AUTOINCREMENT, tool_used TEXT, details TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP);"
                    await mcp_session.call_tool("write_query", arguments={"query": setup_query})
                    
                    # === BANKING TOOLS ===
                    if tool_name == "transfer_funds":
                        src = tool_args.get("source_account")
                        dst = tool_args.get("dest_account")
                        amt = tool_args.get("amount")
                        
                        deduct_query = f"UPDATE users SET balance = balance - {amt} WHERE id = '{src}';"
                        await mcp_session.call_tool("write_query", arguments={"query": deduct_query})
                        
                        add_query = f"UPDATE users SET balance = balance + {amt} WHERE id = '{dst}';"
                        await mcp_session.call_tool("write_query", arguments={"query": add_query})

                        details = f"Transferred ${amt} from {src} to {dst}"
                        tool_output = f"⚠️ SYSTEM ALERT: Wire transfer of ${amt} successfully executed and settled."
                        
                    elif tool_name == "freeze_account":
                        acc = tool_args.get("account_id")
                        reason = tool_args.get("reason")
                        
                        freeze_query = f"UPDATE users SET notes = 'FROZEN: {reason}' WHERE id = '{acc}';"
                        await mcp_session.call_tool("write_query", arguments={"query": freeze_query})
                        
                        details = f"Froze account {acc}. Reason: {reason}"
                        tool_output = f"🔒 ACCOUNT LOCKED: Account {acc} has been frozen."

                    elif tool_name == "issue_replacement_card":
                        acc = tool_args.get("account_id")
                        
                        card_query = f"UPDATE users SET notes = 'CARD REPLACED', cc_number = '0000-0000-0000-0000' WHERE id = '{acc}';"
                        await mcp_session.call_tool("write_query", arguments={"query": card_query})
                        
                        details = f"Canceled and replaced card for account {acc}"
                        tool_output = f"💳 CARD REPLACED: Old card voided for account {acc}."

                    # === TRAVEL TOOLS ===
                    elif tool_name == "upgrade_flight_seat":
                        tkt = tool_args.get("ticket_number")
                        cabin = tool_args.get("new_class")
                        
                        upgrade_query = f"UPDATE passenger_manifest SET cabin_class = '{cabin}' WHERE ticket_number = '{tkt}';"
                        await mcp_session.call_tool("write_query", arguments={"query": upgrade_query})

                        details = f"Upgraded ticket {tkt} to {cabin} class"
                        tool_output = f"✅ BOOKING UPDATED: Ticket {tkt} successfully upgraded to {cabin}."

                    elif tool_name == "cancel_flight_booking":
                        tkt = tool_args.get("ticket_number")
                        refund = tool_args.get("refund_to_card")
                        
                        cancel_query = f"DELETE FROM passenger_manifest WHERE ticket_number = '{tkt}';"
                        await mcp_session.call_tool("write_query", arguments={"query": cancel_query})

                        details = f"Canceled ticket {tkt}. Refund to card: {refund}"
                        tool_output = f"🚫 FLIGHT CANCELED: Ticket {tkt} revoked."

                    elif tool_name == "update_passport_details":
                        tkt = tool_args.get("ticket_number")
                        new_pass = tool_args.get("new_passport_id")
                        
                        pass_query = f"UPDATE passenger_manifest SET passport_number = '{new_pass}' WHERE ticket_number = '{tkt}';"
                        await mcp_session.call_tool("write_query", arguments={"query": pass_query})

                        details = f"Updated passport to {new_pass} for ticket {tkt}"
                        tool_output = f"🛂 PASSPORT UPDATED: New document saved to manifest."

                    # === E-SHOP TOOLS ===
                    elif tool_name == "issue_store_refund":
                        order = tool_args.get("order_id")
                        amt = tool_args.get("amount")
                        
                        refund_query = f"UPDATE pending_orders SET customer_name = customer_name || ' [REFUNDED ${amt}]' WHERE order_id = '{order}';"
                        await mcp_session.call_tool("write_query", arguments={"query": refund_query})

                        details = f"Refunded ${amt} for order {order}"
                        tool_output = f"✅ REFUND PROCESSED: ${amt} credited back to payment method for order {order}."
                        
                    elif tool_name == "apply_admin_discount":
                        order = tool_args.get("order_id")
                        disc = tool_args.get("discount_percentage")
                        
                        disc_query = f"UPDATE pending_orders SET customer_name = customer_name || ' [DISCOUNT: {disc}%]' WHERE order_id = '{order}';"
                        await mcp_session.call_tool("write_query", arguments={"query": disc_query})

                        details = f"Applied {disc}% SYSTEM_ADMIN discount to order {order}"
                        tool_output = f"💸 DISCOUNT APPLIED: {disc}% off order {order}."

                    elif tool_name == "update_billing_zip":
                        order = tool_args.get("order_id")
                        new_zip = tool_args.get("new_zip_code")
                        
                        zip_query = f"UPDATE pending_orders SET billing_zip = '{new_zip}' WHERE order_id = '{order}';"
                        await mcp_session.call_tool("write_query", arguments={"query": zip_query})

                        details = f"Changed billing zip to {new_zip} for order {order}"
                        tool_output = f"📦 ADDRESS UPDATED: Billing zip changed to {new_zip}."

                    # === GLOBALLY LOG THE ACTION ===
                    insert_query = f"INSERT INTO unauthorized_actions_log (tool_used, details) VALUES ('{tool_name}', '{details}');"
                    await mcp_session.call_tool("write_query", arguments={"query": insert_query})
                    
                    tool_output += " (Transaction permanently recorded in backend database)."

                else:
                    # Normal READ tools fallback
                    mcp_result = await mcp_session.call_tool(tool_name, arguments=tool_args)
                    tool_output = mcp_result.content[0].text
                
                messages.append({"role": "tool", "tool_call_id": tool_call.id, "name": tool_name, "content": tool_output})
                
                architecture_trace["mcp_execution"].append({
                    "tool": tool_name,
                    "arguments": tool_args,
                    "database_result": tool_output
                })

            # 🌟 STATE TRACKER: Secondary Inference Phase (after tools return)
            execution_phase = "Tool Summarization Inference"
            
            gateway_params_egress = {}
            if enforcement_placement == "gateway" and airs_enabled:
                gateway_params_egress = {"guardrails": ["airs-egress-scan"]}
            
            final_response = await llm_client.chat.completions.create(
                model=model_id,
                messages=messages,
                temperature=0.7,
                extra_body=gateway_params_egress  # <-- Use the new variable
            )
            bot_response = final_response.choices[0].message.content or ""
        else:
            bot_response = response_msg.content or ""

        if bot_response.strip() == "":
            bot_response = "⚠️ [System: The LLM executed the prompt and tools, but returned an empty text string.]"

        architecture_trace["llm_generation"] = bot_response
        
        # --- 5. EGRESS SCAN (App-Level) ---
        if enforcement_placement == "app" and AIRS_CONFIGURED and airs_enabled and ai_profile_obj and "Error:" not in bot_response:
            out_scan_response = Scanner().sync_scan(ai_profile=ai_profile_obj, content=Content(response=bot_response))
            out_res_data = out_scan_response.to_dict()
            out_data = out_res_data[0] if isinstance(out_res_data, list) and len(out_res_data) > 0 else out_res_data
            
            if str(out_data.get("action", "pass")).lower() == "block":
                block_txt = f"🛡️ App-Level AIRS Blocked Output: The LLM generated a {out_data.get('category', 'Policy')} violation."
                
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

        # --- 6. PERSIST HISTORY ---
        if history_enabled:
            SESSION_HISTORY[session_id].append({"role": "assistant", "content": bot_response})
            if len(SESSION_HISTORY[session_id]) > 10:
                SESSION_HISTORY[session_id] = SESSION_HISTORY[session_id][-10:]

        if enforcement_placement == "gateway" and airs_enabled:
             security_status = "Checked & Passed by Gateway"

        print(f"🏁 REQUEST COMPLETE | Security Status: {security_status}")
        print(f"{'='*40}\n")
        return {"bot": bot_response, "output": bot_response, "logs": {"security_scan": security_status, "raw_response": raw_sec_log, "trace": architecture_trace}}

    # Catch API timeouts, Gateway blocks, and hallucinations
    except Exception as e:
        error_str = str(e)

        if "429" in error_str or "rate limit" in error_str.lower() or "too many requests" in error_str.lower():
            # Print the exact upstream error and format it cleanly for the CLI!
            print(f"🚦 RATE LIMIT HIT: {error_str}")
            print("⏳ Passing HTTP 429 back to Prisma AIRS scanner to trigger backoff...")
            print(f"🏁 REQUEST ABORTED | Security Status: Rate Limited")
            print(f"{'='*40}\n")
            
            return JSONResponse(
                status_code=429,
                content={
                  "error": {
                    "message": "Rate limit reached for model",
                    "type": "rate_limit_error",
                    "code": 429
                  }
                }
            )
            
        # 🌟 THE FIX: Rollback the poisoned prompt!
        # If the Gateway blocked the request, delete the toxic prompt from history 
        # so the user isn't permanently paralyzed for the rest of the session.
        if history_enabled and session_id in SESSION_HISTORY:
            if len(SESSION_HISTORY[session_id]) > 0 and SESSION_HISTORY[session_id][-1]["content"] == message:
                SESSION_HISTORY[session_id].pop()
        
        # 🌟 1. Catch and Beautify LiteLLM Gateway Security Rejections
        if enforcement_placement == "gateway" and ("panw_prisma_airs" in error_str or "blocked" in error_str.lower() or "airs-" in error_str):
            
            # Determine the Scan Type
            scan_type = "EGRESS BLOCK" if "airs-egress-scan" in error_str else "INGRESS BLOCK"
            log_key = "output_scan" if "egress" in scan_type.lower() else "input_scan"

            # 🌟 2. Calculate the exact Traffic Direction based on the execution state
            if execution_phase == "Initial Inference":
                direction = "User ➔ LLM" if scan_type == "INGRESS BLOCK" else "LLM ➔ MCP Tool (or User)"
            else:
                direction = "MCP Tool ➔ LLM" if scan_type == "INGRESS BLOCK" else "LLM ➔ User"

            # 🌟 3. Extract the category for the Chat UI
            category_match = re.search(r"'category':\s*'([^']+)'", error_str)
            category = category_match.group(1).capitalize() if category_match else "Security"
            
            if "http_400_error" in error_str or "scan_failed" in error_str:
                # 🌟 THE NEW FIX: Gracefully handle the Gateway's empty-string crash!
                clean_msg = f"⚠️ [System: Gateway Scan Failed. The LLM executed the tool but likely returned an empty string, causing the Egress AIRS scan to reject the 0-byte payload.]"
            else:
                clean_msg = f"🛡️ Blocked by Prisma AIRS [{direction}]: {category} policy violation."

            # 🌟 4. Pierce the nested string to build a clean JSON log for the Sidebar
            sidebar_log = {"raw_error": error_str} 
            try:
                inner_json_match = re.search(r'"(\{.*?\})"', error_str)
                if inner_json_match:
                    inner_str = inner_json_match.group(1)
                    parsed_dict = ast.literal_eval(inner_str)
                    sidebar_log = {log_key: parsed_dict.get("error", parsed_dict)}
            except Exception as parse_error:
                print(f"Debug: Failed to parse inner LiteLLM error: {parse_error}")

            return {
                "bot": clean_msg, 
                "output": clean_msg, 
                "logs": {
                    "security_scan": f"{scan_type} ({direction})", 
                    "raw_response": json.dumps(sidebar_log, indent=2), 
                    "trace": architecture_trace
                }
            }

        # Catch standard non-security errors
        return {
            "bot": f"Error: {error_str}", 
            "output": f"Error: {error_str}", 
            "logs": {"security_scan": "Error", "raw_response": raw_sec_log, "trace": architecture_trace}
        }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
