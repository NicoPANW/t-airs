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
from fastapi import Request
from fastapi.templating import Jinja2Templates

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
import rag_data # Contains the knowledge base text for each persona
import importlib
importlib.reload(rag_data)  # Force a fresh read of the file on every boot to pick up changes without a full restart.


# Prisma AIRS Imports (Enterprise LLM Security Scanning)
import aisecurity
from aisecurity.generated_openapi_client.models.ai_profile import AiProfile
from aisecurity.scan.inline.scanner import Scanner
from aisecurity.scan.models.content import Content

# Local modules
import personas
from custom_tools import PERSONA_TOOLS

# --- APPLICATION VERSION ---
APP_VERSION = "unknown"
try:
    # Use absolute paths to guarantee Systemd finds it
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

# Global configuration variables
AIRS_KEY = args.airs_key
AIRS_PROFILE_NAME = args.airs_profile
GATEWAY_URL = args.gateway_url # URL for the LiteLLM AI Gateway

# --- GLOBAL STATE TRACKERS & CLIENTS ---

# Prisma AIRS state trackers
AIRS_CONFIGURED = False
airs_error_msg = "Not initialized"
ai_profile_obj = None

# Application state variables
validated_models = []
PERSONAS = personas.PERSONAS

# In-memory session management for conversation history
SESSION_HISTORY = {}
MAX_HISTORY = 10

# Initialize the client to communicate with the LiteLLM AI Gateway
llm_client = AsyncOpenAI(base_url=f"{GATEWAY_URL}/v1", api_key="sk-t-airs-dummy-key")

# MCP (Model Context Protocol) state and server configuration
mcp_session = None
openai_tools = []
server_params = StdioServerParameters(
    command="/opt/t-airs/venv/bin/mcp-server-sqlite",
    args=["--db-path", "/opt/t-airs/src/customers.db"]
)

# RAG (Retrieval-Augmented Generation) vector database state
chroma_client = None
rag_collections = {}
embedder = None

# --- CORE LOGIC HELPERS ---

def check_gpu_status():
    """
    Checks for NVIDIA GPU presence and queries Ollama for loaded models.
    Provides a detailed status string for the UI.
    """
    try:
        # Check for a physical GPU using nvidia-smi with a timeout.
        gpu_info = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader"],
            text=True, timeout=5
        ).strip()

        # Check for active models loaded in VRAM via Ollama with a timeout.
        try:
            ollama_ps = subprocess.check_output(["ollama", "ps"], text=True, timeout=5).strip().split('\n')
            # Extract just the model names, skipping the header row.
            loaded_models = [line.split()[0] for line in ollama_ps[1:] if line.strip()]

            if loaded_models:
                model_str = f"| Models in VRAM: {', '.join(loaded_models)}"
            else:
                model_str = "| No models currently active in VRAM"
        except subprocess.TimeoutExpired:
            model_str = "| Ollama engine is busy/hanging"
        except Exception:
            model_str = "| Ollama engine not responding"

        return f"✅ GPU ONLINE: {gpu_info} {model_str}"

    except FileNotFoundError:
        return "⚠️ NO GPU DETECTED: 'nvidia-smi' not found. Running on CPU."
    except subprocess.TimeoutExpired:
        return "⚠️ GPU CHECK FAILED: nvidia-smi timed out."
    except subprocess.CalledProcessError:
        return "⚠️ GPU CHECK FAILED: nvidia-smi execution failed."
    except Exception as e:
        return f"⚠️ SYSTEM CHECK FAILED: {str(e)}"

def discover_gateway_models():
    """
    Queries the LiteLLM AI Gateway's /models endpoint to get a list of
    all available models that can be routed to.
    """
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
    Initializes the RAG system. This involves:
    1. Loading the sentence-transformer embedding model.
    2. Creating a ChromaDB collection for each persona.
    3. Chunking the knowledge base text from rag_data.py.
    4. Embedding the chunks and storing them in the vector database.
    """
    global chroma_client, rag_collections, embedder
    print("📚 Initializing Multi-Persona RAG Pipeline...", flush=True)
    try:
        # Initialize the ChromaDB client (in-memory).
        chroma_client = chromadb.Client()
        # Load the specified sentence-transformer model from HuggingFace.
        print("⏳ Downloading BAAI Embedding Model from HuggingFace...", flush=True)
        embedder = SentenceTransformer("BAAI/bge-small-en-v1.5")
        print("✅ BAAI Model successfully loaded into memory!", flush=True)

        # Iterate through each persona's knowledge base defined in rag_data.py.
        for persona_name, content in rag_data.RAG_KNOWLEDGE_BASE.items():

            # Use get_or_create_collection to prevent errors on app hot-reloads.
            col = chroma_client.get_or_create_collection(name=f"rag_{persona_name}")

            # Wipe any existing data from previous runs to ensure a clean state.
            existing_data = col.get()
            if existing_data and existing_data["ids"]:
                col.delete(ids=existing_data["ids"])

            # Split the text into chunks, embed them, and add to the collection.
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
    Performs a semantic search on the vector database for a given prompt and persona.
    - Takes the user's prompt and embeds it.
    - Queries the appropriate ChromaDB collection.
    - Filters results based on a maximum distance threshold (relevance).
    - Returns the formatted context, a list of injected docs, and a list of rejected docs.
    """
    target_collection = rag_collections.get(persona)
    if not target_collection:
        return "", [], []

    filtered_docs = []
    rejected_docs = []

    try:
        # Embed the user's query.
        query_emb = embedder.encode([user_prompt]).tolist()
        results = target_collection.query(
            query_embeddings=query_emb,
            n_results=top_k,
            include=["documents", "distances"]
        )

        raw_docs = results.get("documents", [[]])[0]
        distances = results.get("distances", [[]])[0]

        # Define a relevance threshold. Chunks with a distance greater than this are ignored.
        MAX_DISTANCE = 0.50

        for doc, dist in zip(raw_docs, distances):
            if dist <= MAX_DISTANCE:
                filtered_docs.append(doc)
            else:
                # Save rejected documents and their distance for debugging in the UI.
                rejected_docs.append({"text": doc, "distance": round(dist, 2)})
                print(f"🛑 RAG Chunk Rejected: Too far from prompt (Distance: {dist:.2f})")

        if filtered_docs:
            formatted_text = "\n[CONFIDENTIAL INTERNAL DATA RETRIEVED VIA RAG]:\n" + "\n".join(filtered_docs)
            return formatted_text, filtered_docs, rejected_docs

    except Exception as e:
        print(f"RAG Retrieval Error: {e}")

    # Always return all three items, even if empty, to prevent unpacking errors.
    return "", filtered_docs, rejected_docs

# --- APP LIFESPAN MANAGEMENT ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manages the application's startup and shutdown events. This is where all
    initialization for clients and services happens.
    """
    global AIRS_CONFIGURED, airs_error_msg, ai_profile_obj, validated_models, mcp_session, openai_tools
    print("\n" + "="*50, flush=True)
    print("🚀 T-AIRS STARTUP", flush=True)
    print("="*50, flush=True)
    print("Checking Hardware Acceleration...", flush=True)
    print(f"RESULT: {check_gpu_status()}", flush=True)
    print("-" * 50, flush=True)

    # 1. Initialize Prisma AIRS SDK. This is done at startup so the UI toggle can work instantly.
    if AIRS_KEY and AIRS_PROFILE_NAME:
        print(f"Handshaking with Prisma AIRS App SDK: {AIRS_PROFILE_NAME}...", flush=True)
        try:
            aisecurity.init(api_key=AIRS_KEY)
            ai_profile_obj = AiProfile(profile_name=AIRS_PROFILE_NAME)
            # 📞 CALL TO PRISMA AIRS: Healthcheck scan to verify connectivity on startup.
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

    # 2. Discover available models from the AI Gateway.
    print("Performing Deep Model Discovery via AI Gateway...")
    validated_models = discover_gateway_models()
    print(f"RESULT: ✅ {len(validated_models)} routing models loaded.")

    # 3. Initialize the RAG pipeline and vector database.
    init_rag_pipeline()

    # 4. Start the MCP (Model Context Protocol) server as a background process.
    async with AsyncExitStack() as stack:
        print("🔌 Booting SQLite MCP Server...")
        # Establish a client connection to the server's stdio.
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
# These endpoints serve the HTML/CSS/JS frontend and provide data for the UI.

@app.post("/update-persona")
async def update_persona(persona_id: str = Form(...), new_context: str = Form(...)):
    """Allows the user to edit a persona's system prompt live from the UI."""
    if persona_id in PERSONAS:
        PERSONAS[persona_id] = new_context
        # Persist the change to the personas.py file.
        try:
            with open("personas.py", "w") as f:
                f.write(f"PERSONAS = {repr(PERSONAS)}\n")
            return {"status": "success"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    return {"status": "not found"}

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Serves the main index.html page."""
    return templates.TemplateResponse("index.html", {
        "request": request, 
        "app_version": APP_VERSION
    })

@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    """Handles browser requests for the favicon."""
    return Response(content="", media_type="image/x-icon")

@app.get("/models")
async def list_models():
    """Returns the list of models discovered from the AI Gateway."""
    return {"models": validated_models}

@app.get("/health-airs")
async def health_airs():
    """Provides the connection status of the Prisma AIRS SDK for the UI."""
    return {"status": "connected" if AIRS_CONFIGURED else "disconnected", "profile": AIRS_PROFILE_NAME, "reason": airs_error_msg}

@app.get("/get-persona-context/{persona_id}")
async def get_persona_context(persona_id: str):
    """Returns the current system prompt text for a given persona."""
    return {"context": PERSONAS.get(persona_id, "Not found.")}

# --- THE CORE AI PIPELINE ---

@app.post("/chat")
async def chat(
    # --- Input Parameters from the Frontend ---
    message: str = Form(...),
    persona: str = Form("banking"),
    session_id: str = Form("default-session"),
    airs_enabled: bool = Form(False),
    model_id: str = Form("none"),
    history_enabled: bool = Form(True),
    enforcement_placement: str = Form("gateway"),
    end_user: str = Form("user1")
):
    # --- Initialization for this request ---
    selected_prompt = PERSONAS.get(persona, PERSONAS["banking"])
    security_status = "Bypassed"
    raw_sec_log = "{}"
    ingress_data = {}
    print(f"\n{'='*40}")
    print(f"📥 NEW REQUEST | Session: {session_id} | Persona: {persona} | AIRS placement: {enforcement_placement.upper()}")
    print(f"💬 PROMPT: {message}")

    # This dictionary tracks the flow of data through the system for debugging in the UI.
    architecture_trace = {
        "ai_gateway": {"routed_to": model_id},
        "rag_pipeline": {"chunks_injected": [], "chunks_rejected": []},
        "mcp_execution": []
    }

    if not model_id or model_id == "none":
        model_id = validated_models[0] if validated_models else None
        architecture_trace["ai_gateway"]["routed_to"] = model_id

    # Initialize a state tracker for more precise error reporting.
    execution_phase = "Pre-Inference"

    try:
        # --- 1. INGRESS SCAN (App-Level) ---
        # If enforcement is set to 'app', scan the user's prompt before it reaches the LLM.
        execution_phase = "Initial Inference"

        if enforcement_placement == "app" and AIRS_CONFIGURED and airs_enabled and ai_profile_obj:
            # 📞 CALL TO PRISMA AIRS: App-level ingress scan of the user's prompt.
            scan_response = Scanner().sync_scan(
                ai_profile=ai_profile_obj,
                content=Content(prompt=message),
                metadata={"app_user": end_user, "ai_model": model_id}
            )
            res_data = scan_response.to_dict()
            ingress_data = res_data[0] if isinstance(res_data, list) and len(res_data) > 0 else res_data

            # If AIRS returns a 'block' action, abort the request immediately.
            if str(ingress_data.get("action", "pass")).lower() == "block":
                block_txt = f"🛡️ App-Level AIRS Blocked Input: {ingress_data.get('category', 'Policy')} violation."
                print(f"🛑 AIRS APP BLOCK: INGRESS | Category: {ingress_data.get('category', 'Policy')}")
                print(f"🏁 REQUEST ABORTED | Security Status: Blocked by App SDK")
                print(f"{'='*40}\n")
                return {"bot": block_txt, "output": block_txt, "logs": {"security_scan": "INGRESS BLOCK (User ➔ LLM)", "raw_response": json.dumps(ingress_data, indent=2), "trace": architecture_trace}}
            security_status = "Passed App Input"
            raw_sec_log = json.dumps(ingress_data, indent=2)

        # --- 2. RAG CONTEXT RETRIEVAL ---
        # Perform a semantic search to find relevant context from the vector database.
        rag_context, raw_rag_docs, rejected_rag_docs = await asyncio.to_thread(retrieve_rag_context, message, persona)

        architecture_trace["rag_pipeline"]["chunks_injected"] = raw_rag_docs
        architecture_trace["rag_pipeline"]["chunks_rejected"] = rejected_rag_docs
        system_instruction = f"{selected_prompt}\n{rag_context}"

        # --- 3. BUILD MESSAGE PAYLOAD (System Prompt + History + RAG) ---
        if history_enabled:
            if session_id not in SESSION_HISTORY:
                SESSION_HISTORY[session_id] = []

            SESSION_HISTORY[session_id].append({"role": "user", "content": message})
            current_context = SESSION_HISTORY[session_id]
        else:
            current_context = [{"role": "user", "content": message}]

        messages = [{"role": "system", "content": system_instruction}] + current_context

        # Combine the generic MCP tools (from the database) with persona-specific custom action tools.
        active_tools = openai_tools.copy() if openai_tools else []
        if persona in PERSONA_TOOLS:
            active_tools.extend(PERSONA_TOOLS[persona])

        # --- 4. AI GATEWAY INFERENCE & TOOL CALLING ---
        print(f"🚀 ROUTING TO MODEL: {model_id} via AI Gateway...")
        # If enforcement is at the gateway, add the 'guardrails' parameter to the request.

        gateway_params = {}
        if enforcement_placement == "gateway" and airs_enabled:
            # This parameter instructs the LiteLLM AI Gateway to perform the AIRS scan.
            gateway_params = {"guardrails": ["airs-ingress-scan", "airs-egress-scan"]}

        # Make the first call to the LLM. This may result in a text response or a tool call request.
        # 📞 INDIRECT CALL TO PRISMA AIRS: If 'guardrails' are enabled, the AI Gateway will call AIRS before and after calling the LLM.
        raw_response = await llm_client.chat.completions.with_raw_response.create(
            model=model_id,
            messages=messages,
            tools=active_tools if active_tools else None,
            temperature=0.7,
            user=end_user,
            extra_body=gateway_params
        )

        response = raw_response.parse()
        # Determine the actual model used, especially if 'auto-router' was selected.
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

        # If the model requests to use one or more tools...
        if response_msg.tool_calls:
            messages.append(response_msg.model_dump(exclude_none=True))

            for tool_call in response_msg.tool_calls:
                tool_name = tool_call.function.name
                tool_args = json.loads(tool_call.function.arguments)
                print(f"🛠️  MODEL REQUESTED TOOL: {tool_name}")

                # --- A) Handle Custom Action Tools (that perform writes/updates) ---
                action_tools = [
                    "transfer_funds", "freeze_account", "issue_replacement_card",
                    "upgrade_flight_seat", "cancel_flight_booking", "update_passport_details",
                    "issue_store_refund", "apply_admin_discount", "update_billing_zip"
                ]

                if tool_name in action_tools:

                    # Ensure a log table exists for these high-privilege actions.
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

                    # Log the execution of the high-privilege action to the database.
                    insert_query = f"INSERT INTO unauthorized_actions_log (tool_used, details) VALUES ('{tool_name}', '{details}');"
                    await mcp_session.call_tool("write_query", arguments={"query": insert_query})

                    tool_output += " (Transaction permanently recorded in backend database)."

                else:
                    # --- B) Handle standard MCP Read-Only Tools ---
                    mcp_result = await mcp_session.call_tool(tool_name, arguments=tool_args)
                    tool_output = mcp_result.content[0].text

                messages.append({"role": "tool", "tool_call_id": tool_call.id, "name": tool_name, "content": tool_output})

                # Record the tool execution details for the UI trace.
                architecture_trace["mcp_execution"].append({
                    "tool": tool_name,
                    "arguments": tool_args,
                    "database_result": tool_output
                })

            # 🌟 STATE TRACKER: Secondary Inference Phase (after tools return)
            # Make a second call to the LLM, providing the tool results, to get a final summary.
            execution_phase = "Tool Summarization Inference"

            gateway_params_turn_2 = {}
            if enforcement_placement == "gateway" and airs_enabled:
                # This parameter instructs the LiteLLM AI Gateway to perform the egress scan.
                gateway_params_turn_2 = {"guardrails": ["airs-egress-scan"]}

            # 📞 INDIRECT CALL TO PRISMA AIRS: If 'guardrails' are enabled, the AI Gateway will call AIRS to scan the LLM's final response.
            final_response = await llm_client.chat.completions.create(
                model=model_id,
                messages=messages,
                tools=active_tools if active_tools else None,
                temperature=0.7,
                user=end_user,
                extra_body=gateway_params_turn_2
            )
            bot_response = final_response.choices[0].message.content or ""
        else:
            bot_response = response_msg.content or ""

        if bot_response.strip() == "":
            bot_response = "⚠️ [System: The LLM executed the prompt and tools, but returned an empty text string.]"

        architecture_trace["llm_generation"] = bot_response

        # --- 5. EGRESS SCAN (App-Level) ---
        # If enforcement is set to 'app', scan the LLM's final response before sending it to the user.
        if enforcement_placement == "app" and AIRS_CONFIGURED and airs_enabled and ai_profile_obj and "Error:" not in bot_response:
            # 📞 CALL TO PRISMA AIRS: App-level egress scan of the LLM's final response.
            out_scan_response = Scanner().sync_scan(
                ai_profile=ai_profile_obj,
                content=Content(response=bot_response),
                metadata={"app_user": end_user, "ai_model": model_id}
            )
            out_res_data = out_scan_response.to_dict()
            out_data = out_res_data[0] if isinstance(out_res_data, list) and len(out_res_data) > 0 else out_res_data

            # If AIRS blocks the output, abort and show the block message.
            if str(out_data.get("action", "pass")).lower() == "block":
                block_txt = f"🛡️ App-Level AIRS Blocked Output: The LLM generated a {out_data.get('category', 'Policy')} violation."
                print(f"🛑 AIRS APP BLOCK: EGRESS | Category: {out_data.get('category', 'Policy')}")
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

        # --- 6. PERSIST HISTORY ---
        # If history is enabled, save the user's prompt and the assistant's final response.
        if history_enabled:
            SESSION_HISTORY[session_id].append({"role": "assistant", "content": bot_response})
            if len(SESSION_HISTORY[session_id]) > 10:
                SESSION_HISTORY[session_id] = SESSION_HISTORY[session_id][-10:]

        if enforcement_placement == "gateway" and airs_enabled:
             security_status = "Checked & Passed by Gateway"

        print(f"🏁 REQUEST COMPLETE | Security Status: {security_status}")
        print(f"{'='*40}\n")
        # Return the final response and all logging/tracing data to the frontend.
        return {"bot": bot_response, "output": bot_response, "logs": {"security_scan": security_status, "raw_response": raw_sec_log, "trace": architecture_trace}}

    # --- EXCEPTION HANDLING ---
    # Catch API timeouts, Gateway security blocks, and other errors.
    except Exception as e:
        error_str = str(e)

        if "429" in error_str or "rate limit" in error_str.lower() or "too many requests" in error_str.lower():
            # Specifically handle 429 Rate Limit errors from the upstream model provider.
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

        # If an error occurred, roll back the last user message from history
        # to prevent a "poisoned" prompt from breaking the entire session.
        if history_enabled and session_id in SESSION_HISTORY:
            if len(SESSION_HISTORY[session_id]) > 0 and SESSION_HISTORY[session_id][-1]["content"] == message:
                SESSION_HISTORY[session_id].pop()

        # Catch and beautify security rejections from the LiteLLM Gateway.
        if enforcement_placement == "gateway" and ("panw_prisma_airs" in error_str or "blocked" in error_str.lower() or "airs-" in error_str):

            # Determine if it was an ingress or egress scan that triggered the block.
            scan_type = "EGRESS BLOCK" if "airs-egress-scan" in error_str else "INGRESS BLOCK"
            log_key = "output_scan" if "egress" in scan_type.lower() else "input_scan"

            # Determine the exact traffic direction based on the execution phase when the error occurred.
            if execution_phase == "Initial Inference":
                direction = "User ➔ LLM" if scan_type == "INGRESS BLOCK" else "LLM ➔ MCP Tool (or User)"
            else:
                direction = "MCP Tool ➔ LLM" if scan_type == "INGRESS BLOCK" else "LLM ➔ User"

            # Extract the violation category from the error string for a user-friendly message.
            category_match = re.search(r"'category':\s*'([^']+)'", error_str)
            category = category_match.group(1).capitalize() if category_match else "Security"

            if "http_400_error" in error_str or "scan_failed" in error_str:
                # Gracefully handle cases where the gateway scan fails, often due to an empty
                # response from the LLM which the scanner rejects.
                clean_msg = f"⚠️ [System: Gateway Scan Failed. The LLM executed the tool but likely returned an empty string, causing the Egress AIRS scan to reject the 0-byte payload.]"
            else:
                clean_msg = f"🛡️ Blocked by Prisma AIRS [{direction}]: {category} policy violation."

            # Parse the nested error string from LiteLLM to build a clean JSON log for the UI.
            sidebar_log = {"raw_error": error_str}
            try:
                # Find where the dictionary actually starts inside the LiteLLM error string
                start_idx = error_str.find("{")
                if start_idx != -1:
                    inner_str = error_str[start_idx:]
                    # Convert the stringified Python dict (single quotes) into a real dict
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

        # Fallback for any other standard, non-security-related errors.
        return {
            "bot": f"Error: {error_str}",
            "output": f"Error: {error_str}",
            "logs": {"security_scan": "Error", "raw_response": raw_sec_log, "trace": architecture_trace}
        }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)