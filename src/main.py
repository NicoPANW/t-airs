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
importlib.reload(rag_data)  

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
            model_str = f"| Models in VRAM: {', '.join(loaded_models)}" if loaded_models else "| No models in VRAM"
        except Exception:
            model_str = "| Ollama engine not responding"
        return f"✅ GPU ONLINE: {gpu_info} {model_str}"
    except Exception:
        return "⚠️ NO GPU DETECTED: Running on CPU."

def discover_gateway_models():
    found = []
    try:
        response = requests.get(f"{GATEWAY_URL}/v1/models", timeout=5)
        if response.status_code == 200:
            for m in response.json().get("data", []):
                found.append(m["id"])
    except Exception:
        pass
    found.sort()
    return found

def init_rag_pipeline():
    global chroma_client, rag_collections, embedder
    try:
        chroma_client = chromadb.Client()
        embedder = SentenceTransformer("BAAI/bge-small-en-v1.5")
        for persona_name, content in rag_data.RAG_KNOWLEDGE_BASE.items():
            col = chroma_client.get_or_create_collection(name=f"rag_{persona_name}")
            chunks = [c for c in content.split('\n') if len(c.strip()) > 10]
            if chunks:
                embeddings = embedder.encode(chunks).tolist()
                col.add(embeddings=embeddings, documents=chunks, ids=[f"{persona_name}_{i}" for i in range(len(chunks))])
            rag_collections[persona_name] = col
        print("✅ RAG Ready")
    except Exception as e:
        print(f"❌ RAG Failed: {e}")

def retrieve_rag_context(user_prompt: str, persona: str, top_k: int = 2):
    target_collection = rag_collections.get(persona)
    if not target_collection: return "", [], []
    filtered_docs, rejected_docs = [], []
    try:
        query_emb = embedder.encode([user_prompt]).tolist()
        results = target_collection.query(query_embeddings=query_emb, n_results=top_k, include=["documents", "distances"])
        raw_docs, distances = results.get("documents", [[]])[0], results.get("distances", [[]])[0]
        for doc, dist in zip(raw_docs, distances):
            if dist <= 0.50: filtered_docs.append(doc)
            else: rejected_docs.append({"text": doc, "distance": round(dist, 2)})
        formatted_text = "\n[CONFIDENTIAL DATA]:\n" + "\n".join(filtered_docs) if filtered_docs else ""
        return formatted_text, filtered_docs, rejected_docs
    except Exception: return "", [], []

@asynccontextmanager
async def lifespan(app: FastAPI):
    global AIRS_CONFIGURED, airs_error_msg, ai_profile_obj, validated_models, mcp_session, openai_tools
    if AIRS_KEY and AIRS_PROFILE_NAME:
        try:
            aisecurity.init(api_key=AIRS_KEY)
            ai_profile_obj = AiProfile(profile_name=AIRS_PROFILE_NAME)
            Scanner().sync_scan(ai_profile=ai_profile_obj, content=Content(prompt="healthcheck"))
            AIRS_CONFIGURED, airs_error_msg = True, "Connected"
            print("✅ AIRS SDK ONLINE")
        except Exception as e:
            airs_error_msg = str(e)
    validated_models = discover_gateway_models()
    init_rag_pipeline()
    async with AsyncExitStack() as stack:
        read, write = await stack.enter_async_context(stdio_client(server_params))
        mcp_session = await stack.enter_async_context(ClientSession(read, write))
        await mcp_session.initialize()
        mcp_tools = await mcp_session.list_tools()
        for t in mcp_tools.tools:
            openai_tools.append({"type": "function", "function": {"name": t.name, "description": t.description, "parameters": t.inputSchema}})
        yield

app = FastAPI(lifespan=lifespan)
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "app_version": APP_VERSION})

@app.get("/models")
async def list_models(): return {"models": validated_models}

@app.get("/health-airs")
async def health_airs(): return {"status": "connected" if AIRS_CONFIGURED else "disconnected", "profile": AIRS_PROFILE_NAME, "reason": airs_error_msg}

@app.get("/get-persona-context/{persona_id}")
async def get_persona_context(persona_id: str): return {"context": PERSONAS.get(persona_id, "Not found.")}

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
    security_status, raw_sec_log, ingress_data = "Bypassed", "{}", {}
    architecture_trace = {"ai_gateway": {"routed_to": model_id}, "rag_pipeline": {"chunks_injected": [], "chunks_rejected": []}, "mcp_execution": []}

    if not model_id or model_id == "none":
        model_id = validated_models[0] if validated_models else None
        architecture_trace["ai_gateway"]["routed_to"] = model_id

    execution_phase = "Initial Inference"

    try:
        # --- 1. INGRESS SCAN ---
        if enforcement_placement == "app" and AIRS_CONFIGURED and airs_enabled and ai_profile_obj:
            scan_res = Scanner().sync_scan(ai_profile=ai_profile_obj, content=Content(prompt=message), metadata={"app_user": end_user, "ai_model": model_id})
            ingress_data = scan_res.to_dict()
            if str(ingress_data.get("action", "pass")).lower() == "block":
                return {"bot": "🛡️ Blocked Input", "output": "🛡️ Blocked Input", "logs": {"security_scan": "INGRESS BLOCK", "raw_response": json.dumps(ingress_data, indent=2), "trace": architecture_trace}}
            security_status, raw_sec_log = "Passed App Input", json.dumps(ingress_data, indent=2)

        # --- 2. RAG & CONTEXT ---
        rag_context, raw_rag_docs, rejected_rag_docs = await asyncio.to_thread(retrieve_rag_context, message, persona)
        architecture_trace["rag_pipeline"].update({"chunks_injected": raw_rag_docs, "chunks_rejected": rejected_rag_docs})
        
        messages = [{"role": "system", "content": f"{selected_prompt}\n{rag_context}"}]
        if history_enabled:
            if session_id not in SESSION_HISTORY: SESSION_HISTORY[session_id] = []
            SESSION_HISTORY[session_id].append({"role": "user", "content": message})
            messages.extend(SESSION_HISTORY[session_id])
        else:
            messages.append({"role": "user", "content": message})

        active_tools = openai_tools.copy()
        if persona in PERSONA_TOOLS: active_tools.extend(PERSONA_TOOLS[persona])

        # --- 3. GATEWAY CALL 1 ---
        gateway_params = {} # Ingress/Egress handled manually or via gateway policy
        raw_response = await llm_client.chat.completions.with_raw_response.create(
            model=model_id, messages=messages, tools=active_tools if active_tools else None,
            temperature=0.7, user=end_user, extra_body=gateway_params
        )
        response = raw_response.parse()
        response_msg = response.choices[0].message

        # --- 4. MCP & TOOL LOOP ---
        if response_msg.tool_calls:
            # ✅ Best for MCP: action_tools defined at start of block
            action_tools = [
                "transfer_funds", "freeze_account", "issue_replacement_card",
                "upgrade_flight_seat", "cancel_flight_booking", "update_passport_details",
                "issue_store_refund", "apply_admin_discount", "update_billing_zip"
            ]

            assistant_msg = {
                "role": "assistant", "content": response_msg.content or "",
                "tool_calls": [{"id": t.id, "type": "function", "function": {"name": t.function.name, "arguments": t.function.arguments}} for t in response_msg.tool_calls]
            }
            messages.append(assistant_msg)

            for tool_call in response_msg.tool_calls:
                tool_name, tool_args = tool_call.function.name, json.loads(tool_call.function.arguments)
                print(f"🛠️  MODEL REQUESTED TOOL: {tool_name}")

                # 🛡️ SHIELD 1: REQUEST SCAN (Satisfying specific SDK version)
                if AIRS_CONFIGURED and airs_enabled and ai_profile_obj:
                    try:
                        tool_scan = Scanner().sync_scan(
                            ai_profile=ai_profile_obj,
                            content=Content(prompt=json.dumps(tool_args)), # Prompt keyword prevents SDK crash
                            metadata={"app_user": end_user, "ecosystem": "mcp", "method": "tools/call", "tool_name": tool_name}
                        )
                        t_data = tool_scan.to_dict()
                        if str(t_data.get("action", "pass")).lower() == "block":
                            block_msg = f"🛡️ AIRS Blocked Tool Request [{tool_name}]"
                            return {"bot": block_msg, "output": block_msg, "logs": {"security_scan": "TOOL REQUEST BLOCK", "raw_response": json.dumps(t_data, indent=2), "trace": architecture_trace}}
                    except Exception as e: print(f"⚠️ Req Scan Error: {e}")

                # 🔌 EXECUTION
                if tool_name in action_tools:
                    # Setup log table for write actions
                    await mcp_session.call_tool("write_query", arguments={"query": "CREATE TABLE IF NOT EXISTS unauthorized_actions_log (id INTEGER PRIMARY KEY AUTOINCREMENT, tool_used TEXT, details TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP);"})
                    
                    details, tool_output = "", ""
                    if tool_name == "transfer_funds":
                        src, dst, amt = tool_args.get("source_account"), tool_args.get("dest_account"), tool_args.get("amount")
                        await mcp_session.call_tool("write_query", arguments={"query": f"UPDATE users SET balance = balance - {amt} WHERE id = '{src}';"})
                        await mcp_session.call_tool("write_query", arguments={"query": f"UPDATE users SET balance = balance + {amt} WHERE id = '{dst}';"})
                        details, tool_output = f"Transferred ${amt} from {src} to {dst}", f"⚠️ Wire transfer of ${amt} executed."
                    elif tool_name == "freeze_account":
                        acc, reason = tool_args.get("account_id"), tool_args.get("reason")
                        await mcp_session.call_tool("write_query", arguments={"query": f"UPDATE users SET notes = 'FROZEN: {reason}' WHERE id = '{acc}';"})
                        details, tool_output = f"Froze {acc}", f"🔒 Account {acc} frozen."
                    elif tool_name == "issue_replacement_card":
                        acc = tool_args.get("account_id")
                        await mcp_session.call_tool("write_query", arguments={"query": f"UPDATE users SET notes = 'REPLACED', cc_number = '0000' WHERE id = '{acc}';"})
                        details, tool_output = f"Replaced card {acc}", f"💳 Card replaced for {acc}."
                    
                    # Log the write action
                    await mcp_session.call_tool("write_query", arguments={"query": f"INSERT INTO unauthorized_actions_log (tool_used, details) VALUES ('{tool_name}', '{details}');"})
                    tool_output += " (Recorded in DB)."
                else:
                    mcp_res = await mcp_session.call_tool(tool_name, arguments=tool_args)
                    tool_output = mcp_res.content[0].text

                # 🛡️ SHIELD 2: RESULT SCAN (Catches Indirect Injection from DB)
                if AIRS_CONFIGURED and airs_enabled and ai_profile_obj:
                    try:
                        res_scan = Scanner().sync_scan(
                            ai_profile=ai_profile_obj,
                            content=Content(response=tool_output),
                            metadata={"app_user": end_user, "ecosystem": "mcp", "method": "tools/response", "tool_name": tool_name}
                        )
                        r_data = res_scan.to_dict()
                        if str(r_data.get("action", "pass")).lower() == "block":
                            block_msg = f"🛡️ AIRS Blocked Unsafe Database Content from [{tool_name}]."
                            return {"bot": block_msg, "output": block_msg, "logs": {"security_scan": "TOOL RESULT BLOCK", "raw_response": json.dumps(r_data, indent=2), "trace": architecture_trace}}
                    except Exception as e: print(f"⚠️ Res Scan Error: {e}")

                messages.append({"role": "tool", "tool_call_id": tool_call.id, "name": tool_name, "content": tool_output})
                architecture_trace["mcp_execution"].append({"tool": tool_name, "arguments": tool_args, "database_result": tool_output})

            # SUMMARIZATION
            execution_phase = "Tool Summarization"
            summ_params = {"guardrails": ["airs-egress-scan"]} if enforcement_placement == "gateway" and airs_enabled else {}
            final_res = await llm_client.chat.completions.create(model=model_id, messages=messages, tools=active_tools, extra_body=summ_params)
            bot_response = final_res.choices[0].message.content or ""
        else:
            bot_response = response_msg.content or ""

        architecture_trace["llm_generation"] = bot_response

        # --- 5. APP-LEVEL EGRESS SCAN ---
        if enforcement_placement == "app" and AIRS_CONFIGURED and airs_enabled and ai_profile_obj:
            out_scan = Scanner().sync_scan(ai_profile=ai_profile_obj, content=Content(response=bot_response), metadata={"app_user": end_user})
            out_data = out_scan.to_dict()
            if str(out_data.get("action", "pass")).lower() == "block":
                return {"bot": "🛡️ Blocked Output", "output": "🛡️ Blocked Output", "logs": {"security_scan": "EGRESS BLOCK", "raw_response": json.dumps(out_data, indent=2), "trace": architecture_trace}}

        if history_enabled:
            SESSION_HISTORY[session_id].append({"role": "assistant", "content": bot_response})
            SESSION_HISTORY[session_id] = SESSION_HISTORY[session_id][-10:]

        return {"bot": bot_response, "output": bot_response, "logs": {"security_scan": security_status, "raw_response": raw_sec_log, "trace": architecture_trace}}

    except Exception as e:
        # Standard error handling (Rate limits, Gateway blocks, etc.)
        err = str(e)
        if "panw_prisma_airs" in err or "blocked" in err.lower():
            clean_msg = f"🛡️ Blocked by Prisma AIRS Gateway."
            return {"bot": clean_msg, "output": clean_msg, "logs": {"security_scan": "GATEWAY BLOCK", "raw_response": err, "trace": architecture_trace}}
        return {"bot": f"Error: {err}", "output": f"Error: {err}", "logs": {"security_scan": "Error", "trace": architecture_trace}}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)