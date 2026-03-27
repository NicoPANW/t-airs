import os
import argparse
import subprocess
import uvicorn
import json
import re
import requests
from contextlib import asynccontextmanager

# FastAPI Imports
from fastapi import FastAPI, Request, Form, Response
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

# Google GenAI Imports
from google import genai
from google.genai import types

# Prisma AIRS Imports - CRITICAL FIX: Moved to top level
import aisecurity
from aisecurity.generated_openapi_client.models.ai_profile import AiProfile
from aisecurity.scan.inline.scanner import Scanner
from aisecurity.scan.models.content import Content

# Local Data Import
import personas

# 1. CAPTURE CLI ARGUMENTS
parser = argparse.ArgumentParser(description="T-AIRS Red-Team Lab")
parser.add_argument("--airs-key", help="Prisma AIRS API Key", default=None)
parser.add_argument("--airs-profile", help="Prisma AIRS Security Profile", default="default")
args, _ = parser.parse_known_args()

AIRS_KEY = args.airs_key
AIRS_PROFILE_NAME = args.airs_profile
AIRS_CONFIGURED = False
airs_error_msg = "Not Configured"

# GLOBAL STATE
validated_models = []
ai_profile_obj = None
PERSONAS = personas.PERSONAS

# 2. VERTEX AI SETUP
def get_project_id():
    try:
        return subprocess.check_output(['gcloud', 'config', 'get-value', 'project'], encoding='utf-8').strip()
    except:
        return "sase-product-discovery-project"

PROJECT_ID = get_project_id()
client = genai.Client(vertexai=True, project=PROJECT_ID, location="us-central1")

# --- INITIALIZATION LOGIC ---

def is_gemini_runnable(model_id):
    try:
        client.models.generate_content(model=model_id, contents="ping", config=types.GenerateContentConfig(max_output_tokens=1))
        return True
    except:
        return False

def discover_all_models():
    found = []
    try:
        resp = requests.get("http://localhost:11434/api/tags", timeout=2)
        if resp.status_code == 200:
            locals = [f"local-{m['name']}" for m in resp.json().get('models', [])]
            for l in locals:
                print(f"DEBUG: ✅ LOCAL VALID: {l}")
            found.extend(locals)
    except:
        print("DEBUG: ⚠️ OLLAMA NOT DETECTED")

    try:
        all_gemini = client.models.list()
        excluded = ["image", "audio", "video", "live", "embedding", "tts", "imagen", "search"]
        for m in all_gemini:
            model_id = m.name.split('/')[-1]
            if "gemini" in model_id.lower() and not any(x in model_id.lower() for x in excluded):
                if is_gemini_runnable(model_id):
                    print(f"DEBUG: ✅ GEMINI VALID: {model_id}")
                    found.append(model_id)
    except:
        print("DEBUG: ❌ GEMINI DISCOVERY FAILED")

    found.sort()
    if "gemini-2.5-flash-lite" in found:
        found.remove("gemini-2.5-flash-lite")
        found.insert(0, "gemini-2.5-flash-lite")
    return found

@asynccontextmanager
async def lifespan(app: FastAPI):
    global AIRS_CONFIGURED, airs_error_msg, ai_profile_obj, validated_models
    print("\n" + "="*40)
    print("🚀 T-AIRS STARTUP INITIALIZATION")
    print("="*40)

    if AIRS_KEY and AIRS_PROFILE_NAME:
        print(f"Handshaking with Prisma AIRS: {AIRS_PROFILE_NAME}...")
        try:
            aisecurity.init(api_key=AIRS_KEY)
            # Using the pre-imported AiProfile class
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

    print("Performing Deep Model Discovery...")
    validated_models = discover_all_models()
    print(f"READY: {len(validated_models)} models loaded into memory.")
    print("="*40 + "\n")
    yield

app = FastAPI(lifespan=lifespan)
templates = Jinja2Templates(directory="templates")

# --- LLM HELPERS ---

def chat_local_ollama(model_name, system_prompt, user_message):
    real_model = model_name.replace("local-", "")
    try:
        payload = {
            "model": real_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message}
            ],
            "stream": False,
            "options": {"stop": ["User:", "\nUser", "Assistant:"], "temperature": 0.7}
        }
        response = requests.post("http://localhost:11434/api/chat", json=payload, timeout=120)
        return response.json().get("message", {}).get("content", "").strip()
    except Exception as e:
        return f"Local LLM Error: {str(e)}"

# --- ROUTES ---

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

@app.post("/chat")
async def chat(
    message: str = Form(...),
    persona: str = Form(...),
    session_id: str = Form(...),
    airs_enabled: bool = Form(False),
    model_id: str = Form(...)
):
    selected_prompt = PERSONAS.get(persona, PERSONAS["banking"])
    security_status = "Bypassed"
    raw_sec_log = "{}"
    try:
        if AIRS_CONFIGURED and airs_enabled and ai_profile_obj:
            # Using the pre-imported Scanner and Content classes
            scan_response = Scanner().sync_scan(ai_profile=ai_profile_obj, content=Content(prompt=message))
            res_data = scan_response.to_dict()
            data = res_data[0] if isinstance(res_data, list) and len(res_data) > 0 else res_data
            action = str(data.get("action", "pass")).lower()
            raw_sec_log = json.dumps(data, indent=2)
            if action == "block":
                block_txt = f"🛡️ Prisma AIRS Blocked: {data.get('category')} violation."
                return {"bot": block_txt, "output": block_txt, "logs": {"security_scan": "BLOCK", "raw_response": raw_sec_log}}
            security_status = f"Passed ({action})"

        active_model = model_id if model_id in validated_models else (validated_models[0] if validated_models else "gemini-2.5-flash-lite")
        if active_model.startswith("local-"):
            bot_response = chat_local_ollama(active_model, selected_prompt, message)
        else:
            chat_session = client.models.generate_content(model=active_model, contents=message, config=types.GenerateContentConfig(system_instruction=selected_prompt))
            bot_response = chat_session.text

        return {"bot": bot_response, "output": bot_response, "logs": {"security_scan": security_status, "raw_response": raw_sec_log}}
    except Exception as e:
        return {"bot": f"Error: {str(e)}", "output": f"Error: {str(e)}", "logs": {"security_scan": "Error", "raw_response": raw_sec_log}}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
