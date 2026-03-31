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

# Prisma AIRS Imports
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
parser.add_argument("--target-cloud", help="Deploy target: aws or gcp", default="gcp")
parser.add_argument("--gcp-project", help="GCP Project ID for Vertex AI", default="")
parser.add_argument("--gcp-region", help="GCP Region for Vertex AI", default="us-central1")
parser.add_argument("--aws-region", help="AWS Region", default="us-east-1")
parser.add_argument("--bedrock-model-id", help="Bedrock Model ID", default="meta.llama3-8b-instruct-v1:0")
args, _ = parser.parse_known_args()

AIRS_KEY = args.airs_key
AIRS_PROFILE_NAME = args.airs_profile
TARGET_CLOUD = args.target_cloud

AIRS_CONFIGURED = False
airs_error_msg = "Not initialized"

# GLOBAL STATE
validated_models = []
ai_profile_obj = None
PERSONAS = personas.PERSONAS

# 2. CLOUD CLIENT SETUP
vertex_client = None
bedrock_client = None

if TARGET_CLOUD == "gcp":
    try:
        vertex_client = genai.Client(vertexai=True, project=args.gcp_project, location=args.gcp_region)
        print("✅ GCP Vertex AI Initialized.")
    except Exception as e:
        print(f"CRITICAL: Failed to initialize Vertex AI in {args.gcp_region}. Error: {e}")
elif TARGET_CLOUD == "aws":
    import boto3
    try:
        bedrock_client = boto3.client("bedrock-runtime", region_name=args.aws_region)
        print(f"✅ AWS Bedrock Initialized in {args.aws_region}.")
    except Exception as e:
        print(f"CRITICAL: Failed to initialize AWS Bedrock. Error: {e}")

# --- INITIALIZATION LOGIC ---

def is_gemini_runnable(model_id):
    try:
        vertex_client.models.generate_content(model=model_id, contents="ping", config=types.GenerateContentConfig(max_output_tokens=1))
        return True
    except:
        return False

def discover_all_models():
    found = []
    # Local Ollama Discovery
    try:
        resp = requests.get("http://localhost:11434/api/tags", timeout=2)
        if resp.status_code == 200:
            locals = [f"local-{m['name']}" for m in resp.json().get('models', [])]
            for l in locals:
                print(f"DEBUG: ✅ LOCAL VALID: {l}")
            found.extend(locals)
    except:
        print("DEBUG: ⚠️ OLLAMA NOT DETECTED")

    # GCP Discovery
    if TARGET_CLOUD == "gcp" and vertex_client:
        try:
            all_gemini = vertex_client.models.list()
            excluded = ["image", "audio", "video", "live", "embedding", "tts", "imagen", "search"]
            for m in all_gemini:
                model_id = m.name.split('/')[-1]
                if "gemini" in model_id.lower() and not any(x in model_id.lower() for x in excluded):
                    if is_gemini_runnable(model_id):
                        print(f"DEBUG: ✅ GEMINI VALID: {model_id}")
                        found.append(model_id)
        except:
            print("DEBUG: ❌ GEMINI DISCOVERY FAILED")
            
    # AWS Discovery
    if TARGET_CLOUD == "aws" and bedrock_client:
        print(f"DEBUG: ✅ BEDROCK CONFIGURED: {args.bedrock_model_id}")
        found.append(args.bedrock_model_id)

    found.sort()
    
    # Set default order for GCP
    if TARGET_CLOUD == "gcp" and "gemini-2.5-flash-lite" in found:
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

def chat_aws_bedrock(model_id, system_prompt, user_message):
    try:
        response = bedrock_client.converse(
            modelId=model_id,
            messages=[{"role": "user", "content": [{"text": user_message}]}],
            system=[{"text": system_prompt}],
            inferenceConfig={"temperature": 0.7}
        )
        return response['output']['message']['content'][0]['text']
    except Exception as e:
        return f"AWS Bedrock Error: {str(e)}"

# --- ROUTES ---

@app.post("/update-persona")
async def update_persona(
    persona_id: str = Form(...),
    new_context: str = Form(...)
):
    if persona_id in PERSONAS:
        # 1. Update the live memory
        PERSONAS[persona_id] = new_context
        
        # 2. Write it permanently to the personas.py file
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
    
    # Safe fallback if UI sends empty string
    if not model_id or model_id == "none":
        model_id = validated_models[0] if validated_models else None

    try:
        # --- 1. INGRESS SCAN (Check the User's Prompt) ---
        if AIRS_CONFIGURED and airs_enabled and ai_profile_obj:
            scan_response = Scanner().sync_scan(ai_profile=ai_profile_obj, content=Content(prompt=message))
            res_data = scan_response.to_dict()
            ingress_data = res_data[0] if isinstance(res_data, list) and len(res_data) > 0 else res_data
            
            action = str(ingress_data.get("action", "pass")).lower()
            
            if action == "block":
                block_txt = f"🛡️ Prisma AIRS Blocked Input: {ingress_data.get('category', 'Policy')} violation."
                raw_sec_log = json.dumps(ingress_data, indent=2)
                return {"bot": block_txt, "output": block_txt, "logs": {"security_scan": "INGRESS BLOCK", "raw_response": raw_sec_log}}
            
            security_status = "Passed Input"
            raw_sec_log = json.dumps(ingress_data, indent=2)

        # --- 2. GENERATE LLM RESPONSE (The core AI engine) ---
        if not model_id:
             bot_response = "Error: No AI engine available. Cloud clients failed to initialize."
        elif model_id.startswith("local-"):
            bot_response = chat_local_ollama(model_id, selected_prompt, message)
        elif TARGET_CLOUD == "aws":
            bot_response = chat_aws_bedrock(model_id, selected_prompt, message)
        elif TARGET_CLOUD == "gcp" and vertex_client:
            chat_session = vertex_client.models.generate_content(
                model=model_id, 
                contents=message, 
                config=types.GenerateContentConfig(system_instruction=selected_prompt)
            )
            bot_response = chat_session.text
        else:
             bot_response = "Error: Invalid cloud target or missing client."

        # --- 3. EGRESS SCAN (Check the LLM's Answer) ---
        if AIRS_CONFIGURED and airs_enabled and ai_profile_obj and "Error:" not in bot_response:
            out_scan_response = Scanner().sync_scan(ai_profile=ai_profile_obj, content=Content(prompt=bot_response))
            out_res_data = out_scan_response.to_dict()
            out_data = out_res_data[0] if isinstance(out_res_data, list) and len(out_res_data) > 0 else out_res_data
            
            out_action = str(out_data.get("action", "pass")).lower()
            
            if out_action == "block":
                block_txt = f"🛡️ Prisma AIRS Blocked Output: The LLM generated a {out_data.get('category', 'Policy')} violation."
                raw_sec_log = json.dumps(out_data, indent=2)
                return {"bot": block_txt, "output": block_txt, "logs": {"security_scan": "EGRESS BLOCK", "raw_response": raw_sec_log}}
            
            security_status = "Passed Input & Output"
            raw_sec_log = json.dumps({"input_scan": ingress_data, "output_scan": out_data}, indent=2)

        # --- 4. RETURN SAFE RESPONSE ---
        return {"bot": bot_response, "output": bot_response, "logs": {"security_scan": security_status, "raw_response": raw_sec_log}}

    except Exception as e:
        return {"bot": f"Error: {str(e)}", "output": f"Error: {str(e)}", "logs": {"security_scan": "Error", "raw_response": raw_sec_log}}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
