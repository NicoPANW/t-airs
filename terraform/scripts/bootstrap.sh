#!/bin/bash

# Capture the Terraform variables
ENABLE_LOCAL_LLM="${enable_local_llm}"

echo "Setting custom hostname for ${target_cloud}..."
hostnamectl set-hostname "t-airs-node-${target_cloud}"

# --- 0. ROBUST UPDATE & INSTALL ---
echo "Updating system packages..."
# Loop until Apt is free from background locks
until apt-get update && apt-get install -y python3-pip python3-venv git curl unattended-upgrades sqlite3; do
    echo "Apt is locked or network is busy. Retrying in 5s..."
    sleep 5
done

# 1.5 Configure Automatic Security Updates (Zero-Touch Patching)
cat <<EOF > /etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
systemctl restart unattended-upgrades


# ==========================================
# DYNAMIC LLM BLOCK (Logic fully contained)
# ==========================================
if [ "$ENABLE_LOCAL_LLM" == "true" ]; then
    

    # 🌟 Check if drivers are already working. If so, skip the whole block!
    if lsmod | grep -q nvidia; then
        echo "✅ NVIDIA drivers are already loaded and active."
    else
        echo "⚠️ Nvidia drivers missing (Check your DLAMI/DLVM mapping!)"
    fi

    # ---  Setup Ollama ---
    export HOME=/root
    if ! command -v ollama &> /dev/null; then
        echo "Ollama not found. Installing..."
        curl -fsSL https://ollama.com/install.sh | sh
        systemctl enable --now ollama
    else
        echo "✅ Ollama is already installed."
        systemctl start ollama
    fi

    # Wait dynamically for the Ollama API to wake up
    echo "Waiting for Ollama engine to initialize..."
    until curl -s http://127.0.0.1:11434/api/tags > /dev/null; do 
        sleep 2
    done

    # ---  Configure Ollama for Multi-Model Preloading ---
    echo "Configuring Ollama to hold multiple models in VRAM..."
    mkdir -p /etc/systemd/system/ollama.service.d
    cat <<EOF > /etc/systemd/system/ollama.service.d/override.conf
[Service]
# Allow up to 3 models to be loaded into VRAM at the same time
Environment="OLLAMA_MAX_MODELS=3"
# Allow multiple requests to be processed concurrently
Environment="OLLAMA_NUM_PARALLEL=3"
EOF
    systemctl daemon-reload
    systemctl restart ollama
    sleep 3 # Give it a second to wake back up

    # --- 6. Pull Models (Using Terraform-Safe String Syntax) ---
    echo "Pre-loading LLM models (this may take 10-15 minutes)..."
    
    MODELS_TO_PULL="llama3.2:3b ministral-3:3b qwen2.5:1.5b"
    
    for model in $MODELS_TO_PULL; do
        if ! ollama list | grep -q "$model"; then
            echo "⬇️ Pulling $model..."
            ollama pull "$model"
        else
            echo "✅ $model is already downloaded."
        fi

        echo "Verifying $model readiness..."
        until ollama list | grep -q "$model"; do 
            sleep 5
        done
        echo "🧠 Locking $model into GPU VRAM..."
        curl -s -X POST http://127.0.0.1:11434/api/generate -d "{\"model\": \"$model\", \"keep_alive\": -1}" > /dev/null
        echo "🚀 $model is ready to use."
    done

    echo "✅ All local GPU models are successfully loaded!"

else
    # This correctly closes the main ENABLE_LOCAL_LLM check
    echo "ENABLE_LOCAL_LLM is false. Skipping GPU/Ollama setup."
fi
# ==========================================


# --- 3. Deploy Application Code, AI Gateway, MCP & RAG ---
mkdir -p /opt/t-airs
git clone https://github.com/NicoPANW/t-airs.git /opt/t-airs
cd /opt/t-airs

# B. Create the Dummy Customer Database
echo "Executing SQL Seeder"
python3 /opt/t-airs/src/sql_data.py

# D. Setup Python Virtual Environment & Install Requirements
python3 -m venv venv
source venv/bin/activate

# 🌟 CONDITIONAL PYTORCH INSTALL
if [ "$ENABLE_LOCAL_LLM" == "true" ]; then
    echo "GPU Enabled: Installing massive CUDA 12.4 optimized PyTorch wheels..."
    pip3 install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu124
else
    echo "API Only Mode: Skipping CUDA wheels (will use lightweight CPU version for RAG)."
fi



echo "Installing remaining Python requirements..."
pip3 install -r /opt/t-airs/src/requirements.txt

echo "Pre-downloading HuggingFace BAAI Embedding Model..."
# We run this in the foreground so systemd doesn't choke the network connection!
python3 -c "from huggingface_hub import snapshot_download; snapshot_download('BAAI/bge-base-en-v1.5')"
echo "✅ BAAI Model successfully cached!"

# --- 3.5 DYNAMICALLY BUILD THE AI GATEWAY CONFIG ---
echo "Building LiteLLM routing configuration..."
cat <<EOF > /opt/t-airs/src/litellm_config.yaml
model_list:
EOF

# Inject GCP Models if deploying to Google
if [ "${target_cloud}" == "gcp" ]; then
cat <<EOF >> /opt/t-airs/src/litellm_config.yaml
  # --- EXPLICIT MODELS (For the manual UI dropdown) ---
  - model_name: gemini-3.1-pro-preview
    litellm_params:
      model: vertex_ai/gemini-3.1-pro-preview
      vertex_project: "${gcp_project}"
      vertex_location: "global"
  - model_name: gemini-3.1-flash-lite-preview
    litellm_params:
      model: vertex_ai/gemini-3.1-flash-lite-preview
      vertex_project: "${gcp_project}"
      vertex_location: "global"
  - model_name: gemini-2.5-pro
    litellm_params:
      model: vertex_ai/gemini-2.5-pro
      vertex_project: "${gcp_project}"
      vertex_location: "global"
  - model_name: gemini-2.5-flash
    litellm_params:
      model: vertex_ai/gemini-2.5-flash
      vertex_project: "${gcp_project}"
      vertex_location: "global"
  - model_name: gemini-2.5-flash-lite
    litellm_params:
      model: vertex_ai/gemini-2.5-flash-lite
      vertex_project: "${gcp_project}"
      vertex_location: "global"

  # --- ALL MODELS IN THE AUTO-ROUTER GROUP ---
  - model_name: auto-router
    litellm_params:
      model: vertex_ai/gemini-3.1-pro-preview
      vertex_project: "${gcp_project}"
      vertex_location: "global"
  - model_name: auto-router
    litellm_params:
      model: vertex_ai/gemini-3.1-flash-lite-preview
      vertex_project: "${gcp_project}"
      vertex_location: "global"
  - model_name: auto-router
    litellm_params:
      model: vertex_ai/gemini-2.5-pro
      vertex_project: "${gcp_project}"
      vertex_location: "global"
  - model_name: auto-router
    litellm_params:
      model: vertex_ai/gemini-2.5-flash
      vertex_project: "${gcp_project}"
      vertex_location: "global"
  - model_name: auto-router
    litellm_params:
      model: vertex_ai/gemini-2.5-flash-lite
      vertex_project: "${gcp_project}"
      vertex_location: "global"
EOF
# Inject AWS Models if deploying to Amazon
elif [ "${target_cloud}" == "aws" ]; then
cat <<EOF >> /opt/t-airs/src/litellm_config.yaml
  # --- EXPLICIT MODELS (For the manual UI dropdown) ---
  - model_name: ${bedrock_model_id}
    litellm_params:
      model: bedrock/${bedrock_model_id}
      aws_region_name: "${aws_region}"

  # --- ALL MODELS IN THE AUTO-ROUTER GROUP ---
  - model_name: auto-router
    litellm_params:
      model: bedrock/${bedrock_model_id}
      aws_region_name: "${aws_region}"
EOF
fi

# Inject Local Models if GPU is enabled
if [ "${enable_local_llm}" == "true" ]; then
cat <<EOF >> /opt/t-airs/src/litellm_config.yaml
  - model_name: local-llama3.2:3b
    litellm_params:
      model: ollama/llama3.2:3b
      api_base: "http://127.0.0.1:11434"
  - model_name: local-ministral:3b
    litellm_params:
      model: ollama/ministral-3:3b
      api_base: "http://127.0.0.1:11434"
  - model_name: local-qwen2.5:1.5b
    litellm_params:
      model: ollama/qwen2.5:1.5b
      api_base: "http://127.0.0.1:11434"
EOF
fi

# Close out the YAML
cat <<EOF >> /opt/t-airs/src/litellm_config.yaml
litellm_settings:
  drop_params: true

router_settings:
  routing_strategy: cost-based-routing

guardrails:
  - guardrail_name: "airs-ingress-scan"
    litellm_params:
      guardrail: panw_prisma_airs
      mode: "pre_call"
      default_on: false
      api_key: os.environ/AIRS_API_KEY
      profile_name: os.environ/AIRS_PROFILE

  - guardrail_name: "airs-egress-scan"
    litellm_params:
      guardrail: panw_prisma_airs
      mode: "post_call"
      default_on: false
      api_key: os.environ/AIRS_API_KEY
      profile_name: os.environ/AIRS_PROFILE
EOF


# --- 4. Create Systemd Services ---

echo "Configuring Prisma AIRS Integration Mode: $AIRS_MODE"

# A. Create the AI Gateway Service (LiteLLM)
cat <<EOF > /etc/systemd/system/litellm.service
[Unit]
Description=LiteLLM AI Gateway
After=network.target

[Service]
WorkingDirectory=/opt/t-airs/src
EOF

# 🌟 UNCONDITIONAL INJECTION: Gateway must always have keys ready for the Live UI Toggle
cat <<EOF >> /etc/systemd/system/litellm.service
Environment="PANW_PRISMA_AIRS_API_KEY=${airs_key}"
Environment="AIRS_API_KEY=${airs_key}"
Environment="AIRS_PROFILE=${airs_profile}"
ExecStart=/opt/t-airs/venv/bin/litellm --config litellm_config.yaml --port 4000
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF


# B. Create the T-AIRS App Service
# We conditionally add ollama.service dependency if local LLMs are enabled
if [ "${enable_local_llm}" == "true" ]; then
    TAIRS_AFTER="network.target litellm.service ollama.service"
else
    TAIRS_AFTER="network.target litellm.service"
fi

cat <<EOF > /etc/systemd/system/t-airs.service
[Unit]
Description=T-AIRS
After=$TAIRS_AFTER

[Service]
# 1. Explicitly define the cache locations
Environment="HOME=/root"
Environment="HF_HOME=/root/.cache/huggingface"
Environment="HF_HUB_OFFLINE=1"
WorkingDirectory=/opt/t-airs/src

# ==========================================
# 🔍 NEW: SYSTEMD DEBUG DUMP
# ==========================================
ExecStartPre=/bin/bash -c 'echo "=== 🕵️ SYSTEMD DEBUG DUMP ==="; echo "Current User: \$(whoami)"; echo "HOME Variable: \$HOME"; echo "HF_HOME Variable: \$HF_HOME"; echo "--- Checking Cache Directory ---"; ls -lah /root/.cache/huggingface/ || echo "❌ /root/.cache/huggingface IS EMPTY OR MISSING!"; echo "--- Cache Folder Size ---"; du -sh /root/.cache/huggingface/ 2>/dev/null || echo "❌ Cannot calculate size!"; echo "================================="'
# ==========================================

ExecStartPre=/bin/bash -c 'until curl -s -f http://127.0.0.1:4000 > /dev/null; do echo "Waiting for AI Gateway..."; sleep 2; done; echo "LiteLLM started!"'
ExecStart=/opt/t-airs/venv/bin/python3 main.py --airs-key ${airs_key} --airs-profile ${airs_profile} --gateway-url http://127.0.0.1:4000
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

# --- 5. Start Services ---
systemctl daemon-reload
systemctl enable litellm
systemctl start litellm
systemctl enable t-airs
systemctl start t-airs
