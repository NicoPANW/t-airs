#!/bin/bash

# Capture the Terraform variables passed into the template.
# These variables control which blocks of this script are executed.
ENABLE_LOCAL_LLM="${enable_local_llm}"

# Set a unique and descriptive hostname for the VM based on its cloud and environment.
# This makes it easier to identify instances in the cloud console.
echo "Setting custom hostname for ${target_cloud}..."
hostnamectl set-hostname "t-airs-node-${target_cloud}-${env}"


# --- 0. ROBUST UPDATE & INSTALL ---
# This section ensures the base OS is up-to-date and has essential tools.
echo "Updating system packages..."
# Use a loop to handle potential 'apt lock' issues on fresh VMs.
# This ensures that automated background updates don't interfere with our setup.
until apt-get update && apt-get install -y python3-pip python3-venv git curl unattended-upgrades sqlite3; do
    echo "Apt is locked or network is busy. Retrying in 5s..."
    sleep 5
done

# Configure the system to automatically install security updates.
# This is a best practice for maintaining a secure, "zero-touch" server.
cat <<EOF > /etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
systemctl restart unattended-upgrades


# ==========================================
# DYNAMIC LLM BLOCK (GPU & OLLAMA SETUP)
# This entire block only runs if 'enable_local_llm' is true.
# ==========================================
if [ "$ENABLE_LOCAL_LLM" == "true" ]; then
    

    # First, check if NVIDIA drivers are already loaded.
    # This is expected on a Deep Learning VM/AMI, so we can skip installation.
    if lsmod | grep -q nvidia; then
        echo "✅ NVIDIA drivers are already loaded and active."
    else
        echo "⚠️ Nvidia drivers missing (Check your DLAMI/DLVM mapping!)"
    fi

    # Install and enable the Ollama service if it's not already present.
    export HOME=/root
    if ! command -v ollama &> /dev/null; then
        echo "Ollama not found. Installing..."
        curl -fsSL https://ollama.com/install.sh | sh
        systemctl enable --now ollama
    else
        echo "✅ Ollama is already installed."
        systemctl start ollama
    fi

    # Wait for the Ollama API to become responsive before proceeding.
    echo "Waiting for Ollama engine to initialize..."
    until curl -s http://127.0.0.1:11434/api/tags > /dev/null; do 
        sleep 2
    done

    # Configure Ollama to keep multiple models loaded in VRAM simultaneously.
    # This improves performance by avoiding constant loading/unloading.
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

    # Pull the required local LLM models from the Ollama registry.
    echo "Pre-loading LLM models (this may take 10-15 minutes)..."
    
    MODELS_TO_PULL="llama3.2:3b ministral-3:3b qwen2.5:1.5b"
    
    for model in $MODELS_TO_PULL; do
        if ! ollama list | grep -q "$model"; then
            echo "⬇️ Pulling $model..."
            ollama pull "$model"
        else
            echo "✅ $model is already downloaded."
        fi

        # Verify the model is fully pulled and registered.
        echo "Verifying $model readiness..."
        until ollama list | grep -q "$model"; do 
            sleep 5
        done
        # Send a request with 'keep_alive: -1' to lock the model in VRAM indefinitely.
        echo "🧠 Locking $model into GPU VRAM..."
        curl -s -X POST http://127.0.0.1:11434/api/generate -d "{\"model\": \"$model\", \"keep_alive\": -1}" > /dev/null
        echo "🚀 $model is ready to use."
    done

    echo "✅ All local GPU models are successfully loaded!"

else
    # This message is shown if local LLMs are disabled.
    echo "ENABLE_LOCAL_LLM is false. Skipping GPU/Ollama setup."
fi
# ==========================================


# --- 3. Deploy Application Code, AI Gateway, MCP & RAG ---
# This section sets up the core T-AIRS application.
mkdir -p /opt/t-airs

# Determine which branch to clone based on the environment.
# 'prod' environment (from 'default' workspace) uses the 'main' branch.
# 'dev' environment uses the 'dev' branch.
if [ "${env}" == "dev" ]; then
    BRANCH="dev"
else
    BRANCH="main"
fi
echo "Deploying from git branch: $BRANCH"

# Clone the specific branch of the application source code from the GitHub repository.
git clone --branch $BRANCH https://github.com/NicoPANW/t-airs.git /opt/t-airs
cd /opt/t-airs

# Create the SQLite database and populate it with initial customer data.
# This provides the structured data for the MCP agent to interact with.
echo "Executing SQL Seeder"
python3 /opt/t-airs/src/sql_data.py

# Set up a Python virtual environment to isolate dependencies.
python3 -m venv venv
source venv/bin/activate

# Conditionally install the correct PyTorch version.
# GPU instances need the large CUDA-enabled version, while CPU instances use a lightweight one.
if [ "$ENABLE_LOCAL_LLM" == "true" ]; then
    echo "GPU Enabled: Installing massive CUDA 12.4 optimized PyTorch wheels..."
    pip3 install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu124
else
    echo "API Only Mode: Skipping CUDA wheels (will use lightweight CPU version for RAG)."
fi



# Install all other Python packages required by the application.
echo "Installing remaining Python requirements..."
pip3 install -r /opt/t-airs/src/requirements.txt


# Pre-download the embedding model for the RAG system from HuggingFace.
# This prevents a long delay on the first application startup.
echo "Pre-downloading HuggingFace BAAI Embedding Model..."
python3 -c "from huggingface_hub import snapshot_download; snapshot_download('BAAI/bge-base-en-v1.5')"
echo "✅ BAAI Model successfully cached!"

# --- 3.5 DYNAMICALLY BUILD THE AI GATEWAY CONFIG ---
# This section creates the LiteLLM configuration file on the fly.
# The configuration is tailored to the specific cloud provider (GCP/AWS) and whether local LLMs are used.
echo "Building LiteLLM routing configuration..."
cat <<EOF > /opt/t-airs/src/litellm_config.yaml
model_list:
EOF

# Inject GCP model definitions if the target cloud is GCP.
if [ "${target_cloud}" == "gcp" ]; then
cat <<EOF >> /opt/t-airs/src/litellm_config.yaml
  # --- EXPLICIT MODELS (For the manual UI dropdown) ---
  - model_name: gemini-3.1-flash-lite
    litellm_params:
      model: vertex_ai/gemini-3.1-flash-lite
      vertex_project: "${gcp_project}"
      vertex_location: "global"
  - model_name: gemini-3.5-flash
    litellm_params:
      model: vertex_ai/gemini-3.5-flash
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
      model: vertex_ai/gemini-3.1-flash-lite
      vertex_project: "${gcp_project}"
      vertex_location: "global"
  - model_name: auto-router
    litellm_params:
      model: vertex_ai/gemini-3.5-flash
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
# Inject AWS model definitions if the target cloud is AWS.
elif [ "${target_cloud}" == "aws" ]; then
# Loop through each model ID passed from Terraform and add it to the config.
for model_id in ${bedrock_model_ids}; do
cat <<EOF >> /opt/t-airs/src/litellm_config.yaml
  - model_name: $${model_id}
    litellm_params:
      model: bedrock/$${model_id}
      aws_region_name: "${aws_region}"
  - model_name: auto-router
    litellm_params:
      model: bedrock/$${model_id}
      aws_region_name: "${aws_region}"
EOF
done
fi

# Inject local Ollama model definitions if GPU mode is enabled.
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

# Add the final settings for routing and Prisma AIRS guardrails.
# The guardrails are defined but set to 'default_on: false' so they can be toggled from the UI.
cat <<EOF >> /opt/t-airs/src/litellm_config.yaml
litellm_settings:
  drop_params: true
  modify_params: true

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
  
  - guardrail_name: "airs-mcp-scan"
    litellm_params:
      guardrail: panw_prisma_airs
      mode: "pre_mcp_call"
      default_on: false
      api_key: os.environ/AIRS_API_KEY
      profile_name: os.environ/AIRS_PROFILE
EOF


# --- 4. Create Systemd Services ---
# This section creates systemd service files to ensure the application and its
# dependencies run automatically on boot and restart if they crash.

echo "Configuring Prisma AIRS Integration Mode: $AIRS_MODE"

# Create the service file for the LiteLLM AI Gateway.
# This service is responsible for routing requests to the correct LLM.
cat <<EOF > /etc/systemd/system/litellm.service
[Unit]
Description=LiteLLM AI Gateway
After=network.target

[Service]
WorkingDirectory=/opt/t-airs/src
# Inject the AIRS credentials directly into the gateway's environment.
# This is necessary for the live UI toggle to enable/disable gateway-level scanning.
Environment="PANW_PRISMA_AIRS_API_KEY=${airs_key}"
Environment="AIRS_API_KEY=${airs_key}"
Environment="AIRS_PROFILE=${airs_profile}"
ExecStart=/opt/t-airs/venv/bin/litellm --config litellm_config.yaml --port 4000
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF


# Create the service file for the main T-AIRS application (FastAPI server).
# Conditionally add 'ollama.service' as a dependency if local LLMs are enabled.
if [ "${enable_local_llm}" == "true" ]; then
    TAIRS_AFTER="network.target litellm.service ollama.service"
else
    TAIRS_AFTER="network.target litellm.service"
fi

cat <<EOF > /etc/systemd/system/t-airs.service
[Unit]
Description=T-AIRS
After=network.target litellm.service

[Service]
# Set environment variables required by HuggingFace libraries to cache models correctly.
Environment="HOME=/root"
Environment="HF_HOME=/root/.cache/huggingface"
Environment="HF_HUB_CACHE=/root/.cache/huggingface/hub"


WorkingDirectory=/opt/t-airs/src
# Before starting the app, wait until the AI Gateway is fully responsive.
ExecStartPre=/bin/bash -c 'until curl -s -f http://127.0.0.1:4000 > /dev/null; do echo "Waiting for AI Gateway..."; sleep 2; done'
# Launch the main Python application, passing in credentials.
ExecStart=/opt/t-airs/venv/bin/python3 main.py --airs-key ${airs_key} --airs-profile ${airs_profile} --gateway-url http://127.0.0.1:4000
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

# --- 5. Start Services ---
# Reload the systemd daemon to recognize the new service files,
# then enable and start the services.
systemctl daemon-reload
systemctl enable litellm
systemctl start litellm
systemctl enable t-airs
systemctl start t-airs
