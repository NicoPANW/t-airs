#!/bin/bash

# Capture the Terraform variables passed into the template.
# These variables control which blocks of this script are executed.
GATEWAY_PROVIDER="${gateway_provider}" # e.g., "litellm" or "portkey"

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


# Install all other Python packages required by the application.
echo "Installing remaining Python requirements..."
/opt/t-airs/venv/bin/pip install -r /opt/t-airs/src/requirements.txt


# Inject FastAPI 0.115+ compatibility shim for LiteLLM versions expecting 'get_flat_dependant'
/opt/t-airs/venv/bin/python3 -c "
import fastapi.dependencies.utils as utils
if not hasattr(utils, 'get_flat_dependant'):
    with open(utils.__file__, 'a') as f:
        f.write('\n\ndef get_flat_dependant(dependant, *, skip_repeats: bool = False):\n    flat = [dependant]\n    for dep in dependant.dependencies:\n        flat.extend(get_flat_dependant(dep, skip_repeats=skip_repeats))\n    return flat\n')
"


# Pre-download the embedding model for the RAG system from HuggingFace.
# This prevents a long delay on the first application startup.
echo "Pre-downloading HuggingFace BAAI Embedding Model..."
python3 -c "from huggingface_hub import snapshot_download; snapshot_download('BAAI/bge-base-en-v1.5')"
echo "✅ BAAI Model successfully cached!"


# ==========================================
# 3.5 DYNAMICALLY BUILD THE AI GATEWAY CONFIG
# Only build this if LiteLLM is the active gateway
# ==========================================
if [ "$GATEWAY_PROVIDER" == "litellm" ]; then
    echo "Installing LiteLLM packages conditionally..."
    /opt/t-airs/venv/bin/pip install "litellm" "litellm[proxy]" "litellm-enterprise" "litellm-proxy-extras" "google-auth"

    echo "Building LiteLLM routing configuration..."
    cat <<EOF > /opt/t-airs/src/litellm_config.yaml
model_list:
EOF

    # Inject GCP model definitions if the target cloud is GCP.
    if [ "${target_cloud}" == "gcp" ]; then
    cat <<EOF >> /opt/t-airs/src/litellm_config.yaml
  - model_name: gemini-3.6-flash
    litellm_params:
      model: vertex_ai/gemini-3.6-flash
      vertex_project: "${gcp_project}"
      vertex_location: "global"
  - model_name: gemini-3.5-flash-lite
    litellm_params:
      model: vertex_ai/gemini-3.5-flash-lite
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
      model: vertex_ai/gemini-3.6-flash
      vertex_project: "${gcp_project}"
      vertex_location: "global"
  - model_name: auto-router
    litellm_params:
      model: vertex_ai/gemini-3.5-flash-lite
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


    # Add the final settings for routing and Prisma AIRS guardrails.
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
fi


# --- 4. Create Systemd Services ---
# This section creates systemd service files to ensure the application and its
# dependencies run automatically on boot and restart if they crash.

echo "Configuring Prisma AIRS Integration Mode: $AIRS_MODE"

# Determine base dependencies for T-AIRS
TAIRS_AFTER="network.target"

# Only configure and start LiteLLM if it is the chosen gateway
if [ "$GATEWAY_PROVIDER" == "litellm" ]; then
    echo "Configuring LiteLLM Service..."
    cat <<EOF > /etc/systemd/system/litellm.service
[Unit]
Description=LiteLLM AI Gateway
After=network.target

[Service]
WorkingDirectory=/opt/t-airs/src
# Inject the AIRS credentials directly into the gateway's environment.
Environment="PANW_PRISMA_AIRS_API_KEY=${airs_key}"
Environment="AIRS_API_KEY=${airs_key}"
Environment="AIRS_PROFILE=${airs_profile}"
ExecStart=/opt/t-airs/venv/bin/litellm --config litellm_config.yaml --port 4000
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable litellm
    systemctl start litellm
    
    # Add litellm to T-AIRS dependencies
    TAIRS_AFTER="$TAIRS_AFTER litellm.service"
fi

cat <<EOF > /etc/systemd/system/t-airs.service
[Unit]
Description=T-AIRS
After=$${TAIRS_AFTER}

[Service]
# Set environment variables required by HuggingFace libraries to cache models correctly.
Environment="HOME=/root"
Environment="HF_HOME=/root/.cache/huggingface"
Environment="HF_HUB_CACHE=/root/.cache/huggingface/hub"
# Inject Portkey credentials from Terraform (ignored if LiteLLM is active)
Environment="PORTKEY_API_KEY=${portkey_api_key}"
Environment="PORTKEY_VIRTUAL_KEY=${portkey_virtual_key}"
Environment="PORTKEY_SLUG=${portkey_slug}"

WorkingDirectory=/opt/t-airs/src

# Before starting the app, wait until the AI Gateway is fully responsive IF using LiteLLM
ExecStartPre=/bin/bash -c 'if [ "${gateway_provider}" == "litellm" ]; then until curl -s -f http://127.0.0.1:4000/health/readiness > /dev/null; do echo "Waiting for local LiteLLM AI Gateway..."; sleep 2; done; fi'

# Launch the main Python application dynamically configured for the selected provider
ExecStart=/opt/t-airs/venv/bin/python3 main.py --airs-key ${airs_key} --airs-profile ${airs_profile} --gateway-url http://127.0.0.1:4000 --gateway-provider ${gateway_provider} --portkey-slug "${portkey_slug}"
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

# --- 5. Start Services ---
# Reload the systemd daemon to recognize the new service files,
# then enable and start the services.
systemctl daemon-reload
systemctl enable t-airs
systemctl start t-airs