#!/bin/bash

NODE_ROLE="${node_role}"               # "app" or "mcp"
GATEWAY_PROVIDER="${gateway_provider}" # "portkey" or "litellm"
MCP_PORT="${mcp_port}"

if [ -z "$NODE_ROLE" ]; then
    NODE_ROLE="app"
fi
if [ -z "$MCP_PORT" ]; then
    MCP_PORT="8080"
fi

echo "Setting custom hostname for ${target_cloud} ($NODE_ROLE)..."
hostnamectl set-hostname "t-airs-$NODE_ROLE-${target_cloud}-${env}"

# --- 0. ROBUST UPDATE & INSTALL ---
echo "Updating system packages..."
until apt-get update && apt-get install -y python3-pip python3-venv git curl unattended-upgrades sqlite3 jq; do
    echo "Apt is locked or network is busy. Retrying in 5s..."
    sleep 5
done

cat <<EOF > /etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
systemctl restart unattended-upgrades

# --- 1. CLONE REPOSITORY ---
mkdir -p /opt/t-airs

if [ "${env}" == "dev" ]; then
    BRANCH="dev"
else
    BRANCH="main"
fi
echo "Deploying from git branch: $BRANCH"

git clone --branch $BRANCH https://github.com/NicoPANW/t-airs.git /opt/t-airs
cd /opt/t-airs

if [ -f "/opt/t-airs/VERSION" ]; then
    APP_VERSION=$(cat /opt/t-airs/VERSION | tr -d '\r\n[:space:]')
    CLEAN_VERSION=$(echo "$APP_VERSION" | tr '.' '-')
    hostnamectl set-hostname "t-airs-$NODE_ROLE-${target_cloud}-${env}-v$CLEAN_VERSION"
fi

# ==============================================================================
# ROLE A: DEDICATED REMOTE SQLITE MCP SERVER VM
# ==============================================================================
if [ "$NODE_ROLE" == "mcp" ]; then
    echo "🗄️ Configuring Dedicated Remote MCP Server VM..."

    echo "Executing SQL Seeder on MCP VM..."
    python3 /opt/t-airs/src/sql_data.py

    python3 -m venv /opt/t-airs/venv
    /opt/t-airs/venv/bin/pip install --upgrade pip
    /opt/t-airs/venv/bin/pip install "mcp==2.3.0" "uvicorn>=0.30.0" "starlette>=0.40.0"

    cat <<EOF > /etc/systemd/system/t-airs-mcp.service
[Unit]
Description=T-AIRS Remote SQLite MCP Server (Streamable HTTP)
After=network.target

[Service]
WorkingDirectory=/opt/t-airs/src
Environment="MCP_HOST=0.0.0.0"
Environment="MCP_PORT=$MCP_PORT"
Environment="MCP_DB_PATH=/opt/t-airs/src/customers.db"
Environment="MCP_AUTH_TOKEN=${mcp_auth_token}"
ExecStart=/opt/t-airs/venv/bin/python3 /opt/t-airs/src/mcp_server_simple.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable t-airs-mcp
    systemctl start t-airs-mcp
    echo "✅ Remote MCP Server VM setup complete!"
    exit 0
fi

# ==============================================================================
# ROLE B: MAIN AI AGENT & WEB UI VM
# ==============================================================================
echo "🤖 Configuring Main T-AIRS Agent VM (Remote MCP via AI Gateway)..."

python3 -m venv /opt/t-airs/venv
source /opt/t-airs/venv/bin/activate

if [ "$GATEWAY_PROVIDER" == "litellm" ]; then
    echo "" >> /opt/t-airs/src/requirements.txt
    echo "litellm[proxy]==1.104.2" >> /opt/t-airs/src/requirements.txt
    echo "litellm-enterprise" >> /opt/t-airs/src/requirements.txt
    echo "litellm-proxy-extras" >> /opt/t-airs/src/requirements.txt
    echo "google-auth==2.59.1" >> /opt/t-airs/src/requirements.txt
fi

echo "Installing Python requirements..."
/opt/t-airs/venv/bin/pip install -r /opt/t-airs/src/requirements.txt

echo "Pre-downloading HuggingFace BAAI Embedding Model..."
python3 -c "from huggingface_hub import snapshot_download; snapshot_download('BAAI/bge-small-en-v1.5')"
echo "✅ BAAI Model successfully cached!"

# ==============================================================================
# DYNAMICALLY BUILD LITELLM CONFIG (IF LITELLM GATEWAY IS SELECTED)
# ==============================================================================
if [ "$GATEWAY_PROVIDER" == "litellm" ]; then
    echo "Building LiteLLM routing configuration with remote VPC MCP server..."
    cat <<EOF > /opt/t-airs/src/litellm_config.yaml
model_list:
EOF

    if [ "${target_cloud}" == "gcp" ]; then
        cd /opt/t-airs
        for model in $(jq -r '.[]' src/gemini_models.json); do
            cat <<EOF >> /opt/t-airs/src/litellm_config.yaml
  - model_name: $model
    litellm_params:
      model: vertex_ai/$model
      vertex_project: "${gcp_project}"
      vertex_location: "global"
EOF
        done

        cat <<EOF >> /opt/t-airs/src/litellm_config.yaml

  # --- ALL MODELS IN THE AUTO-ROUTER GROUP ---
EOF
        for model in $(jq -r '.[]' src/gemini_models.json); do
            cat <<EOF >> /opt/t-airs/src/litellm_config.yaml
  - model_name: auto-router
    litellm_params:
      model: vertex_ai/$model
      vertex_project: "${gcp_project}"
      vertex_location: "global"
EOF
        done
    elif [ "${target_cloud}" == "aws" ]; then
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

    cat <<EOF >> /opt/t-airs/src/litellm_config.yaml
mcp_servers:
  sqlite_server:
    url: "http://${mcp_internal_ip}:$MCP_PORT/mcp"
    transport: "http"
    auth_type: "bearer_token"
    auth_value: "${mcp_auth_token}"
    allow_all_keys: true

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

  - guardrail_name: "airs-mcp-pre-scan"
    litellm_params:
      guardrail: panw_prisma_airs
      mode: "pre_mcp_call"
      default_on: true
      api_key: os.environ/AIRS_API_KEY
      profile_name: os.environ/AIRS_PROFILE

  - guardrail_name: "airs-mcp-post-scan"
    litellm_params:
      guardrail: panw_prisma_airs
      mode: "post_mcp_call"
      default_on: true
      api_key: os.environ/AIRS_API_KEY
      profile_name: os.environ/AIRS_PROFILE
EOF
fi

# --- CREATE SYSTEMD SERVICES ---
TAIRS_AFTER="network.target"

if [ "$GATEWAY_PROVIDER" == "litellm" ]; then
    echo "Configuring LiteLLM Service..."
    cat <<EOF > /etc/systemd/system/litellm.service
[Unit]
Description=LiteLLM AI Gateway
After=network.target

[Service]
WorkingDirectory=/opt/t-airs/src
Environment="PANW_PRISMA_AIRS_API_KEY=${airs_key}"
Environment="AIRS_API_KEY=${airs_key}"
Environment="AIRS_PROFILE=${airs_profile}"
Environment="LITELLM_DANGEROUSLY_PERMIT_WEAK_OR_UNSET_MASTER_KEY=true"
ExecStart=/opt/t-airs/venv/bin/litellm --config litellm_config.yaml --port 4000
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable litellm
    systemctl start litellm

    TAIRS_AFTER="$TAIRS_AFTER litellm.service"
fi

cat <<EOF > /etc/systemd/system/t-airs.service
[Unit]
Description=T-AIRS
After=$${TAIRS_AFTER}

[Service]
Environment="HOME=/root"
Environment="HF_HOME=/root/.cache/huggingface"
Environment="HF_HUB_CACHE=/root/.cache/huggingface/hub"
Environment="PORTKEY_API_KEY=${portkey_api_key}"
Environment="PORTKEY_SLUG=${portkey_slug}"
Environment="PORTKEY_MCP_SLUG=${portkey_mcp_slug}"
Environment="MCP_GATEWAY_URL=${mcp_gateway_url}"
Environment="MCP_AUTH_TOKEN=${mcp_auth_token}"
Environment="APP_ENV=${env}"

WorkingDirectory=/opt/t-airs/src

ExecStartPre=/bin/bash -c 'if [ "${gateway_provider}" == "litellm" ]; then until curl -s -f http://127.0.0.1:4000/health/readiness > /dev/null; do echo "Waiting for local LiteLLM AI Gateway..."; sleep 2; done; fi'

ExecStart=/opt/t-airs/venv/bin/python3 main.py --airs-key ${airs_key} --airs-profile ${airs_profile} --gateway-url http://127.0.0.1:4000 --gateway-provider ${gateway_provider} --portkey-slug "${portkey_slug}" --portkey-mcp-slug "${portkey_mcp_slug}"
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable t-airs
systemctl start t-airs