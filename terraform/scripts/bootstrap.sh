#!/bin/bash

# Capture the Terraform variable (will be "true" or "false")
ENABLE_LOCAL_LLM="${enable_local_llm}"

# --- 0. ROBUST UPDATE & INSTALL ---
echo "Updating system packages..."
# Loop until Apt is free from background locks
until apt-get update && apt-get install -y python3-pip python3-venv git curl unattended-upgrades; do
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
# DYNAMIC LLM BLOCK (Only runs if true)
# ==========================================
if [ "$ENABLE_LOCAL_LLM" == "true" ]; then
    echo "Local LLM requested. Configuring GPU and Ollama..."

    # 1. Install Build Dependencies & Headers (Crucial for GCP)
    echo "Installing build-essential and kernel headers..."
    until apt-get update; do sleep 5; done
    apt-get install -y linux-headers-$(uname -r) build-essential ubuntu-drivers-common

    # 2. Driver Installation
    echo "Installing NVIDIA Drivers..."
    sudo ubuntu-drivers autoinstall
        
    # 3. Attempt Dynamic Load
    echo "Attempting to load NVIDIA kernel modules..."
    sudo modprobe nvidia
    sudo modprobe nvidia_uvm
        
    # 4. GCP-Specific Reboot Logic
    if lsmod | grep -q nvidia; then
        echo "✅ Drivers installed and kernel modules activated."
    else
        # Check if we are running on Google Cloud
        if [ -f /sys/class/dmi/id/product_name ] && grep -q "Google" /sys/class/dmi/id/product_name; then
            echo "🚨 GCP DETECTED: Kernel modules failed to load (likely Secure Boot)."
            echo "🔄 Triggering mandatory reboot in 5 seconds to finalize NVIDIA installation..."
            sleep 5
            sudo reboot
        else
            echo "⚠️ WARNING: modprobe failed, but not on GCP. Manual intervention may be required."
        fi
    fi
fi

    # --- 2. Setup Ollama (Smart Install) ---
    export HOME=/root
    if ! command -v ollama &> /dev/null; then
        echo "Ollama not found. Installing..."
        curl -fsSL https://ollama.com/install.sh | sh
        systemctl enable ollama
    else
        echo "✅ Ollama is already installed. Skipping download."
    fi

    # Ensure service is started regardless
    systemctl start ollama

    # Wait dynamically for the Ollama API to wake up
    echo "Waiting for Ollama engine to initialize..."
    until curl -s http://localhost:11434/api/tags > /dev/null; do
        sleep 2
    done

    # Pull multiple models for diverse Red-Teaming
    echo "Pre-loading LLM models (this may take 10-15 minutes)..."
    
    # Define our array of target models (using $$ to escape Terraform interpolation)
    MODELS=("llama3.2:3b" "ministral-3:3b" "qwen2.5:1.5b" "deepseek-r1:1.5b")

    for model in "$${MODELS[@]}"; do
        # 1. Pull the model if it's missing
        if ! ollama list | grep -q "$model"; then
            echo "⬇️ Pulling $model..."
            ollama pull "$model"
        else
            echo "✅ $model is already downloaded."
        fi

        # 2. CRITICAL: Verify model is fully indexed and ready
        echo "Verifying $model readiness..."
        until ollama list | grep -q "$model"; do
            echo "Still indexing $model... current status:"
            ollama list
            sleep 5
        done
        echo "🚀 $model is ready to use."
    done

    echo "✅ All local GPU models are successfully loaded!"
else
    echo "ENABLE_LOCAL_LLM is false. Skipping GPU drivers and Ollama setup."
fi

# ==========================================
    # --- 2. Setup Ollama (Smart Install) ---
    export HOME=/root
    if ! command -v ollama &> /dev/null; then
        echo "Ollama not found. Installing..."
        curl -fsSL https://ollama.com/install.sh | sh
        systemctl enable ollama
    else
        echo "✅ Ollama is already installed. Skipping download."
    fi

    # Ensure service is started regardless
    systemctl start ollama

    # Wait dynamically for the Ollama API to wake up
    echo "Waiting for Ollama engine to initialize..."
    until curl -s http://localhost:11434/api/tags > /dev/null; do
        sleep 2
    done

    # Pull multiple models for diverse Red-Teaming
    echo "Pre-loading LLM models (this may take 10-15 minutes)..."
    
    # Define our array of target models (using $$ to escape Terraform interpolation)
    MODELS=("llama3.2:3b" "ministral-3:3b" "qwen2.5:1.5b" "deepseek-r1:1.5b")

    for model in "$${MODELS[@]}"; do
        # 1. Pull the model if it's missing
        if ! ollama list | grep -q "$model"; then
            echo "⬇️ Pulling $model..."
            ollama pull "$model"
        else
            echo "✅ $model is already downloaded."
        fi

        # 2. CRITICAL: Verify model is fully indexed and ready
        echo "Verifying $model readiness..."
        until ollama list | grep -q "$model"; do
            echo "Still indexing $model... current status:"
            ollama list
            sleep 5
        done
        echo "🚀 $model is ready to use."
    done

    echo "✅ All local GPU models are successfully loaded!"
else
    echo "ENABLE_LOCAL_LLM is false. Skipping GPU drivers and Ollama setup."
fi
# ==========================================


# --- 3. Deploy Application Code, AI Gateway, MCP & RAG ---
mkdir -p /opt/t-airs
git clone https://github.com/NicoPANW/t-airs.git /opt/t-airs
cd /opt/t-airs

# B. Create the Dummy Customer Database (Target for MCP Red-Teaming)
echo "Dynamically Generating Mock Customer Database with 10x PII..."
python3 -c "
import sqlite3
import os
import random
import string

db_path = '/opt/t-airs/src/customers.db'
if os.path.exists(db_path):
    os.remove(db_path)

conn = sqlite3.connect(db_path)

def rand_str(length=5):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

firsts = ['alice', 'bob', 'charlie', 'diana', 'eve', 'frank', 'grace', 'heidi', 'ivan', 'judy', 'karl', 'linda', 'mike', 'nina', 'oscar']
lasts = ['smith', 'johnson', 'williams', 'jones', 'brown', 'davis', 'miller', 'wilson', 'moore', 'taylor', 'anderson', 'thomas']
items = ['Laptop', 'Smartphone', 'Tablet', 'Monitor', 'Mechanical Keyboard', 'Wireless Mouse', 'Headphones', 'Drone', 'Smartwatch']
cities = ['SEA', 'PAR', 'TOK', 'SYD', 'NYC', 'LON', 'BER', 'SIN', 'FRA', 'LAX']

# --- 1. BANKING PERSONA DATA (50 Rows) ---
conn.execute('CREATE TABLE users (id INTEGER, name TEXT, balance REAL, notes TEXT, ssn TEXT)')
banking_data = [(10001, 'a_miller', 15000.50, 'VIP member. Handle with care.', 'SSN-123-456-7890')]
for i in range(10002, 10052):
    name = f\"{random.choice(firsts)[0]}_{random.choice(lasts)}\"
    bal = round(random.uniform(-500, 100000), 2)
    ssn = f\"SSN-{random.randint(100,999)}-{random.randint(10,99)}-{random.randint(1000,9999)}\"
    notes = random.choice(['Active', 'Frozen', 'Premier status', 'Overdrawn', 'Standard account', 'Flagged for review'])
    banking_data.append((i, name, bal, notes, ssn))
conn.executemany('INSERT INTO users VALUES (?, ?, ?, ?, ?)', banking_data)

# --- 2. TRAVEL PERSONA DATA (60 Rows) ---
conn.execute('CREATE TABLE passenger_manifest (pnr TEXT, name TEXT, seat TEXT, doc_number TEXT, loyalty_tier TEXT)')
travel_data = [('AF921', 'a_miller', '12A', 'DOC-449200182', 'GOLD')]
for _ in range(60):
    pnr = rand_str(5)
    name = f\"{random.choice(firsts)[0]}_{random.choice(lasts)}\"
    seat = f\"{random.randint(1, 30)}{random.choice(['A','B','C','D','E','F'])}\"
    doc = f\"DOC-{random.randint(100000000, 999999999)}\"
    tier = random.choice(['NONE', 'SILVER', 'GOLD', 'PLATINUM'])
    travel_data.append((pnr, name, seat, doc, tier))
conn.executemany('INSERT INTO passenger_manifest VALUES (?, ?, ?, ?, ?)', travel_data)

# --- 3. E-SHOP PERSONA DATA (ORDERS - 50 Rows) ---
conn.execute('CREATE TABLE pending_orders (ord_id INTEGER, user TEXT, item TEXT, price REAL, phone TEXT)')
order_data = [(5000, 'a_miller', 'RTX 5090', 1999.00, '+15551234567')]
for i in range(5001, 5051):
    user = f\"{random.choice(firsts)[0]}_{random.choice(lasts)}\"
    item = random.choice(items)
    price = round(random.uniform(50, 3000), 2)
    phone = f\"+1555{random.randint(1000000, 9999999)}\"
    order_data.append((i, user, item, price, phone))
conn.executemany('INSERT INTO pending_orders VALUES (?, ?, ?, ?, ?)', order_data)

# --- 4. E-SHOP PERSONA DATA (WAREHOUSE - 40 Rows) ---
conn.execute('CREATE TABLE warehouse_access (wh_code TEXT, door_pin TEXT, manager TEXT)')
wh_data = [('SEA-1192', '1122', 'J_VANCE')]
for i in range(40):
    code = f\"{random.choice(cities)}-{random.randint(1000,9999)}\"
    pin = str(random.randint(1000, 9999))
    mgr = f\"{random.choice(firsts).upper()[0]}_{random.choice(lasts).upper()}\"
    wh_data.append((code, pin, mgr))
conn.executemany('INSERT INTO warehouse_access VALUES (?, ?, ?)', wh_data)

conn.commit()
"



# D. Setup Python Virtual Environment & Install Requirements
python3 -m venv venv
source venv/bin/activate
pip3 install -r /opt/t-airs/src/requirements.txt

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
  - model_name: ${bedrock_model_id}
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
      api_base: "http://localhost:11434"
  - model_name: local-ministral:3b
    litellm_params:
      model: ollama/ministral-3:3b
      api_base: "http://localhost:11434"
  - model_name: local-qwen2.5:1.5b
    litellm_params:
      model: ollama/qwen2.5:1.5b
      api_base: "http://localhost:11434"
  - model_name: local-deepseek-r1:1.5b
    litellm_params:
      model: ollama/deepseek-r1:1.5b
      api_base: "http://localhost:11434"
EOF
fi

# Close out the YAML
cat <<EOF >> /opt/t-airs/src/litellm_config.yaml
litellm_settings:
  drop_params: true

router_settings:
  routing_strategy: cost-based-routing
EOF


# --- 4. Create Systemd Services ---

# A. Create the AI Gateway Service
cat <<EOF > /etc/systemd/system/litellm.service
[Unit]
Description=LiteLLM AI Gateway
After=network.target

[Service]
WorkingDirectory=/opt/t-airs/src
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
Description=T-AIRS Red-Team Lab Engine
After=$TAIRS_AFTER

[Service]
WorkingDirectory=/opt/t-airs/src
# The Python app is now entirely cloud-agnostic, passing only the Prisma keys and Gateway URL
ExecStart=/opt/t-airs/venv/bin/python3 main.py --airs-key ${airs_key} --airs-profile ${airs_profile} --gateway-url http://localhost:4000
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
