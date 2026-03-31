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

    # --- 1. DRIVER INSTALLATION ---
    echo "Checking for NVIDIA Drivers..."
    if ! command -v nvidia-smi &> /dev/null; then
        echo "Installing NVIDIA Drivers..."
        until apt-get update && apt-get install -y ubuntu-drivers-common; do sleep 5; done
        
        # Install the drivers
        sudo ubuntu-drivers autoinstall
        
        # Dynamically load the NVIDIA kernel modules WITHOUT rebooting
        echo "Loading NVIDIA kernel modules..."
        sudo modprobe nvidia
        sudo modprobe nvidia_uvm
        
        echo "✅ Drivers installed and activated."
    else
        echo "✅ NVIDIA drivers already present."
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
    echo "Pre-loading LLM models (this may take 3-5 minutes)..."
    
    # Only pull if it's missing
    if ! ollama list | grep -q "llama3"; then
        ollama pull llama3
    fi

    # CRITICAL: Verify model is indexed in the library
    echo "Verifying model library readiness..."
    until ollama list | grep -q "llama3"; do
        echo "Still indexing models... current status:"
        ollama list
        sleep 5
    done

    echo "✅ Ollama is ready with Llama3."
else
    echo "ENABLE_LOCAL_LLM is false. Skipping GPU drivers and Ollama setup."
fi
# ==========================================


# --- 3. Deploy Application Code ---
mkdir -p /opt/t-airs
git clone https://github.com/NicoPANW/t-airs.git /opt/t-airs
cd /opt/t-airs

# Setup Python Virtual Environment & Install Requirements
python3 -m venv venv
source venv/bin/activate
pip3 install -r /opt/t-airs/src/requirements.txt

# --- 4. Create Systemd Service for Auto-Start ---
# Conditionally set the service dependencies
if [ "${enable_local_llm}" == "true" ]; then
    SYSTEMD_AFTER="network.target ollama.service"
else
    SYSTEMD_AFTER="network.target"
fi

# 1. Write the top half of the systemd file
cat <<EOF > /etc/systemd/system/t-airs.service
[Unit]
Description=T-AIRS Red-Team Lab Engine
After=$SYSTEMD_AFTER

[Service]
WorkingDirectory=/opt/t-airs/src
EOF

# 2. Safely append the exact ExecStart line using Terraform variables natively
if [ "${target_cloud}" == "aws" ]; then
    echo "ExecStart=/opt/t-airs/venv/bin/python3 main.py --target-cloud aws --aws-region ${aws_region} --bedrock-model-id ${bedrock_model_id} --airs-key ${airs_key} --airs-profile ${airs_profile} --local-llm ${enable_local_llm}" >> /etc/systemd/system/t-airs.service
else
    echo "ExecStart=/opt/t-airs/venv/bin/python3 main.py --target-cloud gcp --gcp-project ${gcp_project} --gcp-region ${gcp_region} --airs-key ${airs_key} --airs-profile ${airs_profile} --local-llm ${enable_local_llm}" >> /etc/systemd/system/t-airs.service
fi

# 3. Write the bottom half of the file
cat <<EOF >> /etc/systemd/system/t-airs.service
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable t-airs
systemctl start t-airs
