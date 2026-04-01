<h1 align="center">🛡️ T-AIRS: Multi-Cloud AI Red-Team Lab</h1>

<p align="center">
<i>A fully automated, Infrastructure-as-Code (IaC) sandbox for testing AI security guardrails.</i>
</p>

<p align="center">
<img src="https://www.google.com/search?q=https://img.shields.io/badge/Terraform-7B42BC%3Fstyle%3Dfor-the-badge%26logo%3Dterraform%26logoColor%3Dwhite" alt="Terraform">
<img src="https://www.google.com/search?q=https://img.shields.io/badge/Python-3776AB%3Fstyle%3Dfor-the-badge%26logo%3Dpython%26logoColor%3Dwhite" alt="Python">
<img src="https://www.google.com/search?q=https://img.shields.io/badge/AWS-232F3E%3Fstyle%3Dfor-the-badge%26logo%3Damazon-aws%26logoColor%3Dwhite" alt="AWS">
<img src="https://www.google.com/search?q=https://img.shields.io/badge/GCP-4285F4%3Fstyle%3Dfor-the-badge%26logo%3Dgoogle-cloud%26logoColor%3Dwhite" alt="GCP">
<img src="https://www.google.com/search?q=https://img.shields.io/badge/Ollama-FFFFFF%3Fstyle%3Dfor-the-badge%26logo%3DOllama%26logoColor%3Dblack" alt="Ollama">
</p>

📖 Table of Contents

✨ Capabilities

🏗️ Architecture Design

🛠️ Prerequisites

🚀 Quick Start Deployment Guide

🛑 Teardown (Important)

🐛 Troubleshooting & Debugging

✨ Capabilities of the App

☁️ Multi-Cloud Ready: Deploy seamlessly to AWS (using Amazon Bedrock) or GCP (using Vertex AI) with a single variable change.

🏎️ Local GPU Arsenal: Automatically provisions NVIDIA T4 GPUs, installs CUDA drivers, and spins up a local Ollama engine loaded with:

Llama 3 (8B)

Mistral (7B)

Gemma 2 (9B)

Qwen 2.5 (7B)

DeepSeek-R1 (7B)

🛡️ Prisma AIRS Integration: Deep, native integration with Palo Alto Networks Prisma AIRS for synchronous Ingress (User Prompt) and Egress (LLM Response) security scanning.

🎭 Dynamic Personas: Instantly switch the AI's system prompt (e.g., Banking, Travel, E-Shop) and edit the constraints live from the UI to test different attack vectors.

🔎 Visual Metadata Trace: A built-in inspector panel shows you the exact raw JSON decision logic from Prisma AIRS on every single interaction.

🏗️ How it is Designed

To keep the application clean and scalable, this repository is a "Monorepo" split into two distinct layers:

The Application Layer (/src): Contains the custom Python FastAPI backend and the sleek web UI. It acts as the "brain," routing messages between the user, the cloud AI models, the local Ollama engine, and the Prisma AIRS security scanner.

The Infrastructure Layer (/terraform): Contains the Terraform blueprints. It dynamically builds a dedicated Virtual Private Cloud (VPC), configures strict firewall rules, and launches a Virtual Machine injected with a bootstrap.sh script to install the application and AI models automatically.

🛠️ Prerequisites

Before you begin, you need a few basic tools installed on your computer:

Terraform: Download here (The engine that builds the cloud infrastructure).

Prisma AIRS API Key: You must have a valid Prisma AIRS profile and API key.

Cloud Authentication: You must be logged into your target cloud provider via your computer's terminal:

For AWS: Install the AWS CLI and run aws configure.

For GCP: Install the Google Cloud SDK and run gcloud auth application-default login.

[!IMPORTANT]

AWS Bedrock Users: AWS does not enable models by default. You must log into the AWS Console, navigate to Amazon Bedrock -> Model Access, and request access to Anthropic, Meta, and Mistral models before deploying.

🚀 Quick Start Deployment Guide

Step 1: Clone the Repository

Download the code to your local machine and enter the directory.

git clone [https://github.com/NicoPANW/t-airs.git](https://github.com/NicoPANW/t-airs.git)
cd t-airs


Step 2: Export Your Variables

Terraform needs to know your environment details, but we never hardcode secrets. Export them as environment variables in your terminal:

# Required for both clouds:
export TF_VAR_airs_key="your_prisma_airs_api_key_here"
export TF_VAR_airs_profile="Your-Profile-Name"
export TF_VAR_enable_local_llm="true" # Set to "false" if you don't want a GPU/Ollama

# If deploying to AWS:
export TF_VAR_target_cloud="aws"
export TF_VAR_aws_region="us-east-1"
export TF_VAR_bedrock_model_id="meta.llama3-8b-instruct-v1:0"

# If deploying to GCP:
export TF_VAR_target_cloud="gcp"
export TF_VAR_gcp_project_id="your-gcp-project-id"
export TF_VAR_gcp_region="us-central1"


Step 3: Run the Preflight Check

Run our built-in safety script to make sure your terminal is configured correctly before you try to build anything.

# For AWS
./preflight_aws.sh

# For GCP
./preflight_gcp.sh


Step 4: Deploy with Terraform

Navigate to the terraform folder, initialize the plugins, and launch the lab!

cd terraform
terraform init
terraform apply -auto-approve


[!NOTE]

If you enabled the Local LLM (GPU), the server will take about 15-20 minutes to boot up, install the NVIDIA drivers, and pull the 24GB of local AI models. Grab a coffee!

Step 5: Access the Lab

Once Terraform finishes, it will print out the Public IP address of your new server. Open your web browser and go to:
http://<YOUR_SERVER_IP>:8000

🛑 Teardown (Stop Paying for the Cloud!)

[!WARNING]

Do not leave this running! GPUs cost money by the hour. When you are done testing, destroy the entire lab securely to stop billing.

Destroy the lab with one command:

cd terraform
terraform destroy -auto-approve


🐛 Troubleshooting & Debugging

If the UI isn't loading, or a model isn't connecting, use this cheat sheet to play detective:

1. General App Debugging (AWS & GCP)

Use these commands to check the Python application or local LLM engine.

Check live application logs: sudo journalctl -u t-airs.service -n 50 -f

Restart the application: sudo systemctl restart t-airs

Verify downloaded local models: ollama list

2. AWS-Specific Debugging

Connect via SSH: ssh ubuntu@<YOUR_AWS_PUBLIC_IP>

Check the startup script (cloud-init) logs: sudo tail -n 100 /var/log/cloud-init-output.log

Check if GPU installed: sudo grep -i "Local LLM" /var/log/cloud-init-output.log

3. GCP-Specific Debugging

Connect via SSH: gcloud compute ssh ubuntu@t-airs-production-node --zone=us-central1-a

Check the startup script (Guest Agent) logs: sudo journalctl -u google-startup-scripts.service --no-pager

Check the raw script GCP received: curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/attributes/startup-script

<p align="center"><i>Developed by Nico PANW</i></p>
