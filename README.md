🛡️ T-AIRS: Multi-Cloud AI Red-Team Lab
Welcome to T-AIRS (Threat-AI Red-Team Simulator)! This project is a fully automated, Infrastructure-as-Code (IaC) deployment that builds a secure, isolated sandbox for testing AI security guardrails.

With a single command, you can deploy a live AI chatbot interface to either AWS or Google Cloud (GCP). It is backed by powerful cloud LLMs and an optional local GPU-accelerated engine loaded with 5 top-tier models. Every single prompt and response is actively monitored by Palo Alto Networks Prisma AIRS to detect and block malicious injections, data exfiltration, and policy violations in real-time.

✨ Capabilities of the App
☁️ Multi-Cloud Ready: Deploy seamlessly to AWS (using Amazon Bedrock) or GCP (using Vertex AI).

🏎️ Local GPU Arsenal: Automatically provisions NVIDIA T4 GPUs, installs CUDA drivers, and spins up a local Ollama engine loaded with:

Llama 3 (8B)

Mistral (7B)

Gemma 2 (9B)

Qwen 2.5 (7B)

DeepSeek-R1 (7B)

🛡️ Prisma AIRS Integration: Deep, native integration with Prisma AIRS for synchronous Ingress (User Prompt) and Egress (LLM Response) security scanning.

🎭 Dynamic Personas: Instantly switch the AI's system prompt (e.g., Banking, Travel, E-Shop) and edit the constraints live from the UI to test different attack vectors.

🔎 Visual Metadata Trace: A built-in inspector panel shows you the exact raw JSON decision logic from Prisma AIRS on every single interaction.

🏗️ How it is Designed
To keep the application clean and scalable, this repository is a "Monorepo" split into two distinct layers:

The Application Layer (/src): Contains the Python FastAPI backend and the web UI. It acts as the "brain," routing messages between the user, the cloud AI models, the local Ollama engine, and the Prisma AIRS security scanner.

The Infrastructure Layer (/terraform): Contains the Terraform blueprints. It dynamically builds a dedicated Virtual Private Cloud (VPC), configures strict firewall rules, and launches a Virtual Machine injected with a bootstrap.sh script to install the application automatically.

🛠️ Prerequisites
Before you begin, you need a few basic tools installed on your computer:

Terraform: Download here (The engine that builds the cloud infrastructure).

Prisma AIRS API Key: You must have a valid Prisma AIRS profile and API key.

Cloud Authentication: You must be logged into your target cloud provider via your computer's terminal:

For AWS: Install the AWS CLI and run aws configure. (Note: You must request model access in the AWS Bedrock console first!)

For GCP: Install the Google Cloud SDK and run gcloud auth application-default login.

🚀 Quick Start Deployment Guide
Step 1: Clone the Repository
Download the code to your local machine and enter the directory.

Bash
git clone [https://github.com/YourUsername/t-airs.git](https://github.com/YourUsername/t-airs.git)
cd t-airs
Step 2: Export Your Variables
Terraform needs to know your environment details, but we never hardcode secrets. Export them as environment variables in your terminal:

Bash
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

Bash
# For AWS
./preflight_aws.sh

# For GCP
./preflight_gcp.sh
(If it says "All preflight checks passed!", you are ready to go!)

Step 4: Deploy with Terraform
Navigate to the terraform folder, initialize the plugins, and launch the lab!

Bash
cd terraform
terraform init
terraform apply -auto-approve
Note: If you enabled the Local LLM (GPU), the server will take about 15-20 minutes to boot up, install the NVIDIA drivers, and pull the 24GB of local AI models.

Step 5: Access the Lab
Once Terraform finishes, it will print out the Public IP address of your new server.
Open your web browser and go to:
http://<YOUR_SERVER_IP>:8000

🛑 Teardown (Stop Paying for the Cloud!)
When you are done testing, do not leave this running. GPUs cost money by the hour! Destroy the entire lab securely with one command:

Bash
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
Connect via SSH: gcloud compute ssh ubuntu@<YOUR_GCP_PUBLIC_IP> --zone=us-central1-a

Check the startup script (Guest Agent) logs: sudo journalctl -u google-startup-scripts.service --no-pager

Check the raw script GCP received from Terraform: curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/attributes/startup-script
