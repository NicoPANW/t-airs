<h1 align="center">🛡️ T-AIRS: AI chatbot app being deployed on GCP or AWS and used to test Prisma AIRS features</h1>

<p align="center">
  <i>A fully automated, Infrastructure-as-Code (IaC) sandbox for testing Prisma AIRS features</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Terraform-7B42BC?style=for-the-badge&logo=terraform&logoColor=white" alt="Terraform">
  <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/AWS-232F3E?style=for-the-badge&logo=amazon-aws&logoColor=white" alt="AWS">
  <img src="https://img.shields.io/badge/GCP-4285F4?style=for-the-badge&logo=google-cloud&logoColor=white" alt="GCP">
  <img src="https://img.shields.io/badge/Ollama-FFFFFF?style=for-the-badge&logo=Ollama&logoColor=black" alt="Ollama">
</p>

---

## ✨ Capabilities of the App

* **☁️ Multi-Cloud Ready:** Deploy seamlessly to AWS (using Amazon Bedrock) or GCP (using Vertex AI) with a single variable change.
* **🛡️ Prisma AIRS Integration:** Deep, native integration with Palo Alto Networks Prisma AIRS for synchronous Ingress (User Prompt) and Egress (LLM Response) security scanning.
* **🎭 Dynamic Personas:** Instantly switch the AI's system prompt (e.g., Banking, Travel, E-Shop) and edit the constraints live from the UI to test different attack vectors.
* **🔎 Visual Metadata Trace:** A built-in inspector panel shows you the exact raw JSON decision logic from Prisma AIRS on every single interaction.
* **🏠 Local models:** even though not recommended since far slower than GCP/AWS SAAS models, there is an option to deploy local models

---

## 🏗️ How it is Designed

To keep the application clean and scalable, this repository is a "Monorepo" split into two distinct layers:

1. **The Application Layer (`/src`):** Contains the custom Python FastAPI backend and the sleek web UI. It acts as the "brain," routing messages between the user, the cloud AI models, the local Ollama engine, and the Prisma AIRS security scanner.
2. **The Infrastructure Layer (`/terraform`):** Contains the Terraform blueprints. It dynamically builds a dedicated Virtual Private Cloud (VPC), configures strict firewall rules, and launches a Virtual Machine injected with a `bootstrap.sh` script to install the application and AI models automatically.

---

## 🛠️ Prerequisites

Before you begin, you need a few basic tools installed on your computer:

1. **Terraform:** Download the engine that builds the cloud infrastructure.
2. **Prisma AIRS API Key:** You must have a valid Prisma AIRS profile and API key.
3. **Cloud Authentication:** You must be logged into your target cloud provider via your computer's terminal:
   * **For AWS:** Install the AWS CLI and run `aws configure`. 
   * **For GCP:** Install the Google Cloud SDK and run `gcloud auth application-default login`.
4. **SSH Key (AWS Only):** You must have an Ed25519 SSH key pair generated on your local machine. Terraform will automatically inject this key into the AWS server. If you don't have one, generate it by running:
   `ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""`

> [!IMPORTANT]  
> **AWS Bedrock Users:** AWS does not enable models by default. You must log into the AWS Console, navigate to Amazon Bedrock -> Model Access, and request access to Anthropic, Meta, and Mistral models before deploying.

---

## 🚀 Quick Start Deployment Guide

### Step 1: Clone the Repository
Download the code to your local machine and enter the directory.

```bash
git clone [https://github.com/NicoPANW/t-airs.git](https://github.com/NicoPANW/t-airs.git)
cd t-airs
```

### Step 2: Export Your Variables
Terraform needs to know your environment details. Export them as environment variables in your terminal:

```bash
# If deploying to AWS:
export TF_VAR_aws_region="us-east-1"
export TF_VAR_airs_key="your_prisma_airs_api_key_here"
export TF_VAR_airs_profile="Your-Profile-Name"

# If deploying to GCP:
export TF_VAR_gcp_project_id="your-gcp-project-id"
export TF_VAR_gcp_region="us-central1"
export TF_VAR_airs_key="your_prisma_airs_api_key_here"
export TF_VAR_airs_profile="Your-Profile-Name"
```

### Step 3: Run the Preflight Check
Run our built-in safety script to make sure your terminal is configured correctly.

```bash
# For AWS
./preflight_aws.sh

# For GCP
./preflight_gcp.sh
```

### Step 4: Deploy with Terraform
Navigate to the terraform folder, initialize the plugins, and launch the lab!

```bash
cd terraform
terraform init
terraform apply -var="target_cloud=gcp" -auto-approve
```

> [!NOTE]  
> If you want to use local LLM with GPU, use this command instead `terraform apply -var="target_cloud=gcp" -var="enable_local_llm=true" -auto-approve`, it will use a bigger instance with an Nvidia T4 GPU, the server will take about **15-20 minutes** to boot up, install the NVIDIA drivers, and pull the 24GB of local AI models. Grab a coffee!

### Step 5: Access the Lab
Once Terraform finishes, it will print out the Public IP address of your new server. Open your web browser and go to:

```bash
http://<YOUR_SERVER_IP>:8000
```

---

## 🛑 Teardown (Stop Paying for the Cloud!)

> [!WARNING]  
> **Do not leave this running!** VMs cost money by the hour. When you are done testing, destroy the entire lab securely to stop billing.

Destroy the lab with one command:

```bash
cd terraform
terraform destroy -auto-approve
```

---

## 🐛 Troubleshooting & Debugging

If the UI isn't loading, or a model isn't connecting, use this cheat sheet to play detective:

### Step 1: SSH into the VM
Before you can run any debug commands, you must log into the server's terminal. 

**For AWS:**
```bash
ssh ubuntu@<YOUR_AWS_PUBLIC_IP>
```

**For GCP:**
```bash
gcloud compute ssh ubuntu@t-airs-production-node --zone=us-central1-a
```

### Step 2: General App Debugging (AWS & GCP)
Once logged in, you can check your live app logs, reset the service, or check your local models:

```bash
sudo journalctl -u t-airs.service -n 50 -f
sudo systemctl restart t-airs
ollama list
```

### Step 3: AWS-Specific Debugging
Check the cloud-init logs to verify if the Terraform startup script and GPU installation succeeded:

```bash
sudo tail -n 100 /var/log/cloud-init-output.log
sudo grep -i "Local LLM" /var/log/cloud-init-output.log
```

### Step 4: GCP-Specific Debugging
Check the Google Guest Agent logs to verify how the startup script executed:

```bash
sudo journalctl -u google-startup-scripts.service --no-pager
curl -H "Metadata-Flavor: Google" [http://metadata.google.internal/computeMetadata/v1/instance/attributes/startup-script](http://metadata.google.internal/computeMetadata/v1/instance/attributes/startup-script)
```
