<h1 align="center">🛡️ T-AIRS: Multi-Cloud AI Red-Team Lab</h1>

<p align="center">
  <i>A fully automated, Infrastructure-as-Code (IaC) sandbox for testing AI security guardrails.</i>
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
* **🏎️ Local GPU Arsenal:** Automatically provisions NVIDIA T4 GPUs, installs CUDA drivers, and spins up a local Ollama engine loaded with:
  * `Llama 3 (8B)`
  * `Mistral (7B)`
  * `Gemma 2 (9B)`
  * `Qwen 2.5 (7B)`
  * `DeepSeek-R1 (7B)`
* **🛡️ Prisma AIRS Integration:** Deep, native integration with Palo Alto Networks Prisma AIRS for synchronous Ingress (User Prompt) and Egress (LLM Response) security scanning.
* **🎭 Dynamic Personas:** Instantly switch the AI's system prompt (e.g., Banking, Travel, E-Shop) and edit the constraints live from the UI to test different attack vectors.
* **🔎 Visual Metadata Trace:** A built-in inspector panel shows you the exact raw JSON decision logic from Prisma AIRS on every single interaction.

---

## 🏗️ How it is Designed

To keep the application clean and scalable, this repository is a "Monorepo" split into two distinct layers:

1. **The Application Layer (`/src`):** Contains the custom Python FastAPI backend and the sleek web UI. It acts as the "brain," routing messages between the user, the cloud AI models, the local Ollama engine, and the Prisma AIRS security scanner.
2. **The Infrastructure Layer (`/terraform`):** Contains the Terraform blueprints. It dynamically builds a dedicated Virtual Private Cloud (VPC), configures strict firewall rules, and launches a Virtual Machine injected with a `bootstrap.sh` script to install the application and AI models automatically.

---

## 🛠️ Prerequisites

Before you begin, you need a few basic tools installed on your computer:

1. **Terraform:** [Download here](https://developer.hashicorp.com/terraform/downloads)
2. **Prisma AIRS API Key:** You must have a valid Prisma AIRS profile and API key.
3. **Cloud Authentication:** You must be logged into your target cloud provider via your computer's terminal:
   * **For AWS:** Install the [AWS CLI](https://aws.amazon.com/cli/) and run `aws configure`. 
   * **For GCP:** Install the [Google Cloud SDK](https://cloud.google.com/sdk/docs/install) and run `gcloud auth application-default login`.

> [!IMPORTANT]  
> **AWS Bedrock Users:** AWS does not enable models by default. You must log into the AWS Console, navigate to Amazon Bedrock -> Model Access, and request access to Anthropic, Meta, and Mistral models before deploying.

---

## 🚀 Quick Start Deployment Guide

### Step 1: Clone the Repository
Download the code to your local machine and enter the directory.

```bash
git clone [https://github.com/NicoPANW/t-airs.git](https://github.com/NicoPANW/t-airs.git)
cd t-airs
