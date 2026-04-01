#!/bin/bash

echo "🛫 Starting Pre-Flight Checks for GCP (Global Mode)..."

# --- 1. GLOBAL CHECKS ---
if ! command -v terraform &> /dev/null; then
    echo "❌ ERROR: Terraform is not installed."
    exit 1
fi

if [ -z "$TF_VAR_airs_key" ]; then
    echo "❌ ERROR: TF_VAR_airs_key is not set."
    exit 1
fi

if [ -z "$TF_VAR_airs_profile" ]; then
    echo "❌ ERROR: TF_VAR_airs_profile is not set."
    exit 1
fi

# --- 2. GCP ENV CHECKS ---
if [ -z "$TF_VAR_gcp_project_id" ] || [ -z "$TF_VAR_gcp_region" ]; then
    echo "❌ ERROR: Missing GCP environment variables (Project ID or Region)."
    exit 1
fi

if ! command -v gcloud &> /dev/null; then
    echo "❌ ERROR: gcloud CLI is not installed."
    exit 1
fi

echo "🔍 Checking GCP Authentication..."
TOKEN=$(gcloud auth print-access-token 2>/dev/null)
if [ -z "$TOKEN" ]; then
    echo "❌ ERROR: Not logged into GCP. Run: gcloud auth application-default login"
    exit 1
fi

echo "🔍 Checking Required APIs..."
ENABLED_SERVICES=$(gcloud services list --project="$TF_VAR_gcp_project_id" --format="value(config.name)")

for api in "compute.googleapis.com" "aiplatform.googleapis.com"; do
    if [[ ! "$ENABLED_SERVICES" =~ "$api" ]]; then
        echo "❌ ERROR: $api is not enabled."
        echo "   Run: gcloud services enable $api --project=$TF_VAR_gcp_project_id"
        exit 1
    fi
done

# --- 3. GLOBAL VERTEX AI CONNECTIVITY & CAPABILITY CHECK ---
echo "📡 Verifying Global Vertex AI Connectivity..."

TOKEN=$(gcloud auth print-access-token 2>/dev/null)
if [ -z "$TOKEN" ]; then
    echo "❌ ERROR: Could not retrieve GCP auth token."
    exit 1
fi

# 1. Baseline Check (POST to :generateContent)
# A 400 Bad Request is a SUCCESS here—it means the model caught the empty payload.
BASELINE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "https://aiplatform.googleapis.com/v1/projects/$TF_VAR_gcp_project_id/locations/global/publishers/google/models/gemini-2.5-flash:generateContent" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}')

if [ "$BASELINE_STATUS" -eq 400 ] || [ "$BASELINE_STATUS" -eq 200 ] || [ "$BASELINE_STATUS" -eq 403 ]; then
    echo "✅ Global Vertex AI is reachable (Baseline verified)."
else
    echo "❌ ERROR: Global Vertex AI Endpoint is not responding (Status: $BASELINE_STATUS)."
    echo "   Ensure your project has the Vertex AI API enabled and billing attached."
    exit 1
fi

# 2. Bleeding-Edge Check for Gemini 3.x Preview (Using v1beta1 API)
echo "💎 Checking for Gemini 3.x capability..."
G3_FOUND=false

# We loop through the exact preview model IDs currently deployed on the Global endpoint
for model in "gemini-3.1-pro-preview" "gemini-3.1-flash-preview" "gemini-3.0-flash-lite-preview"; do
    G3_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
      -X POST "https://aiplatform.googleapis.com/v1beta1/projects/$TF_VAR_gcp_project_id/locations/global/publishers/google/models/$model:generateContent" \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d '{}')

    # 400 Bad Request is success (the model exists but rejected our empty JSON)
    if [ "$G3_STATUS" -eq 400 ] || [ "$G3_STATUS" -eq 200 ]; then
        echo "✅ SUCCESS: $model access confirmed! Your lab will use the latest models."
        G3_FOUND=true
        break # Stop checking once we find one that works
    fi
done

if [ "$G3_FOUND" = false ]; then
    echo "⚠️  NOTE: Gemini 3.x Preview not detected on Global API. The lab will gracefully fall back to Gemini 2.5."
fi

if [ -z "$TF_VAR_prisma_airs_ips" ]; then
    echo "⚠️  NOTE: TF_VAR_airs_ips is not set. Terraform will use the default AIRS IPs."
else
    echo "✅ Dynamic AIRS IPs detected: $TF_VAR_prisma_airs_ips"
fi
