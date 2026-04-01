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

# --- 3. GLOBAL VERTEX AI CONNECTIVITY CHECK ---
echo "📡 Verifying Global Vertex AI Connectivity..."

# We "ping" the global Gemini 1.5 Flash endpoint. 
# A 200 means success. A 403/401 means the endpoint exists but we need full credentials (still a pass).
# A 404 means the Global endpoint is unreachable.
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -X GET "https://aiplatform.googleapis.com/v1/projects/$TF_VAR_gcp_project_id/locations/global/publishers/google/models/gemini-1.5-flash" \
  -H "Authorization: Bearer $TOKEN")

if [ "$HTTP_STATUS" -eq 200 ] || [ "$HTTP_STATUS" -eq 403 ] || [ "$HTTP_STATUS" -eq 401 ]; then
    echo "✅ Global Vertex AI is reachable."
else
    echo "❌ ERROR: Global Vertex AI Endpoint is not responding (Status: $HTTP_STATUS)."
    exit 1
fi

echo "✅ GCP Pre-flight passed! Ready to deploy."
