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

# 1. Baseline Check (Ensures the project can reach the global endpoint at all)
BASELINE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -X GET "https://aiplatform.googleapis.com/v1/projects/$TF_VAR_gcp_project_id/locations/global/publishers/google/models/gemini-2.5-flash" \
  -H "Authorization: Bearer $TOKEN")

if [ "$BASELINE_STATUS" -eq 200 ] || [ "$BASELINE_STATUS" -eq 403 ] || [ "$BASELINE_STATUS" -eq 401 ]; then
    echo "✅ Global Vertex AI is reachable (Baseline verified)."
else
    echo "❌ ERROR: Global Vertex AI Endpoint is not responding (Status: $BASELINE_STATUS)."
    echo "   Ensure your project has the Vertex AI API enabled and billing attached."
    exit 1
fi

# 2. Bleeding-Edge Check (Informative check for Gemini 3)
echo "💎 Checking for Gemini 3.0 capability..."
G3_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -X GET "https://aiplatform.googleapis.com/v1/projects/$TF_VAR_gcp_project_id/locations/global/publishers/google/models/gemini-3.0-flash" \
  -H "Authorization: Bearer $TOKEN")

if [ "$G3_STATUS" -eq 200 ] || [ "$G3_STATUS" -eq 403 ]; then
    echo "✅ SUCCESS: Gemini 3.0 access confirmed! Your lab will use the latest models."
else
    echo "⚠️  NOTE: Gemini 3.0 not detected (Status: $G3_STATUS). The lab will gracefully fall back to Gemini 2.5."
fi

echo "====================================================="
echo "✅ GCP Pre-flight completely passed! Ready to deploy."
