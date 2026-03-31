#!/bin/bash

echo "🛫 Starting Pre-Flight Checks for GCP..."

# --- 1. GLOBAL CHECKS ---
if ! command -v terraform &> /dev/null; then
    echo "❌ ERROR: Terraform is not installed."
    exit 1
fi

if [ -z "$TF_VAR_airs_key" ]; then
    echo "❌ ERROR: TF_VAR_airs_key is not set."
    echo "   Run: export TF_VAR_airs_key='your_prisma_key_here'"
    exit 1
fi

if [ -z "$TF_VAR_airs_profile" ]; then
    echo "❌ ERROR: TF_VAR_airs_profile is not set."
    echo "   Run: export TF_VAR_airs_profile='strict_red_team_profile'"
    exit 1
fi

# --- 2. GCP CHECKS ---
if [ -z "$TF_VAR_gcp_project_id" ] || [ -z "$TF_VAR_gcp_region" ]; then
    echo "❌ ERROR: Missing GCP environment variables."
    echo "   Run: export TF_VAR_gcp_project_id='sase-product-discovery-project'"
    echo "   Run: export TF_VAR_gcp_region='us-central1'"
    exit 1
fi

if ! command -v gcloud &> /dev/null; then
    echo "❌ ERROR: gcloud CLI is not installed."
    exit 1
fi

echo "🔍 Checking GCP Authentication..."
if ! gcloud auth print-access-token &> /dev/null; then
    echo "❌ ERROR: Not logged into GCP. Run: gcloud auth application-default login"
    exit 1
fi

echo "🔍 Checking GCP Compute API..."
if ! gcloud services list --project="$TF_VAR_gcp_project_id" | grep -q "compute.googleapis.com"; then
    echo "❌ ERROR: Compute Engine API is not enabled."
    echo "   Run: gcloud services enable compute.googleapis.com --project=$TF_VAR_gcp_project_id"
    exit 1
fi

echo "🔍 Checking GCP Vertex AI API..."
if ! gcloud services list --project="$TF_VAR_gcp_project_id" | grep -q "aiplatform.googleapis.com"; then
    echo "❌ ERROR: Vertex AI API is not enabled."
    echo "   Run: gcloud services enable aiplatform.googleapis.com --project=$TF_VAR_gcp_project_id"
    exit 1
fi

echo "✅ GCP Pre-flight passed! Ready to deploy."