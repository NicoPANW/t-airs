#!/bin/bash

echo "🛫 Starting Pre-Flight Checks for GCP (Global Mode)..."

FAILED=0

# --- 1. GLOBAL CHECKS ---
if ! command -v terraform &> /dev/null; then
    echo "❌ ERROR: Terraform is not installed."
    FAILED=1
fi

if [ -z "$TF_VAR_airs_key" ]; then
    echo "❌ ERROR: TF_VAR_airs_key is not set."
    FAILED=1
fi

if [ -z "$TF_VAR_airs_profile" ]; then
    echo "❌ ERROR: TF_VAR_airs_profile is not set."
    FAILED=1
fi

# --- 2. GCP ENV CHECKS ---
if [ -z "$TF_VAR_gcp_project_id" ] || [ -z "$TF_VAR_gcp_region" ]; then
    echo "❌ ERROR: Missing GCP environment variables (Project ID or Region)."
    FAILED=1
fi

if ! command -v gcloud &> /dev/null; then
    echo "❌ ERROR: gcloud CLI is not installed."
    FAILED=1
fi

echo "🔍 Checking GCP Authentication..."
if command -v gcloud &> /dev/null; then
    TOKEN=$(gcloud auth print-access-token 2>/dev/null)
    if [ -z "$TOKEN" ]; then
        echo "❌ ERROR: Not logged into GCP. Run: gcloud auth login"
        FAILED=1
    else
        echo "✅ GCP Authentication successful."
    fi
else
    echo "❌ ERROR: Cannot check GCP Authentication because gcloud CLI is not installed."
    FAILED=1
fi

echo "🔍 Checking Required APIs.."
if command -v gcloud &> /dev/null && [ -n "$TF_VAR_gcp_project_id" ] && [ -n "$TOKEN" ]; then
    ENABLED_SERVICES=$(gcloud services list --project="$TF_VAR_gcp_project_id" --format="value(config.name)" 2>/dev/null)
    API_ERR=0
    for api in "compute.googleapis.com" "aiplatform.googleapis.com"; do
        if [[ ! "$ENABLED_SERVICES" =~ "$api" ]]; then
            echo "❌ ERROR: $api is not enabled."
            echo "   Run: gcloud services enable $api --project=$TF_VAR_gcp_project_id"
            FAILED=1
            API_ERR=1
        fi
    done
    if [ "$API_ERR" -eq 0 ]; then
        echo "✅ All required APIs are enabled."
    fi
else
    echo "❌ ERROR: Skipping Required APIs check because GCP project, gcloud CLI, or access token is missing/invalid."
    FAILED=1
fi


# --- 2.5 REGION & ZONE TOPOLOGY CHECK ---
echo "🔍 Validating Region and Zone Topology..."
if command -v gcloud &> /dev/null && [ -n "$TF_VAR_gcp_project_id" ] && [ -n "$TOKEN" ] && [ -n "$TF_VAR_gcp_region" ]; then
    # 1. Check if the provided string is a valid Region
    VALID_REGION=$(gcloud compute regions list --filter="name=($TF_VAR_gcp_region)" --format="value(name)" --project="$TF_VAR_gcp_project_id" 2>/dev/null)

    if [ -z "$VALID_REGION" ]; then
        echo "❌ ERROR: '$TF_VAR_gcp_region' is not a valid GCP region."
        echo "   (Hint: If you typed 'us-central1-a', that is a Zone. Drop the '-a' and just use 'us-central1')."
        FAILED=1
    else
        # 2. Check if the -a Zone exists for this Region
        TARGET_ZONE="${TF_VAR_gcp_region}-a"
        VALID_ZONE=$(gcloud compute zones list --filter="name=($TARGET_ZONE)" --format="value(name)" --project="$TF_VAR_gcp_project_id" 2>/dev/null)

        if [ -z "$VALID_ZONE" ]; then
            echo "❌ ERROR: The zone '$TARGET_ZONE' does not exist physically in Google Cloud."
            FAILED=1
        else
            echo "✅ Region ($TF_VAR_gcp_region) and Target Zone ($TARGET_ZONE) verified."
        fi
    fi
else
    echo "❌ ERROR: Skipping Region & Zone topology checks because environment coordinates, gcloud, or token are missing/invalid."
    FAILED=1
fi

# --- 3. GLOBAL VERTEX AI CONNECTIVITY & CAPABILITY CHECK ---
echo "📡 Verifying Global Vertex AI Connectivity..."
if [ -n "$TOKEN" ] && [ -n "$TF_VAR_gcp_project_id" ]; then
    # Define the precise list of Gemini models to verify
    GEMINI_MODELS=(
        "gemini-2.5-flash"
        "gemini-2.5-flash-lite"
        "gemini-2.5-pro"
        "gemini-3.1-flash-lite"
        "gemini-3.5-flash"
        "gemini-3.5-flash-lite"
        "gemini-3.6-flash"
    )

    ACTIVE_MODELS=0

    for model in "${GEMINI_MODELS[@]}"; do
        echo "🔍 Checking Global Vertex AI Model ($model) Status..."
        
        # A 400 Bad Request or 200 OK indicates the model is ready and responding
        MODEL_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
          -X POST "https://aiplatform.googleapis.com/v1beta1/projects/$TF_VAR_gcp_project_id/locations/global/publishers/google/models/$model:generateContent" \
          -H "Authorization: Bearer $TOKEN" \
          -H "Content-Type: application/json" \
          -d '{}')

        if [ "$MODEL_STATUS" -eq 400 ] || [ "$MODEL_STATUS" -eq 200 ]; then
            echo "✅ Model $model is ACTIVE."
            ACTIVE_MODELS=$((ACTIVE_MODELS + 1))
        else
            echo "⚠️  WARNING: Model '$model' is not active/available (Status: $MODEL_STATUS)."
        fi
    done

    if [ "$ACTIVE_MODELS" -eq 0 ]; then
        echo "❌ ERROR: None of the required Gemini models are active in project '$TF_VAR_gcp_project_id'. Deployment cannot continue."
        FAILED=1
    fi
else
    echo "❌ ERROR: Skipping Vertex AI Connectivity check because authentication token or project ID is missing."
    FAILED=1
fi

# --- 4. PORTKEY API CONNECTIVITY CHECK ---
if [ -n "$TF_VAR_portkey_api_key" ]; then
    echo "📡 Verifying Portkey API Connectivity via Python..."
    python3 -c "
import sys, urllib.request, urllib.error
try:
    headers = {'x-portkey-api-key': '$TF_VAR_portkey_api_key', 'User-Agent': 'Mozilla/5.0'}
    if '$TF_VAR_portkey_slug':
        headers['x-portkey-virtual-key'] = '$TF_VAR_portkey_slug'
    req = urllib.request.Request(
        'https://aigw.portkey.ai/v1/models',
        headers=headers
    )
    with urllib.request.urlopen(req, timeout=5) as response:
        if response.status == 200:
            print('✅ Portkey connectivity and API key verified successfully.')
            sys.exit(0)
except urllib.error.HTTPError as e:
    print(f'❌ Portkey API Error ({e.code}): {e.read().decode(\"utf-8\")}')
    sys.exit(1)
except Exception as e:
    print(f'❌ Network Error: {e}')
    sys.exit(1)
"
    if [ $? -ne 0 ]; then
                FAILED=1
    fi
fi

if [ -z "$TF_VAR_prisma_airs_ips" ]; then
            echo "⚠️  NOTE: TF_VAR_airs_ips is not set. Use default settings."
else
    echo "✅ Dynamic AIRS IPs detected: $TF_VAR_prisma_airs_ips"
fi

        if [ "$FAILED" -eq 1 ]; then
            echo "❌ GCP Pre-flight FAILED! One or more validation checks have failed. Please review the output above."
            exit 1
        else
            echo "✅ GCP Pre-flight passed! Ready to deploy."
        fi
