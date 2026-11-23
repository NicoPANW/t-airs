#!/bin/bash

echo "🛫 Starting Pre-Flight Checks for GCP (Multi-VM + AI Gateway Mode)..."

FAILED=0

# Resolve repository root regardless of current working directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/src/gemini_models.json" ]; then
    REPO_ROOT="$SCRIPT_DIR"
elif [ -f "$SCRIPT_DIR/../src/gemini_models.json" ]; then
    REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
else
    REPO_ROOT="$(pwd)"
fi

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

# --- 2. GCP ENV & API CHECKS ---
if [ -z "$TF_VAR_gcp_project_id" ] || [ -z "$TF_VAR_gcp_region" ]; then
    echo "❌ ERROR: Missing GCP environment variables (TF_VAR_gcp_project_id or TF_VAR_gcp_region)."
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

echo "🔍 Checking Required APIs..."
if command -v gcloud &> /dev/null && [ -n "$TF_VAR_gcp_project_id" ] && [ -n "$TOKEN" ]; then
    ENABLED_SERVICES=$(gcloud services list --project="$TF_VAR_gcp_project_id" --format="value(config.name)" 2>/dev/null)
    API_ERR=0
    for api in "compute.googleapis.com" "aiplatform.googleapis.com" "iam.googleapis.com"; do
        if [[ ! "$ENABLED_SERVICES" =~ "$api" ]]; then
            echo "❌ ERROR: $api is not enabled."
            echo "   Run: gcloud services enable $api --project=$TF_VAR_gcp_project_id"
            FAILED=1
            API_ERR=1
        fi
    done
    if [ "$API_ERR" -eq 0 ]; then
        echo "✅ All required APIs are enabled (Compute, Vertex AI, IAM)."
    fi
else
    echo "❌ ERROR: Skipping Required APIs check because GCP project, gcloud CLI, or access token is missing/invalid."
    FAILED=1
fi

# --- 2.5 REGION & ZONE TOPOLOGY CHECK ---
echo "🔍 Validating Region and Zone Topology..."
if command -v gcloud &> /dev/null && [ -n "$TF_VAR_gcp_project_id" ] && [ -n "$TOKEN" ] && [ -n "$TF_VAR_gcp_region" ]; then
    VALID_REGION=$(gcloud compute regions list --filter="name=($TF_VAR_gcp_region)" --format="value(name)" --project="$TF_VAR_gcp_project_id" 2>/dev/null)

    if [ -z "$VALID_REGION" ]; then
        echo "❌ ERROR: '$TF_VAR_gcp_region' is not a valid GCP region."
        echo "   (Hint: If you typed 'us-central1-a', that is a Zone. Drop the '-a' and just use 'us-central1')."
        FAILED=1
    else
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

# --- 2.6 STATIC IP RESERVATION CHECKS (APP & MCP VMs) ---
echo "🔍 Checking Static External IP Reservations..."
if command -v gcloud &> /dev/null && [ -n "$TF_VAR_gcp_project_id" ] && [ -n "$TOKEN" ] && [ -n "$TF_VAR_gcp_region" ]; then
    check_static_ip() {
        local VAR_NAME="$1"
        local IP_VAL="$2"
        local ROLE_LABEL="$3"

        if [ -z "$IP_VAL" ]; then
            echo "⚠️  NOTE: $VAR_NAME is not set. An ephemeral external IP will be assigned to the $ROLE_LABEL VM."
            return
        fi

        local ADDR_INFO
        ADDR_INFO=$(gcloud compute addresses list \
            --project="$TF_VAR_gcp_project_id" \
            --regions="$TF_VAR_gcp_region" \
            --filter="address=($IP_VAL)" \
            --format="value(name,status)" 2>/dev/null)

        if [ -z "$ADDR_INFO" ]; then
            echo "❌ ERROR: $VAR_NAME ($IP_VAL) is not a reserved regional static IP in '$TF_VAR_gcp_region'."
            echo "   Reserve it with: gcloud compute addresses create t-airs-${ROLE_LABEL}-ip --project=$TF_VAR_gcp_project_id --region=$TF_VAR_gcp_region"
            FAILED=1
        else
            local ADDR_NAME ADDR_STATUS
            ADDR_NAME=$(echo "$ADDR_INFO" | awk '{print $1}')
            ADDR_STATUS=$(echo "$ADDR_INFO" | awk '{print $2}')
            if [ "$ADDR_STATUS" = "RESERVED" ]; then
                echo "✅ $ROLE_LABEL Static IP ($IP_VAL / $ADDR_NAME) is RESERVED and ready."
            else
                echo "⚠️  WARNING: $ROLE_LABEL Static IP ($IP_VAL / $ADDR_NAME) currently has status '$ADDR_STATUS' (expected 'RESERVED' unless updating an existing VM)."
            fi
        fi
    }

    check_static_ip "TF_VAR_static_ip" "$TF_VAR_static_ip" "app"
    check_static_ip "TF_VAR_mcp_static_ip" "$TF_VAR_mcp_static_ip" "mcp"
fi

# --- 2.7 MCP AUTH TOKEN CHECK ---
if [ -z "$TF_VAR_mcp_auth_token" ]; then
    echo "⚠️  NOTE: TF_VAR_mcp_auth_token is not set. Terraform will auto-generate a random 32-char Bearer token."
else
    if [[ "$TF_VAR_mcp_auth_token" =~ [[:space:]%] ]]; then
        echo "❌ ERROR: TF_VAR_mcp_auth_token contains whitespace or a trailing '%' character. Clean it before deploying."
        FAILED=1
    else
        echo "✅ Custom TF_VAR_mcp_auth_token detected."
    fi
fi

# --- 3. GLOBAL VERTEX AI CONNECTIVITY & CAPABILITY CHECK ---
echo "📡 Verifying Global Vertex AI Connectivity..."
if [ -n "$TOKEN" ] && [ -n "$TF_VAR_gcp_project_id" ]; then
    MODELS_FILE="$REPO_ROOT/src/gemini_models.json"
    if ! command -v jq &> /dev/null; then
        echo "❌ ERROR: jq is not installed. It is required to parse the model list."
        FAILED=1
    elif [ ! -f "$MODELS_FILE" ]; then
        echo "❌ ERROR: Could not find $MODELS_FILE."
        FAILED=1
    else
        GEMINI_MODELS=($(jq -r '.[]' "$MODELS_FILE"))
    fi

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

# --- 4. PRISMA AIRS AI GATEWAY (LLM & MCP) CONNECTIVITY CHECK ---
GW_PROVIDER=${TF_VAR_gateway_provider:-portkey}

if [ "$GW_PROVIDER" = "portkey" ]; then
    if [ -z "$TF_VAR_portkey_api_key" ]; then
        echo "❌ ERROR: TF_VAR_portkey_api_key is not set, but gateway_provider is set to (or defaults to) 'portkey'."
        echo "   Please export your key: export TF_VAR_portkey_api_key='your_key_here'"
        echo "   Alternatively, to use LiteLLM, export TF_VAR_gateway_provider='litellm'"
        FAILED=1
    else
        if [ -z "$TF_VAR_portkey_slug" ]; then
            echo "⚠️  WARNING: TF_VAR_portkey_slug is not set. Ensure your AI Gateway policy allows inline provider routing."
        fi

        echo "📡 Verifying Prisma AIRS AI Gateway (LLM) Connectivity..."
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
            print('✅ Prisma AIRS AI Gateway (LLM) connectivity and API key verified.')
            sys.exit(0)
except urllib.error.HTTPError as e:
    print(f'❌ AI Gateway LLM API Error ({e.code}): {e.read().decode(\"utf-8\")}')
    sys.exit(1)
except Exception as e:
    print(f'❌ Network Error: {e}')
    sys.exit(1)
"
        if [ $? -ne 0 ]; then
            FAILED=1
        fi

        MCP_SLUG=${TF_VAR_portkey_mcp_slug:-t-airs-sqlite}
        MCP_GW_URL=${TF_VAR_mcp_gateway_url:-"https://mcp-aigw.portkey.ai/${MCP_SLUG}/mcp"}
        echo "📡 Probing Prisma AIRS AI Gateway (MCP: $MCP_GW_URL)..."
        MCP_HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 \
            -X POST "$MCP_GW_URL" \
            -H "Authorization: Bearer $TF_VAR_portkey_api_key" \
            -H "x-portkey-api-key: $TF_VAR_portkey_api_key" \
            -H "Content-Type: application/json" \
            -H "Accept: application/json, text/event-stream" \
            -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"preflight","version":"1.0"}}}')

        if [ "$MCP_HTTP_CODE" -eq 200 ]; then
            echo "✅ Prisma AIRS AI Gateway MCP route ($MCP_SLUG) is ACTIVE and reachable."
        elif [ "$MCP_HTTP_CODE" -eq 401 ] || [ "$MCP_HTTP_CODE" -eq 403 ]; then
            echo "❌ ERROR: AI Gateway rejected MCP access ($MCP_HTTP_CODE). Check workspace scope & MCP Invoke permissions on TF_VAR_portkey_api_key."
            FAILED=1
        elif [ "$MCP_HTTP_CODE" -eq 404 ]; then
            echo "⚠️  NOTE: MCP slug '$MCP_SLUG' returned 404 (register it in AI Gateway -> MCP Registry once the MCP VM boots)."
        else
            echo "⚠️  NOTE: MCP Gateway probe returned HTTP $MCP_HTTP_CODE (normal if the MCP VM is not provisioned yet)."
        fi
    fi
fi

# --- 5. FIREWALL ALLOWLIST CHECK ---
if [ -z "$TF_VAR_prisma_airs_ips" ]; then
    echo "⚠️  NOTE: TF_VAR_prisma_airs_ips is not set. Terraform will use default Prisma AIRS IP ranges."
else
    echo "✅ Dynamic AIRS IPs detected: $TF_VAR_prisma_airs_ips"
fi

if [ "$FAILED" -eq 1 ]; then
    echo "❌ GCP Pre-flight FAILED! One or more validation checks have failed. Please review the output above."
    exit 1
else
    echo "✅ GCP Pre-flight passed! Ready to deploy."
fi