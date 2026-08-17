#!/bin/bash

echo "🛫 Starting Pre-Flight Checks for AWS..."

FAILED=0

# --- 1. GLOBAL CHECKS ---
if ! command -v terraform &> /dev/null; then
    echo "❌ ERROR: Terraform is not installed."
    FAILED=1
fi

if [ -z "$TF_VAR_airs_key" ]; then
    echo "❌ ERROR: TF_VAR_airs_key is not set."
    echo "   Run: export TF_VAR_airs_key='your_prisma_key_here'"
    FAILED=1
fi

if [ -z "$TF_VAR_airs_profile" ]; then
    echo "❌ ERROR: TF_VAR_airs_profile is not set."
    echo "   Run: export TF_VAR_airs_profile='strict_red_team_profile'"
    FAILED=1
fi

# --- 2. AWS CHECKS ---
if [ -z "$TF_VAR_aws_region" ]; then
    echo "❌ ERROR: Missing AWS environment variables."
    echo "   Run: export TF_VAR_aws_region='us-east-1'"
    FAILED=1
fi

if ! command -v aws &> /dev/null; then
    echo "❌ ERROR: AWS CLI is not installed."
    FAILED=1
fi

echo "🔍 Checking AWS Authentication..."
if command -v aws &> /dev/null; then
    if ! aws sts get-caller-identity &> /dev/null; then
        echo "❌ ERROR: Not logged into AWS. Check your AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY."
        FAILED=1
    else
        echo "✅ AWS Authentication successful."
    fi
else
    echo "❌ ERROR: Cannot check AWS Authentication because AWS CLI is not installed."
    FAILED=1
fi

if cd terraform/aws 2>/dev/null; then
    if command -v terraform &> /dev/null; then
        terraform init > /dev/null
        echo "✅ Terraform workspace initialized successfully."

        # 1. Get the list of models from Terraform as a JSON string
        echo "🔍 Resolving Bedrock Model IDs from Terraform..."
        MODEL_IDS_JSON=$(echo 'jsonencode(var.bedrock_model_ids)' | terraform console 2>/dev/null | grep '\[.*\]' || echo "")

        if [ -z "$MODEL_IDS_JSON" ] || [[ "$MODEL_IDS_JSON" == "null" ]]; then
            echo "❌ ERROR: Could not resolve 'bedrock_model_ids'. Ensure it is declared in variables.tf and has a default value."
            FAILED=1
        else
            # 2. Check Bedrock Model Status for each model
            ACTIVE_MODELS=0
            # Use sed to clean the JSON array into a space-separated list for the loop
            # Use tr to delete brackets and quotes, then sed to replace commas with spaces. This is more robust.
            MODEL_IDS_CLEAN=$(echo "$MODEL_IDS_JSON" | tr -d '[]"\\' | sed 's/,/ /g')

            for MODEL_ID in $MODEL_IDS_CLEAN; do
                echo "🔍 Checking AWS Bedrock Model ($MODEL_ID) Status..."
                
                # 1. First, try to query it as a standard Foundation Model
                MODEL_STATUS=$(aws bedrock get-foundation-model \
                    --model-id "$MODEL_ID" \
                    --region "$TF_VAR_aws_region" \
                    --query 'modelDetails.modelLifecycle.status' \
                    --output text 2>/dev/null)

                # 2. If it fails or is empty, try querying it as a Cross-Region Inference Profile
                if [ -z "$MODEL_STATUS" ] || [ "$MODEL_STATUS" == "None" ] || [[ "$MODEL_STATUS" == *"An error occurred"* ]]; then
                    MODEL_STATUS=$(aws bedrock get-inference-profile \
                        --inference-profile-identifier "$MODEL_ID" \
                        --region "$TF_VAR_aws_region" \
                        --query 'status' \
                        --output text 2>/dev/null)
                fi

                if [ "$MODEL_STATUS" == "ACTIVE" ]; then
                    echo "✅ Model $MODEL_ID is ACTIVE."
                    ACTIVE_MODELS=$((ACTIVE_MODELS + 1))
                else
                    echo "⚠️  WARNING: Model '$MODEL_ID' is not ACTIVE in region '$TF_VAR_aws_region'. It will be skipped."
                fi
            done

            if [ "$ACTIVE_MODELS" -eq 0 ]; then
                echo "❌ ERROR: None of the specified Bedrock models are active in region '$TF_VAR_aws_region'. Deployment cannot continue."
                FAILED=1
            fi
        fi
    else
        echo "❌ ERROR: Terraform binary is missing. Skipping Bedrock model checks."
        FAILED=1
    fi
    cd ../..
else
    echo "❌ ERROR: terraform/aws directory not found."
    FAILED=1
fi

# --- 3. PORTKEY API CONNECTIVITY CHECK ---
GW_PROVIDER=${TF_VAR_gateway_provider:-portkey}

if [ "$GW_PROVIDER" = "portkey" ]; then
    if [ -z "$TF_VAR_portkey_api_key" ]; then
        echo "❌ ERROR: TF_VAR_portkey_api_key is not set, but gateway_provider is set to (or defaults to) 'portkey'."
        echo "   Please export your key: export TF_VAR_portkey_api_key='your_key_here'"
        echo "   Alternatively, to use LiteLLM, export TF_VAR_gateway_provider='litellm'"
        FAILED=1
    else
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
fi

if [ -z "$TF_VAR_prisma_airs_ips" ]; then
    echo "⚠️  NOTE: TF_VAR_airs_ips is not set. Terraform will use the default AIRS IPs for model scaning inbound connection."
else
    echo "✅ Dynamic AIRS IPs detected: $TF_VAR_prisma_airs_ips"
fi

if [ "$FAILED" -eq 1 ]; then
    echo "❌ AWS Pre-flight FAILED! One or more validation checks have failed. Please review the output above."
    exit 1
else
    echo "✅ AWS Pre-flight passed! Found $ACTIVE_MODELS active models. Ready to deploy."
fi