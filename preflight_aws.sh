#!/bin/bash

echo "🛫 Starting Pre-Flight Checks for AWS..."

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

# --- 2. AWS CHECKS ---
if [ -z "$TF_VAR_aws_region" ]; then
    echo "❌ ERROR: Missing AWS environment variables."
    echo "   Run: export TF_VAR_aws_region='us-east-1'"
    exit 1
fi

if ! command -v aws &> /dev/null; then
    echo "❌ ERROR: AWS CLI is not installed."
    exit 1
fi

echo "🔍 Checking AWS Authentication..."
if ! aws sts get-caller-identity &> /dev/null; then
    echo "❌ ERROR: Not logged into AWS. Check your AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY."
    exit 1
fi


cd terraform/aws || { echo "❌ ERROR: terraform/aws directory not found."; exit 1; }
terraform init > /dev/null

# 1. Ask Terraform for the current value
echo "🔍 Resolving Bedrock Model ID from Terraform..."
MODEL_ID=$(echo "var.bedrock_model_id" | terraform console | tr -d '"')

if [ -z "$MODEL_ID" ] || [[ "$MODEL_ID" == *"Error"* ]]; then
    echo "❌ ERROR: Could not resolve 'bedrock_model_id'. Ensure it is declared in variables.tf"
    exit 1
fi

# 2. Check Bedrock Model Status
echo "🔍 Checking AWS Bedrock Model ($MODEL_ID) Status..."
MODEL_STATUS=$(aws bedrock get-foundation-model \
    --model-id "$MODEL_ID" \
    --region "$TF_VAR_aws_region" \
    --query 'modelDetails.modelLifecycle.status' \
    --output text 2>/dev/null)

if [ "$MODEL_STATUS" == "ACTIVE" ]; then
    echo "✅ AWS Bedrock is ACTIVE and ready."
else
    # Use $TF_VAR_aws_region here for the error message
    echo "❌ ERROR: Model $MODEL_ID is not available or ACTIVE in $TF_VAR_aws_region."
    echo "Check if you have requested access in the Bedrock Console."
    exit 1
fi

if [ -z "$TF_VAR_prisma_airs_ips" ]; then
    echo "⚠️  NOTE: TF_VAR_airs_ips is not set. Terraform will use the default AIRS IPs for model scaning inbound connection."
else
    echo "✅ Dynamic AIRS IPs detected: $TF_VAR_prisma_airs_ips"
fi

echo "✅ AWS Pre-flight passed! Ready to deploy."