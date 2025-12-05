#!/bin/bash
set -e

echo "🛡️  Starting MailShield Backend Deployment..."

# --- 1. Prepare Build Area ---
echo "📦 Preparing build directory..."
rm -rf dist
mkdir -p dist/lambdas
mkdir -p dist/config_defaults

# --- 2. Bundle Configs ---
echo "📂 Bundling default configurations..."
cp -r config_defaults/* dist/config_defaults/

# --- 3. Bundle Code ---
echo "🐍 Bundling Python Logic..."
cp -r lambdas/* dist/lambdas/
echo "📚 Installing dependencies..."
pip install -r lambdas/requirements.txt -t dist/lambdas/ --quiet

# --- 4. Install CDK ---
echo "🛠️  Installing AWS CDK..."
cd infra
npm install --quiet

# --- 5. Deploy ---
echo "🚀 Deploying to AWS..."
npx cdk bootstrap
npx cdk deploy --require-approval never

# --- 6. Fetch CloudFormation Outputs Dynamically ---
echo ""
echo "✅ DEPLOYMENT COMPLETE!"
echo "---------------------------------------------------"
echo "👇 COPY THIS INTO YOUR FRONTEND .env FILE 👇"
echo "---------------------------------------------------"

STACK_NAME="MailShieldStack"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-2}}"

# Helper function to fetch a specific output key
get_cfn_output() {
    aws cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --region "$REGION" \
        --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" \
        --output text
}

# Fetch Outputs
DECISIONS_BUCKET=$(get_cfn_output "DecisionsBucketName")
HITL_TABLE=$(get_cfn_output "HitlTableName")
FEEDBACK_TABLE=$(get_cfn_output "FeedbackTableName")
CONTROLLER_FN=$(get_cfn_output "ControllerName")
FEEDBACK_AGENT_FN=$(get_cfn_output "FeedbackAgentName")
API_BASE_URL=$(get_cfn_output "ApiUrl")

# Build the endpoint URL
LAMBDA_ENDPOINT="${API_BASE_URL}analyze"

echo "# AWS Credentials"
echo "# You must replace these two lines with the keys created in the AWS Console"
echo "AWS_REGION=$REGION"
echo "AWS_ACCESS_KEY_ID=YOUR_ACCESS_KEY_HERE"
echo "AWS_SECRET_ACCESS_KEY=YOUR_SECRET_ACCESS_KEY_HERE"
echo ""
echo "# S3 Configuration"
echo "S3_DECISIONS_BUCKET=$DECISIONS_BUCKET"
echo "S3_DECISIONS_PREFIX=runs"
echo ""
echo "# DynamoDB Tables"
echo "HITL_TABLE=$HITL_TABLE"
echo "FEEDBACK_TABLE=$FEEDBACK_TABLE"
echo ""
echo "# Lambda Functions"
echo "SENDER_INTEL_CONTROLLER_FUNCTION=$CONTROLLER_FN"
echo "FEEDBACK_AGENT_FN=$FEEDBACK_AGENT_FN"
echo ""
echo "# API Gateway Endpoint"
echo "AWS_LAMBDA_ENDPOINT=$LAMBDA_ENDPOINT"
echo "---------------------------------------------------"
