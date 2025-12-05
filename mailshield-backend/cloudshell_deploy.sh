#!/bin/bash
set -e

echo "🛡️  Starting MailShield Backend Deployment..."

# 1. Prepare Build Area
echo "📦 Preparing build directory..."
rm -rf dist
mkdir -p dist/lambdas
mkdir -p dist/config_defaults

# 2. Bundle Configs
echo "📂 Bundling default configurations..."
cp -r config_defaults/* dist/config_defaults/

# 3. Bundle Code
echo "🐍 Bundling Python Logic..."
cp -r lambdas/* dist/lambdas/
echo "📚 Installing dependencies..."
pip install -r lambdas/requirements.txt -t dist/lambdas/ --quiet

# 4. Install CDK
echo "🛠️  Installing AWS CDK..."
cd infra
npm install --quiet

# 5. Deploy
echo "🚀 Deploying to AWS..."
npx cdk bootstrap
npx cdk deploy --require-approval never

# 6. Generate .env Output
echo ""
echo "✅ DEPLOYMENT COMPLETE!"
echo "---------------------------------------------------"
echo "👇 COPY THIS INTO YOUR FRONTEND .env FILE 👇"
echo "---------------------------------------------------"

# Fetch outputs using AWS CLI
STACK_NAME="MailShieldStack"
REGION=$(aws configure get region)
DECISIONS_BUCKET=$(aws cloudformation describe-stacks --stack-name $STACK_NAME --query "Stacks[0].Outputs[?OutputKey=='DecisionsBucket'].OutputValue" --output text)
HITL_TABLE=$(aws cloudformation describe-stacks --stack-name $STACK_NAME --query "Stacks[0].Outputs[?OutputKey=='HitlTable'].OutputValue" --output text)
FEEDBACK_TABLE=$(aws cloudformation describe-stacks --stack-name $STACK_NAME --query "Stacks[0].Outputs[?OutputKey=='FeedbackTable'].OutputValue" --output text)
CONTROLLER_FN=$(aws cloudformation describe-stacks --stack-name $STACK_NAME --query "Stacks[0].Outputs[?OutputKey=='ControllerName'].OutputValue" --output text)
FEEDBACK_AGENT_FN=$(aws cloudformation describe-stacks --stack-name $STACK_NAME --query "Stacks[0].Outputs[?OutputKey=='FeedbackAgentName'].OutputValue" --output text)
API_BASE_URL=$(aws cloudformation describe-stacks --stack-name $STACK_NAME --query "Stacks[0].Outputs[?OutputKey=='ApiUrl'].OutputValue" --output text)

# Construct the full endpoint URL for the simple analyzer
# Note: CDK output usually includes the trailing slash, e.g., ".../prod/"
LAMBDA_ENDPOINT="${API_BASE_URL}analyze"

echo "# AWS Credentials"
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
echo "AWS_LAMBDA_ENDPOINT=$LAMBDA_ENDPOINT"
echo "---------------------------------------------------"