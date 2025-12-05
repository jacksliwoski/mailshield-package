#!/bin/bash
set -e

echo "🔥 STARTING SYSTEM REMOVAL (MailShield) 🔥"
echo "This will permanently delete:"
echo " - All S3 Buckets (Decisions, Logs, Configs)"
echo " - All DynamoDB Tables (Queue, Feedback, Caches)"
echo " - All Lambda Functions & APIs"
echo " - All IAM Roles created by this stack"
echo ""
read -p "Are you sure you want to proceed? (type 'yes' to confirm): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
  echo "❌ Cancellation received. Exiting."
  exit 1
fi

# 1. Install Dependencies (Just in case the session restarted)
# We need CDK to perform the destroy operation
if [ ! -d "infra/node_modules" ]; then
    echo "📦 Installing necessary tools..."
    cd infra
    npm install --quiet
    cd ..
fi

# 2. Run CDK Destroy
echo "🗑️  Destroying Cloud Stack..."
cd infra
# --force skips the "Are you sure?" prompt from CDK itself since we asked above
npx cdk destroy --force

echo "✅ SUCCESS! System completely removed."