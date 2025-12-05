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

# 1. Ensure Config is Valid (Critical Fix for CloudShell)
# We overwrite cdk.json to ensure no legacy feature flags crash the destroy process
echo "🔧 Ensuring valid CDK configuration..."
cat <<EOF > infra/cdk.json
{
  "app": "npx ts-node --prefer-ts-exts bin/infra.ts",
  "watch": {
    "include": ["**"],
    "exclude": ["README.md", "cdk*.json", "**/*.d.ts", "**/*.js", "tsconfig.json", "package*.json", "yarn.lock", "node_modules", "test"]
  },
  "context": {
    "@aws-cdk/aws-lambda:recognizeLayerVersion": true,
    "@aws-cdk/core:checkSecretUsage": true,
    "@aws-cdk/core:target-partitions": ["aws", "aws-cn"],
    "@aws-cdk/aws-ec2:uniqueImdsv2TemplateName": true,
    "@aws-cdk/aws-ecs:arnFormatIncludesClusterName": true,
    "@aws-cdk/aws-iam:minimizePolicies": true,
    "@aws-cdk/core:validateSnapshotRemovalPolicy": true,
    "@aws-cdk/aws-codepipeline:crossAccountKeyAliasStackSafeResourceName": true,
    "@aws-cdk/aws-s3:createDefaultLoggingPolicy": true,
    "@aws-cdk/aws-sns-subscriptions:restrictSqsDescryption": true,
    "@aws-cdk/aws-apigateway:disableCloudWatchRole": true,
    "@aws-cdk/aws-ecr-assets:dockerIgnoreSupport": true,
    "@aws-cdk/aws-secretsmanager:parseOwnedSecretName": true,
    "@aws-cdk/aws-kms:defaultKeyPolicies": true,
    "@aws-cdk/aws-ecs-patterns:removeDefaultDesiredCount": true,
    "@aws-cdk/aws-rds:databaseProxyUniqueResourceName": true,
    "@aws-cdk/aws-codebuild:secretsManagerPlainTextEnv": true,
    "@aws-cdk/aws-lambda:recognizeVersionProps": true
  }
}
EOF

# 2. Install Dependencies (In case of a fresh clone)
echo "📦 Preparing CDK environment..."
cd infra
npm install --quiet

# 3. Run CDK Destroy
echo "🗑️  Destroying Cloud Stack..."
# --force skips confirmation prompts
npx cdk destroy --force --require-approval never

# 4. Clean up local artifacts
cd ..
echo "🧹 Cleaning up local build files..."
rm -rf dist

echo "✅ SUCCESS! System completely removed."