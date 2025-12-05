import * as path from 'path';
import { Stack, StackProps, RemovalPolicy, Duration, CfnOutput } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as s3deploy from 'aws-cdk-lib/aws-s3-deployment';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as apigw from 'aws-cdk-lib/aws-apigateway';
import * as iam from 'aws-cdk-lib/aws-iam';

export class MailShieldStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    // --- 1. STORAGE ---
    const decisionsBucket = new s3.Bucket(this, 'DecisionsBucket', {
      removalPolicy: RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });

    const configBucket = new s3.Bucket(this, 'ConfigBucket', {
      removalPolicy: RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });

    new s3deploy.BucketDeployment(this, 'DeployConfigs', {
      sources: [s3deploy.Source.asset(path.join(__dirname, '../../dist/config_defaults'))],
      destinationBucket: configBucket,
      destinationKeyPrefix: 'org' 
    });

    const hitlQueueTable = new dynamodb.Table(this, 'HitlQueueTable', {
      tableName: 'sender_intel_hitl_queue',
      partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    const feedbackTable = new dynamodb.Table(this, 'FeedbackTable', {
      tableName: 'sender_feedback_table',
      partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'sk', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    const domainCacheTable = new dynamodb.Table(this, 'DomainCacheTable', {
      tableName: 'sc_domain_cache',
      partitionKey: { name: 'domain', type: dynamodb.AttributeType.STRING },
      timeToLiveAttribute: 'ttl',
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    const ipCacheTable = new dynamodb.Table(this, 'IpCacheTable', {
      tableName: 'sc_ip_cache',
      partitionKey: { name: 'ip', type: dynamodb.AttributeType.STRING },
      timeToLiveAttribute: 'ttl',
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    const senderGraphTable = new dynamodb.Table(this, 'SenderGraphTable', {
      tableName: 'sc_sender_graph',
      partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'sk', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // --- 2. LAMBDAS ---
    const codeAsset = lambda.Code.fromAsset(path.join(__dirname, '../../dist/lambdas'));
    const commonEnv = {
      AWS_NODEJS_CONNECTION_REUSE_ENABLED: '1',
      DECISIONS_BUCKET: decisionsBucket.bucketName,
      HITL_TABLE: hitlQueueTable.tableName,
      FEEDBACK_TABLE: feedbackTable.tableName,
      BEDROCK_MODEL_ID: 'us.amazon.nova-pro-v1:0',
    };

    const mimeExtractFn = new lambda.Function(this, 'MimeExtract', {
      code: codeAsset,
      handler: 'mime_extract_lambda.handler',
      runtime: lambda.Runtime.PYTHON_3_12,
      memorySize: 512,
      timeout: Duration.seconds(30),
    });

    const phiScrubberFn = new lambda.Function(this, 'PhiScrubber', {
      code: codeAsset,
      handler: 'phi_scrubber_lambda.lambda_handler',
      runtime: lambda.Runtime.PYTHON_3_12,
      memorySize: 128,
      timeout: Duration.seconds(30),
    });
    phiScrubberFn.addToRolePolicy(new iam.PolicyStatement({
      actions: ['comprehendmedical:DetectPHI'],
      resources: ['*'],
    }));

    const contextAnalyzerFn = new lambda.Function(this, 'ContextAnalyzer', {
      code: codeAsset,
      handler: 'context_analyzer_lambda.lambda_handler',
      runtime: lambda.Runtime.PYTHON_3_12,
      memorySize: 128,
      timeout: Duration.seconds(10),
    });

    const scIntelFn = new lambda.Function(this, 'ScIntel', {
      code: codeAsset,
      handler: 'intel_lambda.handler',
      runtime: lambda.Runtime.PYTHON_3_12,
      memorySize: 1024,
      timeout: Duration.seconds(25),
      environment: {
        ...commonEnv,
        CFG_BUCKET: configBucket.bucketName,
        DDB_DOM: domainCacheTable.tableName,
        DDB_IP: ipCacheTable.tableName,
        DDB_GRAPH: senderGraphTable.tableName,
        WL_KEY: 'org/whitelist.json',
        ACC_KEY: 'org/account_status.json',
        ORG_ENTITIES_KEY: 'org/smileclinic_entities.json',
        BRAND_BASES_KEY: 'org/brand_bases.json',
        OSINT_BUDGET_S: '1.5'
      },
    });
    domainCacheTable.grantReadWriteData(scIntelFn);
    ipCacheTable.grantReadWriteData(scIntelFn);
    senderGraphTable.grantReadWriteData(scIntelFn);
    configBucket.grantRead(scIntelFn);

    const decisionAgentFn = new lambda.Function(this, 'DecisionAgent', {
      code: codeAsset,
      handler: 'decision_agent_lambda.lambda_handler',
      runtime: lambda.Runtime.PYTHON_3_12,
      memorySize: 128,
      timeout: Duration.seconds(10),
      environment: commonEnv,
    });
    decisionAgentFn.addToRolePolicy(new iam.PolicyStatement({
      actions: ['bedrock:InvokeModel'],
      resources: ['*'],
    }));

    const feedbackAgentFn = new lambda.Function(this, 'FeedbackAgent', {
      code: codeAsset,
      handler: 'lambda_function.lambda_handler',
      runtime: lambda.Runtime.PYTHON_3_12,
      memorySize: 128,
      timeout: Duration.seconds(60),
      environment: commonEnv,
    });
    hitlQueueTable.grantReadData(feedbackAgentFn);
    feedbackTable.grantReadData(feedbackAgentFn);
    decisionsBucket.grantRead(feedbackAgentFn);
    feedbackAgentFn.addToRolePolicy(new iam.PolicyStatement({
      actions: ['bedrock:InvokeModel'],
      resources: ['*'],
    }));

    // --- 3. CONTROLLER ---
    const controllerFn = new lambda.Function(this, 'Controller', {
      code: codeAsset,
      handler: 'sender_intel_controller.handler',
      runtime: lambda.Runtime.PYTHON_3_12,
      memorySize: 256,
      timeout: Duration.seconds(20),
      environment: {
        ...commonEnv,
        DECISIONS_PREFIX: 'runs',
        MIME_FN: mimeExtractFn.functionName,
        PHI_FN: phiScrubberFn.functionName,
        CONTEXT_FN: contextAnalyzerFn.functionName,
        INTEL_FN: scIntelFn.functionName,
        DECISION_FN: decisionAgentFn.functionName,
      },
    });

    // Grant Permissions
    mimeExtractFn.grantInvoke(controllerFn);
    phiScrubberFn.grantInvoke(controllerFn);
    contextAnalyzerFn.grantInvoke(controllerFn);
    scIntelFn.grantInvoke(controllerFn);
    decisionAgentFn.grantInvoke(controllerFn);
    decisionsBucket.grantReadWrite(controllerFn);
    hitlQueueTable.grantReadWriteData(controllerFn);
    feedbackTable.grantReadData(controllerFn);
    
    controllerFn.addToRolePolicy(new iam.PolicyStatement({
      actions: ['cloudwatch:PutMetricData'],
      resources: ['*'],
      conditions: { StringEquals: { 'cloudwatch:namespace': 'SCIntel' } },
    }));

    controllerFn.addPermission('AllowSESInvocation', {
      principal: new iam.ServicePrincipal('ses.amazonaws.com'),
      action: 'lambda:InvokeFunction',
    });

    // --- 4. API GATEWAY ---
    const api = new apigw.RestApi(this, 'MailShieldApi', {
      restApiName: 'MailShield Core',
    });
    const analyzeIntegration = new apigw.LambdaIntegration(controllerFn);
    api.root.addResource('analyze').addMethod('POST', analyzeIntegration);

    // --- 5. OUTPUTS (Corrected to avoid conflicts) ---
    new CfnOutput(this, 'ApiUrl', { value: api.url });
    new CfnOutput(this, 'ControllerName', { value: controllerFn.functionName });
    // Renamed these to avoid collision with Resource Names
    new CfnOutput(this, 'DecisionsBucketName', { value: decisionsBucket.bucketName });
    new CfnOutput(this, 'HitlTableName', { value: hitlQueueTable.tableName });
    new CfnOutput(this, 'FeedbackTableName', { value: feedbackTable.tableName });
    new CfnOutput(this, 'FeedbackAgentName', { value: feedbackAgentFn.functionName });
  }
}