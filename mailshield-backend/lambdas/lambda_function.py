import json
import boto3
import os
import traceback

# --- CONFIGURATION ---
HITL_TABLE = os.environ.get("HITL_TABLE", "sender_intel_hitl_queue")
FEEDBACK_TABLE = os.environ.get("FEEDBACK_TABLE", "sender_feedback_table")
BEDROCK_MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "us.amazon.nova-pro-v1:0")

dynamo = boto3.client("dynamodb")
bedrock = boto3.client("bedrock-runtime")
s3 = boto3.client("s3")

# --- KNOWLEDGE BASE: YOUR CURRENT SETUP ---
# Derived from sender_intel_controller.py and decision_agent_lambda.py
CURRENT_SYSTEM_CAPABILITIES = """
1. EMAIL AUTHENTICATION:
   - We already check SPF, DKIM, and DMARC.
   - We flag emails if DMARC is missing or failing.

2. DOMAIN INTELLIGENCE:
   - Typosquatting: We calculate Levenshtein distance against known domains.
   - Domain Age: We check RDAP for "newly registered domains".
   - Vendor List: We check a hardcoded list of known vendors (e.g., 'ADP', 'Cisco').

3. CONTENT ANALYSIS (AI):
   - We detect PHI (Personal Health Info) entities.
   - We detect "Urgency" and "Credential Request" intent.
   - We perform Sentiment Analysis (Tone).

4. DECISION LOGIC:
   - High Risk Rule: If Risk Score > 80, we BLOCK.
   - PHI Safety Net: If PHI is detected AND Confidence < 70%, we force HITL Review.
"""

def get_full_decision_context(bucket, key):
    if not bucket or not key:
        return None
    try:
        obj = s3.get_object(Bucket=bucket, Key=key)
        doc = json.loads(obj['Body'].read().decode('utf-8'))
        return {
            "ai_decision": doc.get("decision", "UNKNOWN"),
            "ai_confidence": doc.get("summary", {}).get("confidence", 0),
            "ai_risk_score": doc.get("summary", {}).get("sender_risk", 0),
            "ai_reasoning": doc.get("decision_reasons", []),
            "detected_signals": doc.get("decision_agent", {}).get("signals", {}),
            "subject_line": doc.get("compact", {}).get("subject", ""),
            "from_address": doc.get("compact", {}).get("from", {}).get("addr", "")
        }
    except Exception as e:
        print(f"❌ Failed to fetch S3 context for {key}: {str(e)}")
        return None

def analyze_feedback_patterns():
    patterns = []
    print(f"🔍 DEBUG: Scanning HITL Table: '{HITL_TABLE}'")
    
    # 1. Scan HITL Queue
    try:
        resp = dynamo.scan(
            TableName=HITL_TABLE,
            FilterExpression="#s = :r",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":r": {"S": "resolved"}}
        )
        for item in resp.get("Items", []):
            notes = item.get("notes", {}).get("S", "").strip()
            if not notes: continue

            log_bucket = item.get("log_bucket", {}).get("S", "")
            log_key = item.get("log_key", {}).get("S", "")
            context = get_full_decision_context(log_bucket, log_key)

            patterns.append({
                "source": "hitl_queue",
                "domain": item.get("from_domain", {}).get("S", "unknown"),
                "verdict": item.get("verdict", {}).get("S", ""),
                "user_notes": notes, 
                "system_context": context 
            })
    except Exception as e:
        print(f"❌ ERROR scanning HITL table: {str(e)}")

    # 2. Scan Feedback Table
    try:
        resp = dynamo.scan(TableName=FEEDBACK_TABLE)
        for item in resp.get("Items", []):
            notes = item.get("notes", {}).get("S", "").strip()
            if not notes: continue

            log_bucket = item.get("log_bucket", {}).get("S", "")
            log_key = item.get("log_key", {}).get("S", "")
            context = get_full_decision_context(log_bucket, log_key)
            
            patterns.append({
                "source": "feedback_table",
                "domain": item.get("from_domain", {}).get("S", "unknown"),
                "verdict": item.get("verdict", {}).get("S", ""),
                "user_notes": notes,
                "system_context": context
            })
    except Exception as e:
        print(f"❌ ERROR scanning Feedback table: {str(e)}")

    return patterns

def ask_bedrock_advisor(analysis_data, current_policy):
    if not analysis_data.get("patterns"):
        return ["No written feedback found. Please review emails and add notes to generate insights."]

    print(f"🤖 Sending {len(analysis_data['patterns'])} patterns to Nova Pro ({BEDROCK_MODEL_ID})...")

    prompt = f"""
    You are an expert Security Operations Center (SOC) Policy Architect.
    Your goal is to tune our email security engine by reconciling the difference between the AI's automated assessment and the Human's manual override.

    --- CURRENT SYSTEM CAPABILITIES (DO NOT RECOMMEND IMPLEMENTING THESE) ---
    {CURRENT_SYSTEM_CAPABILITIES}
    ------------------------------------------------------------------------

    INPUT DATA:
    Here are instances where a Human intervened and explicitly disagreed with the System:
    {json.dumps(analysis_data['patterns'], indent=2)}

    INSTRUCTIONS:
    1. Analyze the Conflict: Compare 'system_context' vs 'user_notes'.
    2. Check Capabilities: Look at CURRENT SYSTEM CAPABILITIES. 
       - If the user notes mention "spoofing" and we already check DMARC, do NOT say "Implement DMARC". Instead, say "Review DMARC enforcement policy" or "Investigate why DMARC passed for this spoofer."
       - If the user notes mention "New Domain" and we already check Domain Age, recommend "Increase the Risk Score penalty for domains < 30 days old."
    3. Generate Recommendations:
       - NAMED ENTITIES: Whitelist specific vendors mentioned in notes (e.g., "Whitelist 'Dentrix'").
       - THRESHOLD TUNING: Suggest adjusting specific weights (e.g., "Increase 'Urgency' signal weight" or "Lower 'PHI' confidence threshold").
       - MISSING LOGIC: Only recommend NEW features if they are strictly absent from the Capabilities list (e.g., "Implement OCR for image-based spam" if not listed).

    OUTPUT FORMAT:
    Output ONLY a JSON object:
    {{
      "recommendations": [
        "Specific, context-aware recommendation 1",
        "Specific, context-aware recommendation 2"
      ],
      "reasoning": "Technical root cause analysis referencing the gap between Current Capabilities and the Human's feedback."
    }}
    """

    body = json.dumps({
        "messages": [
            {
                "role": "user", 
                "content": [{"text": prompt}]
            }
        ],
        "inferenceConfig": {
            "max_new_tokens": 1000,
            "temperature": 0.1 
        }
    })

    try:
        response = bedrock.invoke_model(
            modelId=BEDROCK_MODEL_ID,
            body=body
        )
        
        resp_body = json.loads(response['body'].read())
        content = resp_body['output']['message']['content'][0]['text']
        content = content.replace("```json", "").replace("```", "").strip()
        
        return json.loads(content)
        
    except Exception as e:
        print(f"❌ Nova invocation failed: {str(e)}")
        traceback.print_exc()
        return {
            "recommendations": ["Error generating AI insights."],
            "reasoning": str(e)
        }

def lambda_handler(event, context):
    print("🚀 Feedback Agent started (Context-Aware)...")
    
    patterns = analyze_feedback_patterns()
    print(f"📊 Found {len(patterns)} qualified feedback items.")
    
    analysis_data = {"patterns": patterns}
    result = ask_bedrock_advisor(analysis_data, "standard_policy")
    
    return {
        "statusCode": 200,
        "body": json.dumps(result)
    }