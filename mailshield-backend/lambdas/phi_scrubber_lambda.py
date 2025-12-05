import json, os, logging
import boto3
from botocore.exceptions import BotoCoreError, ClientError

log = logging.getLogger()
log.setLevel(logging.INFO)

CM_REGION = os.getenv("CM_REGION", "us-east-1")

# Try to create Comprehend Medical client once at import
try:
    cm_client = boto3.client("comprehendmedical", region_name=CM_REGION)
except Exception as e:
    log.exception("Failed to create Comprehend Medical client")
    cm_client = None


def scrub_text(text: str) -> dict:
    """
    Core helper: call Comprehend Medical if available, otherwise
    just echo the text and flag an error.
    """
    if not text:
        return {
            "redacted_email": "",
            "entities_detected": 0,
            "model_version": None,
        }

    if cm_client is None:
        return {
            "redacted_email": text,
            "entities_detected": -1,
            "model_version": None,
            "error": "Comprehend Medical client not available",
        }

    try:
        result = cm_client.detect_phi(Text=text)
        entities = result.get("Entities", [])

        # Redact in reverse offset order so positions stay valid
        redacted = text
        for ent in sorted(entities, key=lambda e: e["BeginOffset"], reverse=True):
            start, end = ent["BeginOffset"], ent["EndOffset"]
            redacted = redacted[:start] + "[REDACTED]" + redacted[end:]

        return {
            "redacted_email": redacted,
            "entities_detected": len(entities),
            "model_version": result.get("ModelVersion"),
        }
    except (BotoCoreError, ClientError, Exception) as e:
        log.exception("detect_phi failed")
        return {
            "redacted_email": text,
            "entities_detected": -1,
            "model_version": None,
            "error": str(e),
        }


def lambda_handler(event, context):
    """
    Bedrock-style action Lambda.

    Expects:
      {
        "actionGroup": "phi_scrubber",
        "function": "scrub_phi",
        "parameters": [{ "name": "email_body", "value": "<text>" }],
        "messageVersion": "1.0"
      }
    """
    try:
        params = event.get("parameters") or []
        text = ""
        for p in params:
            if p.get("name") == "email_body":
                text = p.get("value") or ""
                break

        if not text:
            raise ValueError("Missing 'email_body' parameter")

        payload = scrub_text(text)

        return {
            "response": {
                "actionGroup": event.get("actionGroup", "phi_scrubber"),
                "function": event.get("function", "scrub_phi"),
                "functionResponse": {
                    "responseBody": {
                        "TEXT": {"body": json.dumps(payload, ensure_ascii=False)}
                    }
                },
            },
            "messageVersion": event.get("messageVersion", "1.0"),
        }

    except Exception as e:
        log.exception("Unhandled error in phi_scrubber_lambda")
        payload = {"error": str(e)}
        return {
            "response": {
                "actionGroup": event.get("actionGroup", "phi_scrubber"),
                "function": event.get("function", "scrub_phi"),
                "functionResponse": {
                    "responseBody": {
                        "TEXT": {"body": json.dumps(payload, ensure_ascii=False)}
                    }
                },
            },
            "messageVersion": event.get("messageVersion", "1.0"),
        }
