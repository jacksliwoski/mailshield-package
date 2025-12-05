import os
import json
import boto3
import base64
import logging
import time
import uuid
import datetime
from email import policy
from email.parser import BytesParser

DDB = boto3.client("dynamodb")
HITL_TABLE = os.getenv("HITL_TABLE", "")
FEEDBACK_TABLE = os.getenv("FEEDBACK_TABLE", "sender_feedback_table")

log = logging.getLogger()
log.setLevel(logging.INFO)

LAMBDA = boto3.client("lambda")
S3 = boto3.client("s3")
CW = boto3.client("cloudwatch")

MIME_FN = os.environ.get("MIME_FN", "mime_extract_lambda")
INTEL_FN = os.environ.get("INTEL_FN", "sc-intel")
PHI_FN = os.environ.get("PHI_FN", "")
CONTEXT_FN = os.environ.get("CONTEXT_FN", "")
DECISION_FN = os.environ.get("DECISION_FN", "")
DECISIONS_BUCKET = os.environ.get("DECISIONS_BUCKET", "")
DECISIONS_PREFIX = os.environ.get("DECISIONS_PREFIX", "runs")
REGION = os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-2"))


def _get_mime_from_event(event):
    if isinstance(event.get("mime_raw"), str):
        return event["mime_raw"]

    if isinstance(event.get("mime_b64"), str):
        try:
            return base64.b64decode(event["mime_b64"]).decode("utf-8", "replace")
        except Exception:
            return ""

    body = event.get("body")
    if isinstance(body, str):
        if event.get("isBase64Encoded"):
            try:
                return base64.b64decode(body).decode("utf-8", "replace")
            except Exception:
                return body
        return body

    return ""


def _parse_mime_basic(mime_raw: str):
    msg = BytesParser(policy=policy.default).parsebytes(
        mime_raw.encode("utf-8", "ignore")
    )
    subj = msg.get("Subject") or ""
    msg_id = (msg.get("Message-ID") or "").strip().strip("<>") or None
    from_h = msg.get("From") or ""
    to_h = msg.get("To") or ""

    body_text = ""
    try:
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    body_text = part.get_content()
                    break
            if not body_text:
                for part in msg.walk():
                    if part.get_content_type() == "text/html":
                        body_text = part.get_content()
                        break
        else:
            body_text = msg.get_content()
    except Exception:
        body_text = ""

    return {
        "subject": str(subj),
        "body": body_text or "",
        "from_header": from_h,
        "to_header": to_h,
        "message_id": msg_id,
    }


def _invoke_lambda(fn_name: str, payload: dict):
    resp = LAMBDA.invoke(
        FunctionName=fn_name,
        Payload=json.dumps(payload).encode("utf-8"),
    )
    raw = resp["Payload"].read().decode("utf-8")
    try:
        return json.loads(raw)
    except Exception:
        log.exception("Failed to parse Lambda %s response: %s", fn_name, raw)
        return {}


def _call_decision_agent(run_doc: dict) -> dict:
    if not DECISION_FN:
        return {}

    event = {"run": run_doc}
    resp = LAMBDA.invoke(
        FunctionName=DECISION_FN,
        InvocationType="RequestResponse",
        Payload=json.dumps(event).encode("utf-8"),
    )
    payload_bytes = resp["Payload"].read()
    try:
        if not payload_bytes:
            return {}
        decoded = payload_bytes.decode("utf-8")
        return json.loads(decoded)
    except Exception:
        log.exception("Failed to decode decision agent payload")
        return {}


def _call_phi_scrubber(body_text: str):
    if not PHI_FN or not body_text:
        return {
            "redacted_email": body_text,
            "entities_detected": 0,
            "model_version": None,
        }

    event = {
        "actionGroup": "phi_scrubber",
        "function": "scrub_phi",
        "parameters": [
            {"name": "email_body", "value": body_text},
        ],
        "messageVersion": "1.0",
    }
    payload = _invoke_lambda(PHI_FN, event)

    try:
        inner = payload["response"]["functionResponse"]["responseBody"]["TEXT"]["body"]
        data = json.loads(inner)
    except Exception:
        log.exception("phi_scrubber parse error")
        data = {
            "redacted_email": body_text,
            "entities_detected": -1,
            "model_version": None,
        }

    return data


def _call_mime_extract(mime_raw: str):
    payload = _invoke_lambda(MIME_FN, {"mime_raw": mime_raw})
    try:
        body = payload["response"]["functionResponse"]["responseBody"]["TEXT"]["body"]
        data = json.loads(body)
        return data.get("compact") or {}, data.get("sender") or {}, data.get("auth") or {}
    except Exception:
        log.exception("mime_extract parse error")
        return {}, {}, {}


def _call_sender_intel(sender_meta: dict, compact: dict):
    event = {
        "type": "intel_probe",
        "sender": sender_meta or {},
        "compact": compact or {},
    }
    payload = _invoke_lambda(INTEL_FN, event)

    if "response" in payload and "functionResponse" in payload.get("response", {}):
        try:
            inner = payload["response"]["functionResponse"]["responseBody"]["TEXT"]["body"]
            data = json.loads(inner)
            return data
        except Exception:
            log.exception(
                "sender-intel Bedrock-style parse error, falling back to raw payload"
            )
            return payload

    return payload


def _call_context_analyzer(content_compact: dict):
    if not CONTEXT_FN:
        return None

    event = {
        "actionGroup": "intel",
        "function": "analyze_context",
        "parameters": [
            {"name": "compact", "value": json.dumps(content_compact)},
        ],
        "messageVersion": "1.0",
    }
    payload = _invoke_lambda(CONTEXT_FN, event)

    try:
        inner = payload["response"]["functionResponse"]["responseBody"]["TEXT"]["body"]
        data = json.loads(inner)
        return data
    except Exception:
        log.exception("context analyzer parse error")
        return None


def _get_sender_trust(from_domain: str) -> dict:
    """
    Query the feedback table to see if IT has repeatedly allowed/blocked this domain.
    Heuristic: 
      - If > 0 blocks recently -> tier="blocked"
      - If >= 3 allows and 0 blocks -> tier="trusted"
      - Else -> tier=None
    """
    if not FEEDBACK_TABLE or not from_domain:
        return {"tier": None, "allows": 0, "blocks": 0}

    try:
        pk = f"domain#{from_domain}"
        # Get last 10 verdicts
        resp = DDB.query(
            TableName=FEEDBACK_TABLE,
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": {"S": pk}},
            ScanIndexForward=False, # Descending (newest first)
            Limit=10
        )
        
        items = resp.get("Items", [])
        allows = 0
        blocks = 0
        
        for item in items:
            verdict = item.get("verdict", {}).get("S")
            if verdict == "allow":
                allows += 1
            elif verdict == "block":
                blocks += 1
        
        tier = None
        if blocks > 0:
            tier = "blocked" # Even one recent block flags it
        elif allows >= 3:
            tier = "trusted" # Consistent history of approvals
            
        return {"tier": tier, "allows": allows, "blocks": blocks}
        
    except Exception:
        log.exception("Failed to query sender trust feedback")
        return {"tier": None, "allows": 0, "blocks": 0}


def _extract_risk_from_sender(sender_raw):
    if not isinstance(sender_raw, dict):
        return 0.0, {}, {}

    if "features" in sender_raw:
        features = sender_raw.get("features") or {}
        ids = sender_raw.get("ids") or {}
    else:
        features = sender_raw
        ids = {}

    candidates = []

    if "risk_score" in sender_raw:
        candidates.append(sender_raw.get("risk_score"))

    r = sender_raw.get("risk")
    if isinstance(r, dict):
        candidates.append(r.get("score"))

    fr = features.get("risk")
    if isinstance(fr, dict):
        candidates.append(fr.get("score"))

    candidates.append(features.get("risk.score"))

    risk_score = 0.0
    for c in candidates:
        if c is None:
            continue
        try:
            risk_score = float(c)
            break
        except Exception:
            continue

    return risk_score, features, ids


def _compute_decision(sender_raw, content_result):
    # NOTE: This is the fallback logic if Decision Agent is missing.
    # The real logic happens in Decision Agent now.
    risk_score, features, ids = _extract_risk_from_sender(sender_raw)

    classification = ""
    confidence = 0.0
    note0 = None

    if isinstance(content_result, dict):
        notes = content_result.get("notes") or []
        if notes:
            note0 = notes[0]
        classification = (note0 or {}).get("classification") or ""
        try:
            confidence = float(content_result.get("confidence_final") or 0.0)
        except Exception:
            confidence = 0.0

    reasons = []
    decision = "ALLOW"

    if risk_score >= 70:
        decision = "QUARANTINE"
        reasons.append(f"sender risk score {risk_score:.1f} >= 70")

    if classification == "phishing" and confidence >= 0.7:
        decision = "QUARANTINE"
        reasons.append(f"content classified as phishing with confidence {confidence:.2f}")

    if not reasons:
        reasons.append("no high-risk signals triggered")

    return (
        decision,
        risk_score,
        classification,
        confidence,
        reasons,
        features,
        ids,
        note0,
    )


def _emit_metrics(decision, classification, has_phi, elapsed_ms):
    try:
        dims = [{"Name": "Function", "Value": "sender-intel-controller"}]
        CW.put_metric_data(
            Namespace="SCIntel",
            MetricData=[
                {
                    "MetricName": "EmailsProcessed",
                    "Dimensions": dims,
                    "Unit": "Count",
                    "Value": 1,
                },
                {
                    "MetricName": "ProcessingTimeMs",
                    "Dimensions": dims,
                    "Unit": "Milliseconds",
                    "Value": elapsed_ms,
                },
                {
                    "MetricName": "Quarantined",
                    "Dimensions": dims,
                    "Unit": "Count",
                    "Value": 1 if decision == "QUARANTINE" else 0,
                },
                {
                    "MetricName": "HasPHI",
                    "Dimensions": dims,
                    "Unit": "Count",
                    "Value": 1 if has_phi else 0,
                },
            ],
        )
    except Exception:
        log.exception("failed to emit CloudWatch metrics")


def enqueue_hitl_if_needed(decision_doc: dict, log_bucket: str, log_key: str):
    """
    If this decision requires human review, write an item into the HITL queue table.
    """
    if not HITL_TABLE or not log_bucket or not log_key:
        return

    try:
        hitl = (decision_doc.get("decision_agent") or {}).get("hitl") or decision_doc.get("hitl") or {}
        status = (hitl.get("status") or "").lower()

        # Only enqueue if HITL is required/pending or explicit IT_REVIEW decision
        if status not in ("required", "pending") and decision_doc.get("decision") != "IT_REVIEW":
            return

        compact = decision_doc.get("compact") or {}
        sender_intel = decision_doc.get("sender_intel") or {}
        ids = sender_intel.get("ids") or {}

        from_addr = (compact.get("from") or {}).get("addr") or ids.get("from_addr") or ""
        from_domain = ids.get("from_domain") or ""
        subject = compact.get("subject") or ""
        message_id = compact.get("message_id") or ids.get("message_id") or ""

        # Use S3 key basename (without extension) as a stable run_id
        basename = log_key.rsplit("/", 1)[-1]
        run_id = basename.rsplit(".", 1)[0]

        created_ts = decision_doc.get("timestamp") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        risk = (decision_doc.get("decision_agent") or {}).get("risk")
        if risk is None:
            risk = (decision_doc.get("summary") or {}).get("sender_risk", 0)

        has_phi = bool((decision_doc.get("summary") or {}).get("has_phi"))
        intent = (decision_doc.get("summary") or {}).get("intent") or ""

        item = {
            "id": {"S": run_id},
            "status": {"S": "pending"},
            "created_ts": {"S": created_ts},
            "decision": {"S": str(decision_doc.get("decision") or "")},
            "risk": {"N": str(risk or 0)},
            "has_phi": {"BOOL": has_phi},
            "intent": {"S": intent},
            "from_addr": {"S": from_addr},
            "from_domain": {"S": from_domain},
            "subject": {"S": subject},
            "log_bucket": {"S": log_bucket},
            "log_key": {"S": log_key},
        }

        DDB.put_item(TableName=HITL_TABLE, Item=item)
    except Exception:
        log.exception("Failed to enqueue HITL item for %s", log_key)


def handler(event, context):
    t0 = time.time()
    mime_raw = _get_mime_from_event(event)
    if not mime_raw:
        return {"statusCode": 400, "error": "Missing mime_raw/mime_b64/body"}

    basic = _parse_mime_basic(mime_raw)

    # 1) MIME → compact & sender meta
    compact, sender_meta, auth = _call_mime_extract(mime_raw)

    # 2) PHI scrubber on plain text body
    phi = _call_phi_scrubber(basic["body"])
    red_body = phi.get("redacted_email", basic["body"])
    has_phi = bool(phi.get("entities_detected") and phi["entities_detected"] > 0)

    # 3) Content analyzer compact view
    content_compact = {
        "subject": basic["subject"],
        "body": red_body,
        "message_id": basic["message_id"],
        "from": sender_meta.get("email") or (compact.get("from") or {}).get("addr"),
        "to": basic["to_header"],
    }
    content_result = _call_context_analyzer(content_compact)

    # 4) Sender intel (OSINT + graph, etc.)
    sender_raw = _call_sender_intel(sender_meta, compact)
    
    # 4a) TRUST CACHE LOOKUP (New)
    ids = sender_raw.get("ids") or {}
    from_domain = ids.get("from_domain") or (sender_meta.get("domain"))
    trust_feedback = _get_sender_trust(from_domain)

    # 5) Baseline decision from sender + content
    (
        decision,
        risk_score,
        classification,
        confidence,
        reasons,
        features,
        ids,
        note0,
    ) = _compute_decision(sender_raw, content_result)

    now = datetime.datetime.utcnow()
    iso_now = now.replace(microsecond=0).isoformat() + "Z"
    msg_id = basic["message_id"] or ids.get("message_id") or f"nomsg-{uuid.uuid4().hex}"

    key = (
        f"{DECISIONS_PREFIX}/"
        f"{now.year:04d}/{now.month:02d}/{now.day:02d}/"
        f"{msg_id}_{now.strftime('%H%M%S')}.json"
    )

    intent = (note0 or {}).get("intent")
    tone = (note0 or {}).get("tone")
    urgency = (note0 or {}).get("urgency")
    signals = (note0 or {}).get("signals") or {}
    scores = (note0 or {}).get("scores") or {}

    sender_risk_notes = []
    risk_field = features.get("risk") if isinstance(features.get("risk"), dict) else None
    if risk_field:
        sender_risk_notes = risk_field.get("notes") or []
    elif isinstance(features.get("risk.notes"), list):
        sender_risk_notes = features["risk.notes"]

    # Run document: this is what the dashboards will read
    log_doc = {
        "version": 1,
        "timestamp": iso_now,
        "source": {
            "pipeline": "sender-intel-controller",
            "region": REGION,
        },
        "decision": decision,
        "decision_reasons": reasons,
        "summary": {
            "classification": classification or "",
            "confidence": confidence,
            "sender_risk": risk_score,
            "sender_risk_notes": sender_risk_notes,
            "intent": intent,
            "tone": tone,
            "urgency": urgency,
            "has_phi": has_phi,
        },
        "compact": {
            "from": compact.get("from") or {},
            "to": basic["to_header"],
            "subject": basic["subject"],
            "message_id": msg_id,
            "date_iso": compact.get("date_iso"),
            "has_calendar_ics": bool(compact.get("has_calendar_ics")),
            "body_preview": (basic["body"] or "")[:280],
        },
        "phi": {
            "entities_detected": phi.get("entities_detected"),
            "model_version": phi.get("model_version"),
        },
        "content": content_result or {},
        "sender_intel": {
            "raw": sender_raw,
            "risk": risk_score,
            "features": features,
            "ids": ids,
            "trust": trust_feedback, # Inject trust feedback here
        },
        "hitl": {
            "status": "",
            "actor": "",
            "verdict": "",
            "notes": "",
            "ts": None,
        },
        "queue": {
            "status": "auto_cleared" if decision == "ALLOW" else "quarantined",
            "created_ts": iso_now,
            "resolved_ts": None,
        },
        "elapsed_ms": None,
    }

    # 6) Decision agent: can override decision/risk/reasons, but HITL stays downstream.
    decision_agent_out = {}
    if DECISION_FN:
        try:
            decision_agent_out = _call_decision_agent(log_doc) or {}
        except Exception:
            log.exception("decision agent call failed")
            decision_agent_out = {}

    if isinstance(decision_agent_out, dict) and decision_agent_out:
        # Attach raw decision agent payload for transparency.
        log_doc["decision_agent"] = decision_agent_out

        # Override decision if provided.
        da_decision = decision_agent_out.get("decision")
        if isinstance(da_decision, str) and da_decision:
            decision = da_decision
            log_doc["decision"] = da_decision

        # Optional: override risk if agent returns a composite risk.
        if "risk" in decision_agent_out and decision_agent_out["risk"] is not None:
            try:
                risk_score = float(decision_agent_out["risk"])
                log_doc["sender_intel"]["risk"] = risk_score
                log_doc["summary"]["sender_risk"] = risk_score
            except Exception:
                pass

        # Override decision reasons if agent provided them.
        da_reasons = decision_agent_out.get("reasons")
        if isinstance(da_reasons, list) and da_reasons:
            log_doc["decision_reasons"] = da_reasons

        # Allow agent to attach HITL hints (status required, etc.)
        da_hitl = decision_agent_out.get("hitl")
        if isinstance(da_hitl, dict):
            log_doc["hitl"].update(da_hitl)

    # Keep queue status consistent with HITL and final decision
    hitl_info = (log_doc.get("decision_agent") or {}).get("hitl") or log_doc.get("hitl") or {}
    hitl_status = (hitl_info.get("status") or "").lower()
    if "queue" in log_doc:
        if hitl_status in ("required", "pending") or decision == "IT_REVIEW":
            log_doc["queue"]["status"] = "pending"
        else:
            log_doc["queue"]["status"] = (
                "auto_cleared" if decision == "ALLOW" else "quarantined"
            )

    # 7) Final elapsed time
    elapsed_ms = int((time.time() - t0) * 1000)
    log_doc["elapsed_ms"] = elapsed_ms

    # 8) Persist run document to S3
    if DECISIONS_BUCKET:
        try:
            S3.put_object(
                Bucket=DECISIONS_BUCKET,
                Key=key,
                Body=json.dumps(log_doc, ensure_ascii=False).encode("utf-8"),
                ContentType="application/json",
            )
            # Enqueue HITL item if needed
            enqueue_hitl_if_needed(log_doc, DECISIONS_BUCKET, key)
        except Exception:
            log.exception("failed to write run document to S3")

    # 9) Emit CloudWatch metrics
    _emit_metrics(decision, classification, has_phi, elapsed_ms)

    # 10) Return minimal decision envelope to caller
    return {
        "statusCode": 200,
        "decision": decision,
        "risk": risk_score,
        "content_classification": classification,
        "content_confidence": confidence,
        "phi_entities": phi.get("entities_detected"),
        "log_object": {
            "bucket": DECISIONS_BUCKET,
            "key": key,
        },
    }