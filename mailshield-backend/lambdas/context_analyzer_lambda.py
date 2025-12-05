import json, logging, re
from http import HTTPStatus
from typing import Any, Dict, List

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# --- PATTERNS ---
SUSPICIOUS_TERMS = [
    r"\bconfirm\b", r"\bverify\b", r"\bupdate\b", r"\bcredential(s)?\b", r"\bpassword\b",
    r"\bbank( account)?\b", r"\bsecure\b", r"\bportal\b",
    r"\bclick\b.*\blink\b", r"\bfollow\b.*\blink\b", r"\buse\b.*\blink\b",
    r"\blink below\b", r"\blink provided\b", r"\bvia the link\b"
]
URGENCY_TERMS = [
    r"\burgent\b", r"\baction required\b", r"\bimmediately\b", r"\basap\b",
    r"\bavoid delay(s)?\b", r"\bfinal notice\b", r"\bmust\b", r"\brequired\b",
    r"\bprevent\b.*\b(interruption|suspension|lockout)\b",
    r"\bimmediate processing\b", r"\bdelay(ed)? payment(s)?\b"
]
MANIPULATIVE_TONE_TERMS = [
    r"\bto avoid\b.*\b(delay|suspension|termination)\b",
    r"\bfailure to\b.*\bwill result\b",
    r"\bfailure to\b.*\b(delay|issue|penalt(y|ies)|suspension|lockout|cancel)\b",
    r"\bwithout\b.*\b(confirmation|response|action)\b.*\b(delay|hold|impact)\b"
]
CREDENTIAL_INTENT_TERMS = [
    r"\blogin\b", r"\bsign in\b", r"\bverify (?:your )?account\b",
    r"\benter (?:your )?(?:details|credentials|password)\b",
    r"\bconfirm (?:bank|account|details)\b", r"\breactivate\b"
]
FINANCIAL_TERMS = [r"\bpayment\b", r"\binvoice\b", r"\brefund\b", r"\btransfer\b", r"\bbilling\b"]
SUPPORT_TERMS = [r"\bsupport\b", r"\bhelp\b", r"\bassist\b", r"\bissue\b", r"\bticket\b"]
SCHEDULING_TERMS = [r"\bmeeting\b", r"\bappointment\b", r"\bcalendar\b", r"\breschedule\b"]
ATTACHMENT_TERMS = [
    r"\bsee attached\b", r"\bopen the attachment\b", r"\battached file\b",
    r"\battachment\b", r"\battached document\b", r"\battached payroll\b"
]

# Weights determine the maximum risk contribution of a category
WEIGHTS = {
    "credential_language": 0.35,
    "suspicious_link": 0.40,
    "urgency_language": 0.20,
    "manipulative_tone": 0.20,
    "attachment_reference": 0.15
}
THRESHOLDS = {"phishing": 0.5}


def find_matches(patterns: List[str], text: str) -> List[str]:
    # Return all unique matches to allow intensity scoring
    matches = []
    for p in patterns:
        m = re.search(p, text, flags=re.IGNORECASE)
        if m:
            matches.append(m.group(0))
    return list(set(matches))


def extract_urls(text: str) -> List[str]:
    return re.findall(r'https?://[^\s)>\]]+', text, flags=re.IGNORECASE)


def clamp01(x: float) -> float:
    return max(0.0, min(1.0, round(x, 3)))


def classify_tone(body: str) -> str:
    if find_matches(MANIPULATIVE_TONE_TERMS, body):
        return "manipulative"
    if re.search(r"\bthank(s| you)\b", body, re.I) or "appreciate" in body.lower():
        return "friendly"
    if re.search(r"\bregards\b|\bbest\b|\bsincerely\b", body, re.I):
        return "professional"
    return "neutral"


def classify_urgency(body: str) -> str:
    return "urgent" if find_matches(URGENCY_TERMS, body) else "routine"


def infer_intent(body: str) -> str:
    if find_matches(CREDENTIAL_INTENT_TERMS, body):
        return "credential_request"
    if find_matches(FINANCIAL_TERMS, body):
        return "financial_action"
    if find_matches(SUPPORT_TERMS, body):
        return "support_request"
    if find_matches(SCHEDULING_TERMS, body):
        return "scheduling"
    return "informational"


def score_features(subject: str, body: str) -> Dict[str, Any]:
    text = f"{subject} {body}"
    urls = extract_urls(text)
    
    # Return counts (intensity) AND booleans for simple checks
    return {
        "credential_language": len(find_matches(CREDENTIAL_INTENT_TERMS + SUSPICIOUS_TERMS, text)),
        "urgency_language": len(find_matches(URGENCY_TERMS, text)),
        "manipulative_tone": len(find_matches(MANIPULATIVE_TONE_TERMS, text)),
        "suspicious_link": len(urls),
        "attachment_reference": len(find_matches(ATTACHMENT_TERMS, text)),
    }


def compute_scores(signals: Dict[str, Any]) -> Dict[str, float]:
    # Score based on intensity logic
    # 1 match = 60% of weight, 2 matches = 90%, 3+ = 100%
    final_scores = {}
    
    for k, count in signals.items():
        if count == 0:
            final_scores[k] = 0.0
        else:
            max_weight = WEIGHTS.get(k, 0.0)
            impact_factor = min(1.0, 0.6 + (0.3 * (count - 1)))
            final_scores[k] = round(max_weight * impact_factor, 3)
            
    return final_scores


def classify(total: float) -> str:
    return "phishing" if total >= THRESHOLDS["phishing"] else "safe"


def compute_confidence(total: float, classification: str) -> float:
    # Non-linear confidence mapping to avoid "stuck" scores
    # We use 'total' (the risk score) to determine how confident we are
    
    if classification == "phishing":
        # Risk 0.50 -> Conf 0.60
        # Risk 1.00 -> Conf 0.99
        # Curve: slightly exponential to favor high confidence on high risk
        dist = (total - THRESHOLDS["phishing"]) / (1.0 - THRESHOLDS["phishing"])
        conf = 0.60 + (0.39 * (dist ** 0.8)) # power of 0.8 pushes curve up slightly
        return clamp01(conf)
    else:
        # Risk 0.00 -> Conf 0.99 (Safe)
        # Risk 0.49 -> Conf 0.55 (Unsure)
        dist = (THRESHOLDS["phishing"] - total) / THRESHOLDS["phishing"]
        conf = 0.55 + (0.44 * (dist ** 0.8))
        return clamp01(conf)


def agentic_reasoning(subject: str, body: str, signals: Dict[str, Any]) -> List[str]:
    trace: List[str] = []
    
    cred_count = signals.get("credential_language", 0)
    link_count = signals.get("suspicious_link", 0)
    urg_count = signals.get("urgency_language", 0)

    # Critical Combination Check
    if cred_count > 0 and link_count > 0:
        trace.append("CRITICAL: Detected credential request combined with external links - highly indicative of phishing.")
    
    if cred_count > 0 and link_count == 0:
        trace.append("Detected credential request language without links (potential reply-chain phishing).")

    if urg_count > 0:
        trace.append(f"Detected urgency terminology ({urg_count} instance(s)).")

    if link_count > 2:
        trace.append(f"High density of links detected ({link_count}), common in mass-scatter phishing.")
    elif link_count > 0:
        trace.append("Contains external links.")

    if signals.get("financial_action", 0) > 0: # Note: need to pass this through if we want to trace it
        trace.append("Financial terminology detected.")

    if not trace:
        trace.append("No significant phishing patterns detected.")

    return trace


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    try:
        params = event.get("parameters") or []
        compact_raw = ""
        for p in params:
            if p.get("name") == "compact":
                compact_raw = p.get("value") or ""
                break

        if not compact_raw:
            # Fallback for testing
            compact = event.get("compact", {})
        else:
            compact = json.loads(compact_raw)

        subject = compact.get("subject", "") or ""
        body = compact.get("body", "") or ""

        intent = infer_intent(body)
        tone = classify_tone(body)
        urgency = classify_urgency(body)

        signals = score_features(subject, body)
        
        # Critical Combination Boost
        # If Credential Language + Link, boost the virtual score
        # This prevents "Credential Harvesting" from ever slipping by as "Safe"
        if signals["credential_language"] > 0 and signals["suspicious_link"] > 0:
            # Artificial boost to ensure it crosses threshold
            signals["credential_language"] = max(signals["credential_language"], 2) 
        
        scores = compute_scores(signals)
        total_risk = clamp01(sum(scores.values()))
        
        classification = classify(total_risk)
        confidence = compute_confidence(total_risk, classification)
        reasoning = agentic_reasoning(subject, body, signals)

        # Convert signals to boolean for simpler UI display if needed
        signals_bool = {k: v > 0 for k, v in signals.items()}

        result = {
            "confidence_final": confidence,
            "notes": [{
                "intent": intent,
                "tone": tone,
                "urgency": urgency,
                "classification": classification,
                "reasoning": reasoning,
                "signals": signals_bool,
                "scores": scores,
            }],
        }

        return {
            "response": {
                "actionGroup": event.get("actionGroup", "intel"),
                "function": event.get("function", "analyze_context"),
                "functionResponse": {
                    "responseBody": {
                        "TEXT": {"body": json.dumps(result, ensure_ascii=False)}
                    }
                },
            },
            "messageVersion": event.get("messageVersion", "1.0"),
        }

    except Exception as e:
        logger.exception("Unhandled error in context_analyzer_lambda")
        return {
            "statusCode": HTTPStatus.INTERNAL_SERVER_ERROR,
            "body": f"Error: {str(e)}",
        }