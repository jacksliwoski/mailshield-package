import json
import logging
from typing import Any, Dict

log = logging.getLogger()
log.setLevel(logging.INFO)


def _extract_signals(run: Dict[str, Any]) -> Dict[str, Any]:
    """
    Pull out the key signals the decision agent should look at.
    """
    summary = run.get("summary") or {}
    compact = run.get("compact") or {}
    phi = run.get("phi") or {}
    content = run.get("content") or {}
    sender_intel = run.get("sender_intel") or {}

    # Sender risk
    sender_risk = summary.get("sender_risk")
    if sender_risk is None:
        sender_risk = sender_intel.get("risk", 0)
    try:
        sender_risk = float(sender_risk or 0.0)
    except Exception:
        sender_risk = 0.0

    # Classification + confidence
    classification = (summary.get("classification") or "").lower()
    conf = summary.get("confidence")
    if conf is None:
        conf = content.get("confidence_final")
    try:
        confidence = float(conf or 0.0)
    except Exception:
        confidence = 0.0

    # Intent / tone / urgency
    intent = summary.get("intent") or ""
    tone = summary.get("tone") or ""
    urgency = summary.get("urgency") or ""

    notes = content.get("notes") or []
    if notes and isinstance(notes, list) and isinstance(notes[0], dict):
        note0 = notes[0]
        if not classification:
            classification = (note0.get("classification") or "").lower()
        intent = intent or note0.get("intent") or ""
        tone = tone or note0.get("tone") or ""
        urgency = urgency or note0.get("urgency") or ""

    # PHI intensity
    try:
        phi_entities = int(phi.get("entities_detected") or 0)
    except Exception:
        phi_entities = 0

    # Basic identity
    from_obj = compact.get("from") or {}
    from_addr = (from_obj.get("addr") or from_obj.get("email") or "")
    if "@" in from_addr:
        from_domain = from_addr.split("@", 1)[1]
    else:
        from_domain = ""

    subject = compact.get("subject") or ""
    prior_decision = (run.get("decision") or "").upper() or "ALLOW"

    # Org features
    features = sender_intel.get("features") or {}
    org = features.get("org") or {}
    
    # Feedback Trust Tier
    trust = sender_intel.get("trust") or {}
    trust_tier = trust.get("tier") # "trusted", "blocked", or None

    return {
        "classification": classification,
        "confidence": confidence,
        "sender_risk": sender_risk,
        "phi_entities": phi_entities,
        "intent": intent,
        "tone": tone,
        "urgency": urgency,
        "from_addr": from_addr,
        "from_domain": from_domain,
        "subject": subject,
        "prior_decision": prior_decision,
        "org_category": org.get("category"),
        "org_trust_tier": org.get("trust_tier"),
        "org_company": org.get("company") or org.get("org"),
        "feedback_trust_tier": trust_tier,
    }


def _decide(signals: Dict[str, Any]) -> Dict[str, Any]:
    """
    Decision Logic to prevent Alert Fatigue:
    1. Check Feedback Cache (Blocked/Trusted)
    2. Auto-Block High Confidence Phishing
    3. Auto-Allow High Confidence Safe
    4. HITL only for Gray Zone
    """
    classification = (signals.get("classification") or "").lower()
    confidence = float(signals.get("confidence") or 0.0)
    sender_risk = float(signals.get("sender_risk") or 0.0)
    phi_entities = int(signals.get("phi_entities") or 0)
    prior_decision = (signals.get("prior_decision") or "ALLOW").upper()
    
    trust_tier = signals.get("feedback_trust_tier")

    reasons = []
    decision = prior_decision
    risk = sender_risk 

    is_phish = classification == "phishing"
    is_safe = classification == "safe"
    has_phi = phi_entities > 0
    
    hitl_status = ""

    # === RULE 0: HUMAN FEEDBACK CACHE (FAST TRACK) ===
    if trust_tier == "blocked":
        decision = "QUARANTINE"
        hitl_status = "skipped"
        reasons.append("Sender is explicitly blocked by previous IT verdict. Auto-quarantined.")
        # We return early because human block overrides almost everything
        return _pkg(decision, risk, reasons, hitl_status, signals)

    if trust_tier == "trusted":
        # If trusted, we skip HITL unless it's blatantly malicious content
        if is_phish and confidence > 0.90:
            # Trusted sender but hacked account sending blatant phishing?
            decision = "QUARANTINE"
            hitl_status = "required"
            reasons.append("Sender is normally trusted, but content is high-confidence phishing. Account compromise suspected.")
        elif is_safe:
            decision = "ALLOW"
            hitl_status = "skipped"
            reasons.append(f"Sender is trusted by IT history. Auto-allowed despite risk score {sender_risk:.1f}.")
            return _pkg(decision, risk, reasons, hitl_status, signals)

    # === RULE 1: HIGH CONFIDENCE PHISHING (AUTO-QUARANTINE) ===
    if is_phish and confidence >= 0.85:
        decision = "QUARANTINE"
        hitl_status = "skipped" # Auto-block
        reasons.append(f"High-confidence phishing detection ({confidence:.2f}). Auto-quarantined to reduce alert fatigue.")

    # === RULE 2: EXTREME SENDER RISK (AUTO-QUARANTINE) ===
    elif sender_risk >= 85:
        decision = "QUARANTINE"
        hitl_status = "skipped"
        reasons.append(f"Sender risk is critical ({sender_risk:.1f}). Auto-quarantined.")

    # === RULE 3: THE GRAY ZONE (HITL REQUIRED) ===
    elif is_phish and 0.50 <= confidence < 0.85:
        decision = "QUARANTINE"
        hitl_status = "required"
        reasons.append(f"Suspected phishing with moderate confidence ({confidence:.2f}). Requires human verification.")

    elif is_safe and sender_risk >= 60:
        decision = "QUARANTINE"
        hitl_status = "required"
        reasons.append(f"Content appears safe, but sender risk is high ({sender_risk:.1f}). IT review required.")

    # === RULE 4: PHI COMPLIANCE (NUANCED) ===
    elif has_phi:
        if is_safe and confidence >= 0.75 and sender_risk < 50:
            decision = "ALLOW"
            hitl_status = "skipped"
            reasons.append(f"Contains PHI ({phi_entities} entities), but sender/content confidence is high. Allowed.")
        else:
            decision = "ALLOW" # Allow technically, but hold for review
            hitl_status = "required"
            reasons.append(f"Contains PHI with lower confidence ({confidence:.2f}) or elevated risk. Compliance review required.")

    # === RULE 5: HIGH CONFIDENCE SAFE (AUTO-ALLOW) ===
    elif is_safe and confidence >= 0.80 and sender_risk < 50:
        decision = "ALLOW"
        hitl_status = "skipped"
        reasons.append(f"High-confidence safe email ({confidence:.2f}).")

    # === DEFAULT ===
    else:
        if decision == "QUARANTINE":
            hitl_status = "required"
            reasons.append("Baseline logic quarantined message; requiring HITL confirmation.")
        else:
            hitl_status = "skipped"
            reasons.append("Routine email; no high-risk signals detected.")

    return _pkg(decision, risk, reasons, hitl_status, signals)

def _pkg(decision, risk, reasons, hitl_status, signals):
    hitl = {
        "status": hitl_status,
        "actor": "",
        "verdict": "",
        "notes": "",
        "ts": None,
    }
    return {
        "decision": decision,
        "risk": risk,
        "reasons": reasons,
        "hitl": hitl,
        "signals": {k: v for k, v in signals.items() if k != "prior_decision"},
    }

def lambda_handler(event, context):
    log.info("Decision agent invoked; top-level keys: %s", list(event.keys()))
    if "run" in event and isinstance(event["run"], dict):
        run = event["run"]
    else:
        run = event

    signals = _extract_signals(run or {})
    out = _decide(signals)
    return out