# mime_extract_lambda.py
import json, base64, binascii, logging, re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, parsedate_to_datetime

log = logging.getLogger()
log.setLevel(logging.INFO)

# ---------------- envelope helpers ----------------

def _wrap_fn(event, body_obj):
    """Return Bedrock Agent Function schema with TEXT body (kept for compatibility)."""
    action_group = event.get("actionGroup") or "mime"
    function = event.get("function") or "extract"
    return {
        "messageVersion": "1.0",
        "response": {
            "actionGroup": action_group,
            "function": function,
            "functionResponse": {
                "responseBody": {
                    "TEXT": {"body": json.dumps(body_obj, ensure_ascii=False)}
                }
            },
        },
        "sessionAttributes": event.get("sessionAttributes", {}),
        "promptSessionAttributes": event.get("promptSessionAttributes", {}),
    }

def _read_json_request_body(event):
    """Agent OpenAPI style: requestBody.content['application/json'].body -> dict"""
    rb = event.get("requestBody")
    if not isinstance(rb, dict):
        return {}
    content = rb.get("content") or {}
    app = content.get("application/json")
    if isinstance(app, dict) and "body" in app:
        try:
            return app["body"] if isinstance(app["body"], dict) else json.loads(app["body"])
        except Exception:
            return {}
    return {}

def _maybe_json(s):
    if not isinstance(s, str):
        return None
    try:
        return json.loads(s)
    except Exception:
        return None

# ---------------- MIME fetch ----------------

def _get_mime_text(event) -> str:
    """
    Accepts multiple invocation shapes and returns the FULL MIME as a unicode string.
    Supported:
      - Agent function: parameters[{name:'mime_b64'|'mime_raw'}]
      - requestBody.application/json: {'mime_b64' | 'mime_raw' | 'mime'}
      - Top-level event['mime_b64'|'mime_raw'|'mime']
      - API Gateway style: event['body'] (+ optional isBase64Encoded)
      - body: JSON string containing 'mime_b64' or 'mime'
    """
    # 1) OpenAPI requestBody JSON
    body = _read_json_request_body(event)
    mime_b64 = body.get("mime_b64")
    mime_raw = body.get("mime_raw") or body.get("mime")

    # 2) Top-level convenience
    mime_b64 = mime_b64 or event.get("mime_b64")
    mime_raw = mime_raw or event.get("mime_raw") or event.get("mime")

    # 3) Agent parameters (array or dict)
    params = event.get("parameters")
    if isinstance(params, list):
        for p in params:
            if not isinstance(p, dict):
                continue
            n = p.get("name")
            v = p.get("value")
            if isinstance(v, dict):
                v = v.get("stringValue") or v.get("value")
            if n in ("mime_raw", "mime") and v:
                mime_raw = v
            elif n == "mime_b64" and v:
                mime_b64 = v
    elif isinstance(params, dict):
        v = params.get("mime_b64") or params.get("mime_raw") or params.get("mime")
        if v:
            if "b64" in next((k for k in params.keys() if k), ""):
                mime_b64 = v
            else:
                mime_raw = v

    # 4) API GW body (string or dict)
    if not (mime_raw or mime_b64):
        b = event.get("body")
        if isinstance(b, (bytes, bytearray)):
            try:
                return b.decode("utf-8", "replace")
            except Exception:
                return ""
        if isinstance(b, str):
            # APIGW base64?
            if event.get("isBase64Encoded") is True:
                try:
                    return base64.b64decode(b).decode("utf-8", "replace")
                except Exception:
                    return ""
            # maybe a JSON string wrapper?
            j = _maybe_json(b)
            if isinstance(j, dict):
                if "mime_b64" in j and j["mime_b64"]:
                    try:
                        return base64.b64decode(j["mime_b64"]).decode("utf-8", "replace")
                    except Exception:
                        return ""
                if j.get("mime_raw") or j.get("mime"):
                    v = j.get("mime_raw") or j.get("mime")
                    return v if isinstance(v, str) else str(v)
            # otherwise assume raw MIME in body
            return b
        if isinstance(b, dict):
            v = b.get("mime_raw") or b.get("mime")
            if v:
                return v if isinstance(v, str) else str(v)
            vb = b.get("mime_b64")
            if vb:
                try:
                    return base64.b64decode(vb).decode("utf-8", "replace")
                except Exception:
                    return ""

    # 5) Direct fields worked
    if mime_raw:
        return mime_raw if isinstance(mime_raw, str) else str(mime_raw)
    if mime_b64:
        try:
            return base64.b64decode(mime_b64).decode("utf-8", "replace")
        except Exception:
            return ""

    return ""

# ---------------- MIME parse ----------------

_IP_RX = re.compile(r'\[([0-9a-fA-F:.]+)\]')  # naive, works for IPv4/IPv6 literals

def _best_effort_client_ip(headers) -> str | None:
    """
    Try to pull an origin client IP from the *last* Received: header (closest to source).
    """
    recv = headers.get_all("Received", [])
    if not recv:
        return None
    # The earliest hop is typically the *last* Received header in the list
    try_order = list(recv)[-3:] if len(recv) > 3 else list(recv)
    for line in reversed(try_order):
        m = _IP_RX.search(str(line))
        if m:
            return m.group(1)
    return None

def _parse_mime(mime_text: str):
    # Parse to bytes; preserve all headers/lines
    msg = BytesParser(policy=policy.default).parsebytes(mime_text.encode("utf-8", "ignore"))

    # From
    _, from_addr = parseaddr(msg.get("From") or "")
    from_addr = (from_addr or "").lower() or None

    # Return-Path (envelope sender) if present
    _, return_path = parseaddr(msg.get("Return-Path") or "")
    mail_from = (return_path or "").lower() or from_addr

    # Subject
    subject = msg.get("Subject")
    subject = str(subject) if subject is not None else None

    # Message-ID
    msg_id = (msg.get("Message-ID") or "").strip().strip("<>") or None

    # Date → ISO
    date_iso = None
    if msg.get("Date"):
        try:
            date_iso = parsedate_to_datetime(msg.get("Date")).astimezone().isoformat()
        except Exception:
            date_iso = None

    # List-Unsubscribe present?
    list_unsub = bool(msg.get("List-Unsubscribe"))

    # text/calendar or *.ics?
    has_ics = False
    part_count = 1  # single-part by default
    try:
        if msg.is_multipart():
            part_count = 0
            for p in msg.walk():
                part_count += 1
                ctype = (p.get_content_type() or "").lower()
                fname = (p.get_filename() or "").lower()
                if ctype == "text/calendar" or (fname and fname.endswith(".ics")):
                    has_ics = True
        else:
            ctype = (msg.get_content_type() or "").lower()
            fname = (msg.get_filename() or "").lower()
            if ctype == "text/calendar" or (fname and fname.endswith(".ics")):
                has_ics = True
    except Exception:
        pass

    # Best-effort origin IP from Received:
    client_ip = _best_effort_client_ip(msg)

    compact = {
        "from": {"addr": from_addr},
        "envelope": {"client_ip": client_ip, "mail_from": mail_from},
        "message_id": msg_id,
        "date_iso": date_iso,
        "subject": subject,
        "list_unsubscribe_present": list_unsub,
        "has_calendar_ics": has_ics,
        "provenance": "controller-mime-extract",
        # (optional) provide count for dashboards
        "parts": part_count,
    }

    sender = {
        "email": from_addr,
        "domain": (from_addr or "@").split("@")[-1] if from_addr else None,
        "ip": client_ip,
    }

    auth = {"spf.result": None, "dkim.result": None, "dmarc.result": None, "dkim.present": False}

    return {"compact": compact, "sender": sender, "auth": auth, "extracted": True}

# ---------------- Lambda entry ----------------

def handler(event, context):
    try:
        mime_text = _get_mime_text(event)
        if not mime_text:
            return _wrap_fn(event, {"error": "Provide 'mime_raw' or 'mime_b64'."})
        out = _parse_mime(mime_text)
        return _wrap_fn(event, out)
    except Exception:
        log.exception("mime_extract error")
        return _wrap_fn(event, {"error": "Unhandled"})
