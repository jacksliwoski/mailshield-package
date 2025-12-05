# intel_lambda.py
import json, os, time, logging, re
from typing import Any, Dict, Optional, Tuple, List
import boto3, botocore, requests

log = logging.getLogger()
log.setLevel(logging.INFO)

DDB = boto3.client("dynamodb")
S3  = boto3.client("s3")

HTTP_TIMEOUT: Tuple[float, float] = (1.2, 1.5)
BUDGET_S = float(os.getenv("OSINT_BUDGET_S", "2.2"))

DDB_DOM   = os.getenv("DDB_DOM") or ""
DDB_IP    = os.getenv("DDB_IP") or ""
DDB_GRAPH = os.getenv("DDB_GRAPH") or ""

DDB_TTL_DOM = int(os.getenv("DDB_TTL_DOM", str(7 * 24 * 3600)))
DDB_TTL_IP  = int(os.getenv("DDB_TTL_IP",  str(24 * 3600)))

CFG_BUCKET       = os.getenv("CFG_BUCKET") or ""
WL_KEY           = os.getenv("WL_KEY") or ""
ACC_KEY          = os.getenv("ACC_KEY") or ""
ORG_PATTERNS_KEY = os.getenv("ORG_PATTERNS_KEY") or ""
BRAND_BASES_KEY  = os.getenv("BRAND_BASES_KEY") or ""

# New: org roster config (Smile Clinic, vendors, etc.)
ORG_ENTITIES_KEY = os.getenv("ORG_ENTITIES_KEY") or ""
_ORG_CACHE = None

URLSCAN_KEY   = os.getenv("URLSCAN_KEY") or ""
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY") or ""

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "sc-intel/1.0"})
NOW = lambda: int(time.time())

AG_NAME = "intel"
FN_NAME = "probe"


def _load_org_entities() -> dict:
    """
    Lazy-load the org entities roster from S3 (e.g., Smile Clinic internal staff,
    vendors, insurers, etc.). Cached in-memory across invocations.
    """
    global _ORG_CACHE
    if _ORG_CACHE is not None:
        return _ORG_CACHE

    if not CFG_BUCKET or not ORG_ENTITIES_KEY:
        _ORG_CACHE = {}
        return _ORG_CACHE

    try:
        obj = S3.get_object(Bucket=CFG_BUCKET, Key=ORG_ENTITIES_KEY)
        _ORG_CACHE = json.loads(obj["Body"].read().decode("utf-8"))
        log.info("Loaded org entities config with %d entries", len(_ORG_CACHE))
    except Exception:
        log.exception("failed to load org entities config")
        _ORG_CACHE = {}

    return _ORG_CACHE


def _lookup_org_entity(email: str) -> dict | None:
    """
    Lookup a sender email in the org roster. Returns a metadata dict or None.
    """
    if not email:
        return None
    entities = _load_org_entities()
    return entities.get(email.lower())


def _is_openapi_event(event: Dict[str, Any]) -> bool:
    return all(k in event for k in ("actionGroup", "apiPath", "httpMethod"))


def _get_json_request_body(event: Dict[str, Any]) -> Dict[str, Any]:
    rb = event.get("requestBody")
    if not isinstance(rb, dict):
        return {}
    content = rb.get("content", rb)
    app = content.get("application/json") if isinstance(content, dict) else None
    if not isinstance(app, dict):
        return {}
    body = app.get("body") or app.get("json") or app.get("value")
    if isinstance(body, str):
        try:
            return json.loads(body)
        except Exception:
            return {}
    return body if isinstance(body, dict) else {}


def _wrap_openapi_json(
    event: Dict[str, Any],
    body_obj: Dict[str, Any],
    status_code: int = 200,
) -> Dict[str, Any]:
    return {
        "messageVersion": "1.0",
        "response": {
            "actionGroup": event["actionGroup"],
            "apiPath": event["apiPath"],
            "httpMethod": event["httpMethod"],
            "httpStatusCode": status_code,
            "responseBody": {"application/json": {"body": body_obj}},
        },
    }


def _wrap_function_response(event: Dict[str, Any], body_obj: Dict[str, Any]) -> Dict[str, Any]:
    action_group = event.get("actionGroup") or AG_NAME
    function = event.get("function") or FN_NAME
    return {
        "messageVersion": "1.0",
        "response": {
            "actionGroup": action_group,
            "function": function,
            "functionResponse": {
                "responseBody": {"TEXT": {"body": json.dumps(body_obj)}}
            },
        },
        "sessionAttributes": event.get("sessionAttributes", {}),
        "promptSessionAttributes": event.get("promptSessionAttributes", {}),
    }


def _get_param_from_list(params: Any, name: str) -> Optional[Any]:
    if isinstance(params, list):
        for p in params:
            if isinstance(p, dict) and p.get("name") == name:
                v = p.get("value")
                if isinstance(v, dict):
                    return v.get("stringValue") or v.get("value")
                return v
    return None


def _maybe_parse_json_string(s: Any) -> Optional[Dict[str, Any]]:
    if isinstance(s, str) and s.strip():
        try:
            return json.loads(s)
        except Exception:
            return None
    return s if isinstance(s, dict) else None


def _extract_compact_value(event: Dict[str, Any]) -> Optional[Any]:
    rb = _get_json_request_body(event)
    if isinstance(rb, dict) and "compact" in rb:
        return rb.get("compact")

    if isinstance(event.get("parameters"), list):
        v = _get_param_from_list(event["parameters"], "compact")
        if v is not None:
            return v

    if isinstance(event.get("parameters"), dict):
        v = event["parameters"].get("compact")
        if v is not None:
            return v

    for k in ("input", "detail", "payload", "requestBody", "body"):
        container = event.get(k)
        if isinstance(container, str):
            j = _maybe_parse_json_string(container)
            if isinstance(j, dict) and "compact" in j:
                return j.get("compact")
        elif isinstance(container, dict):
            if "compact" in container:
                return container.get("compact")

    if "compact" in event:
        return event.get("compact")

    return None


# Accept either wrapper {"compact": {...}} or plain compact {...}
def _unwrap_compact(obj: Any) -> Any:
    if isinstance(obj, dict) and "compact" in obj and isinstance(obj["compact"], dict):
        inner = obj["compact"]
        if "provenance" not in inner and "provenance" in obj and isinstance(
            obj["provenance"], str
        ):
            inner["provenance"] = obj["provenance"]
        log.info("intel: unwrapped compact from outer wrapper")
        return inner
    return obj


def _normalize_event_to_compact_obj(event: Dict[str, Any]) -> Dict[str, Any]:
    cval = _extract_compact_value(event)
    if isinstance(cval, dict):
        return _unwrap_compact(cval)
    if isinstance(cval, str) and cval.strip():
        j = _maybe_parse_json_string(cval)
        if isinstance(j, dict):
            return _unwrap_compact(j)

    # Back-compat fallbacks / manual form
    if event.get("type") == "intel_probe" and isinstance(event.get("sender"), dict):
        s = event["sender"]
        email = s.get("email")
        ip = s.get("ip")
        return {
            "from": {"addr": email},
            "envelope": {"client_ip": ip, "mail_from": email},
            "message_id": event.get("message_id"),
            "date_iso": event.get("date_iso"),
            "list_unsubscribe_present": False,
            "has_calendar_ics": False,
            "provenance": "controller-mime-extract",
        }

    email = event.get("from_addr")
    ip = event.get("ip") or ((event.get("envelope") or {}).get("client_ip"))
    if email or ip:
        return {
            "from": {"addr": email},
            "envelope": {"client_ip": ip, "mail_from": email},
            "message_id": event.get("message_id"),
            "date_iso": event.get("date_iso"),
            "list_unsubscribe_present": bool(
                event.get("list_unsubscribe_present", False)
            ),
            "has_calendar_ics": bool(event.get("has_calendar_ics", False)),
            "provenance": "controller-mime-extract",
        }

    return {}


def s3_get_json(bucket: str, key: str) -> Optional[Any]:
    if not bucket or not key:
        return None
    try:
        obj = S3.get_object(Bucket=bucket, Key=key)
        data = obj["Body"].read()
        return json.loads(data.decode("utf-8"))
    except botocore.exceptions.ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code not in ("NoSuchKey", "NoSuchBucket", "AccessDenied"):
            log.info("S3 get %s/%s failed: %s", bucket, key, e)
        return None
    except Exception as e:
        log.info("S3 get %s/%s failed: %s", bucket, key, e)
        return None


def whitelist_hit(cfg: Any, addr: Optional[str], dom: Optional[str]) -> bool:
    if not cfg:
        return False
    addrs = set()
    doms = set()
    if isinstance(cfg, dict):
        if isinstance(cfg.get("addresses"), list):
            addrs.update([str(x).lower() for x in cfg["addresses"]])
        if isinstance(cfg.get("domains"), list):
            doms.update([str(x).lower() for x in cfg["domains"]])
        if isinstance(cfg.get("list"), list):
            for x in cfg["list"]:
                s = str(x).lower()
                (addrs if "@" in s else doms).add(s)
    elif isinstance(cfg, list):
        for x in cfg:
            s = str(x).lower()
            (addrs if "@" in s else doms).add(s)
    a = (addr or "").lower()
    d = (dom or "").lower()
    return (a and a in addrs) or (d and d in doms)


def account_status(cfg: Any, addr: Optional[str], dom: Optional[str]) -> Optional[str]:
    if not cfg:
        return None
    a = (addr or "").lower()
    d = (dom or "").lower()
    if isinstance(cfg, dict):
        emails = cfg.get("emails") or {}
        domains = cfg.get("domains") or {}
        if isinstance(emails, dict) and a in emails:
            return str(emails[a])
        if isinstance(domains, dict) and d in domains:
            return str(domains[d])
        for bucket in ("blocked", "deny", "quarantine", "ok", "allow"):
            lst = cfg.get(bucket)
            if isinstance(lst, list):
                ll = [str(x).lower() for x in lst]
                if a in ll or d in ll:
                    return bucket
    return None


def _ddb_get(table: str, key_name: str, key_val: str) -> Optional[Dict[str, Any]]:
    if not (table and key_val):
        return None
    try:
        r = DDB.get_item(TableName=table, Key={key_name: {"S": key_val}})
        return r.get("Item")
    except Exception as e:
        log.warning("DDB get failed %s: %s", table, e)
        return None


def _ddb_put(table: str, item: Dict[str, Any]):
    if not table:
        return
    try:
        DDB.put_item(TableName=table, Item=item)
    except Exception as e:
        log.warning("DDB put failed %s: %s", table, e)


def _expired(item: Dict[str, Any]) -> bool:
    try:
        ttl = int(item.get("ttl", {"N": "0"})["N"])
        return ttl and ttl <= NOW()
    except Exception:
        return False


def http_json(
    url: str, headers: Dict[str, str] = None, params: Dict[str, str] = None
) -> Optional[Any]:
    try:
        r = SESSION.get(
            url,
            headers=headers or {},
            params=params or {},
            timeout=HTTP_TIMEOUT,
        )
        if r.status_code == 200:
            ctype = r.headers.get("content-type", "")
            if "json" in ctype or url.endswith("output=json"):
                return r.json()
            return None
        if r.status_code == 404:
            return {"_status": 404}
    except Exception as e:
        log.info("HTTP fail %s: %s", url, e)
    return None


def crtsh_issuances(domain: str) -> Dict[str, Any]:
    data = http_json(f"https://crt.sh/?q=%25.{domain}&output=json")
    if isinstance(data, list):
        return {"crtsh.count": len(data)}
    if isinstance(data, dict) and data.get("_status") == 404:
        return {"crtsh.count": 0}
    return {"crtsh.count": None}


def securitytxt_present(domain: str) -> Dict[str, Any]:
    for path in ("/.well-known/security.txt", "/security.txt"):
        try:
            r = SESSION.get(f"https://{domain}{path}", timeout=HTTP_TIMEOUT)
            if r.status_code == 200 and r.text:
                return {"securitytxt.present": True}
        except Exception:
            pass
    return {"securitytxt.present": False}


def urlscan_presence(domain: str) -> Dict[str, Any]:
    if not URLSCAN_KEY:
        return {"urlscan.total": None}
    hdr = {"API-Key": URLSCAN_KEY}
    data = http_json(
        "https://urlscan.io/api/v1/search/",
        headers=hdr,
        params={"q": f"domain:{domain}"},
    )
    total = (data or {}).get("total")
    return {"urlscan.total": total if isinstance(total, int) else 0}


def rdap_domain_meta(domain: str) -> Dict[str, Any]:
    data = http_json(f"https://rdap.org/domain/{domain}")
    out: Dict[str, Any] = {"domain.registered_iso": None, "domain.rdap_name": ""}
    try:
        events = data.get("events", []) if isinstance(data, dict) else []
        cr = next(
            (e for e in events if e.get("eventAction") in ("registration", "registered")),
            None,
        )
        out["domain.registered_iso"] = cr.get("eventDate") if cr else None
    except Exception:
        pass
    try:
        entities = (
            data.get("entities", []) if isinstance(data, dict) else []
        )
        for ent in entities:
            v = ent.get("vcardArray")
            if isinstance(v, list) and len(v) == 2 and isinstance(v[1], list):
                for row in v[1]:
                    if (
                        isinstance(row, list)
                        and len(row) >= 4
                        and row[0] == "fn"
                    ):
                        val = row[3]
                        if isinstance(val, str) and val.strip():
                            out["domain.rdap_name"] = val.strip()
                            raise StopIteration
    except StopIteration:
        pass
    except Exception:
        pass
    return out


def abuse_ip(ip: str) -> Dict[str, Any]:
    if not ABUSEIPDB_KEY or not ip:
        return {"abuseipdb.score": None}
    try:
        r = SESSION.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            timeout=HTTP_TIMEOUT,
        )
        if r.status_code == 200:
            j = r.json()
            score = ((j or {}).get("data") or {}).get("abuseConfidenceScore")
            return {
                "abuseipdb.score": int(score) if score is not None else 0
            }
    except Exception:
        pass
    return {"abuseipdb.score": None}


_LI_HREF_RX = re.compile(
    r'href=["\']([^"\']*linkedin\.com/(?:company|school|showcase)/[^"\']*)["\']',
    re.I,
)


def _fetch_html(url: str) -> Optional[str]:
    try:
        r = SESSION.get(url, timeout=HTTP_TIMEOUT, allow_redirects=True)
        if (
            r.status_code == 200
            and "text/html" in (r.headers.get("content-type", ""))
        ):
            return r.text[:300_000]
    except Exception:
        pass
    return None


def linkedin_presence_heuristic(domain: str, budget_left) -> Dict[str, Any]:
    if not domain:
        return {"linkedin.presence": None}
    tests = [
        f"https://{domain}/",
        f"https://www.{domain}/",
        f"https://{domain}/about",
        f"https://{domain}/contact",
        f"https://{domain}/company",
        f"https://{domain}/careers",
    ]
    for u in tests:
        if budget_left() < 0.20:
            break
        html = _fetch_html(u)
        if not html:
            continue
        m = _LI_HREF_RX.search(html)
        if m:
            return {
                "linkedin.presence": True,
                "linkedin.url": m.group(1),
                "linkedin.provider": "homepage_scan",
                "linkedin.query": u,
            }
    return {
        "linkedin.presence": False,
        "linkedin.url": "",
        "linkedin.provider": "homepage_scan",
        "linkedin.query": "",
    }


_ORG_PATTERNS = None
_BRAND_BASES  = None


def _load_org_patterns():
    global _ORG_PATTERNS
    if _ORG_PATTERNS is not None:
        return _ORG_PATTERNS
    _ORG_PATTERNS = []
    if not (CFG_BUCKET and ORG_PATTERNS_KEY):
        return _ORG_PATTERNS
    try:
        cfg = s3_get_json(CFG_BUCKET, ORG_PATTERNS_KEY)
        arr = []
        for org in (cfg.get("orgs") or []) if isinstance(cfg, dict) else []:
            name = (org.get("name") or "").strip()
            domains = [
                str(d).lower().strip()
                for d in (org.get("domains") or [])
                if d
            ]
            rx = org.get("email_regex")
            try:
                email_rx = re.compile(rx, re.I) if rx else None
            except Exception:
                email_rx = None
            arr.append(
                {"name": name, "domains": domains, "email_rx": email_rx}
            )
        _ORG_PATTERNS = arr
    except Exception as e:
        log.info("org_patterns load fail: %s", e)
    return _ORG_PATTERNS


def _load_brand_bases() -> List[str]:
    global _BRAND_BASES
    if _BRAND_BASES is not None:
        return _BRAND_BASES
    _BRAND_BASES = []
    if not (CFG_BUCKET and BRAND_BASES_KEY):
        return _BRAND_BASES
    try:
        cfg = s3_get_json(CFG_BUCKET, BRAND_BASES_KEY)
        if isinstance(cfg, dict) and isinstance(cfg.get("bases"), list):
            _BRAND_BASES = [
                str(x).lower().strip() for x in cfg["bases"] if x
            ]
        elif isinstance(cfg, list):
            _BRAND_BASES = [str(x).lower().strip() for x in cfg if x]
    except Exception as e:
        log.info("brand_bases load fail: %s", e)
    return _BRAND_BASES


def _org_identity_features(
    email: Optional[str], claimed_domain: Optional[str]
) -> Dict[str, Any]:
    feats = {"org.match": None, "org.name": "", "org.reason": ""}
    patterns = _load_org_patterns()
    if not patterns:
        feats["org.reason"] = "no_patterns"
        return feats
    cd = (claimed_domain or "").lower().strip()
    if not cd:
        feats["org.reason"] = "no_domain"
        return feats

    def domain_matches(o_domains: List[str], cd: str) -> bool:
        for d in o_domains:
            if cd == d or cd.endswith("." + d):
                return True
        return False

    cand = next((o for o in patterns if domain_matches(o["domains"], cd)), None)
    if not cand:
        feats["org.match"] = False
        feats["org.reason"] = "domain_not_in_org"
        return feats

    feats["org.name"] = cand["name"]
    em = (email or "").lower()
    if not em:
        feats["org.match"] = False
        feats["org.reason"] = "missing_email"
        return feats

    ok = bool(cand["email_rx"].search(em)) if cand["email_rx"] else any(
        (em.split("@")[-1] == d) or (em.split("@")[-1].endswith("." + d))
        for d in cand["domains"]
    )
    feats["org.match"] = ok
    feats["org.reason"] = "" if ok else "email_regex_fail"
    return feats


_HOMOGLYPHS = {
    "0": "o",
    "o": "0",
    "O": "0",
    "1": "l",
    "l": "1",
    "I": "l",
    "i": "l",
    "5": "s",
    "s": "5",
    "S": "5",
    "8": "b",
    "b": "8",
    "B": "8",
}


def _collapse_bigram_rn(s: str) -> str:
    return s.replace("rn", "m").replace("rN", "m").replace("Rn", "m").replace(
        "RN", "m"
    )


def _norm(s: str) -> str:
    t = _collapse_bigram_rn(s)
    return "".join(_HOMOGLYPHS.get(ch, ch) for ch in t).lower()


def _dl_dist(a: str, b: str) -> int:
    len_a, len_b = len(a), len(b)
    INF = len_a + len_b
    d = [[0] * (len_b + 2) for _ in range(len_a + 2)]
    d[0][0] = INF
    for i in range(len_a + 1):
        d[i + 1][1] = i
        d[i + 1][0] = INF
    for j in range(len_b + 1):
        d[1][j + 1] = j
        d[0][j + 1] = INF
    last: Dict[str, int] = {}
    for i in range(1, len_a + 1):
        db = 0
        for j in range(1, len_b + 1):
            i1 = last.get(b[j - 1], 0)
            j1 = db
            cost = 0 if a[i - 1] == b[j - 1] else 1
            if cost == 0:
                db = j
            d[i + 1][j + 1] = min(
                d[i][j] + cost,
                d[i + 1][j] + 1,
                d[i][j + 1] + 1,
                d[i1][j1] + (i - i1 - 1) + 1 + (j - j1 - 1),
            )
        last[a[i - 1]] = i
    return d[len_a + 1][len_b + 1]


def _etld1(domain: str) -> str:
    parts = (domain or "").lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else (domain or "").lower()


def _candidate_bases_for_typosquat() -> List[str]:
    bases: List[str] = []
    for org in _load_org_patterns():
        bases.extend([_etld1(d) for d in org.get("domains", [])])
    bases.extend([_etld1(b) for b in _load_brand_bases()])
    out: List[str] = []
    seen: set[str] = set()
    for b in bases:
        if b and b not in seen:
            seen.add(b)
            out.append(b)
    return out


def _typosquat_features(candidate_domain: Optional[str]) -> Dict[str, Any]:
    feats = {
        "typosquatting.suspect": False,
        "typosquatting.closest_to": "",
        "typosquatting.reason": "",
    }
    cand = (candidate_domain or "").lower().strip()
    if not cand:
        return feats
    bases = _candidate_bases_for_typosquat()
    if not bases:
        return feats
    cand_etld = _etld1(cand)
    cand_norm = _norm(cand_etld)
    best = (999, "")
    reasons: List[str] = []
    for base_etld in bases:
        base_norm = _norm(base_etld)
        if cand_etld == base_etld:
            continue
        if "xn--" in cand_etld or "xn--" in base_etld:
            reasons.append("punycode_idn")
        if base_norm == cand_norm and base_etld != cand_etld:
            return {
                "typosquatting.suspect": True,
                "typosquatting.closest_to": base_etld,
                "typosquatting.reason": "homoglyph_substitution",
            }
        dist = _dl_dist(base_norm, cand_norm)
        if dist < best[0]:
            best = (dist, base_etld)
    if best[0] <= 1:
        return {
            "typosquatting.suspect": True,
            "typosquatting.closest_to": best[1],
            "typosquatting.reason": "edit_distance<=1",
        }
    if "punycode_idn" in reasons:
        return {
            "typosquatting.suspect": True,
            "typosquatting.closest_to": "",
            "typosquatting.reason": "punycode_idn",
        }
    return feats


def bump_sender_graph(from_addr: Optional[str], domain: Optional[str]):
    if not DDB_GRAPH or not domain:
        return {
            "graph.first_time_domain": None,
            "graph.first_time_addr": None,
            "graph.domain_seen": None,
        }
    try:
        pk = f"dom#{domain}"
        now = str(NOW())
        DDB.update_item(
            TableName=DDB_GRAPH,
            Key={"pk": {"S": pk}, "sk": {"S": "meta"}},
            UpdateExpression=(
                "ADD seen_count :one "
                "SET last_seen=:now, first_seen = if_not_exists(first_seen, :now)"
            ),
            ExpressionAttributeValues={":one": {"N": "1"}, ":now": {"N": now}},
        )
        if from_addr:
            DDB.update_item(
                TableName=DDB_GRAPH,
                Key={"pk": {"S": pk}, "sk": {"S": f"addr#{from_addr}"}},
                UpdateExpression=(
                    "ADD seen_count :one "
                    "SET last_seen=:now, first_seen = if_not_exists(first_seen, :now)"
                ),
                ExpressionAttributeValues={":one": {"N": "1"}, ":now": {"N": now}},
            )
        dom = DDB.get_item(
            TableName=DDB_GRAPH,
            Key={"pk": {"S": pk}, "sk": {"S": "meta"}},
        ).get("Item", {})
        addr = {}
        if from_addr:
            addr = DDB.get_item(
                TableName=DDB_GRAPH,
                Key={"pk": {"S": pk}, "sk": {"S": f"addr#{from_addr}"}},
            ).get("Item", {})
        return {
            "graph.first_time_domain": (
                "first_seen" in dom
                and int(dom["first_seen"]["N"]) == int(dom["last_seen"]["N"])
            ),
            "graph.first_time_addr": (
                "first_seen" in addr
                and int(addr.get("first_seen", {"N": "0"})["N"])
                == int(addr.get("last_seen", {"N": "0"})["N"])
            )
            if addr
            else None,
            "graph.domain_seen": int(dom.get("seen_count", {"N": "0"})["N"])
            if "seen_count" in dom
            else 1,
        }
    except Exception as e:
        log.info("graph error: %s", e)
        return {
            "graph.first_time_domain": None,
            "graph.first_time_addr": None,
            "graph.domain_seen": None,
        }


def risk_score(features: Dict[str, Any]):
    score = 0
    notes: List[str] = []

    s_abuse = features.get("abuseipdb.score")
    if isinstance(s_abuse, int):
        if s_abuse >= 50:
            score += 40
            notes.append("high abuseipdb")
        elif s_abuse > 0:
            score += int(s_abuse / 2)
            notes.append("some abuse reports")

    if features.get("graph.first_time_domain") is True:
        score += 20
        notes.append("first-time domain")
    if features.get("graph.first_time_addr") is True:
        score += 10
        notes.append("first-time address")

    seen = features.get("graph.domain_seen")
    if isinstance(seen, int) and seen >= 10:
        score -= 5
        notes.append("domain seen often")

    if features.get("securitytxt.present") is False:
        score += 5
        notes.append("no security.txt")

    crt = features.get("crtsh.count")
    if isinstance(crt, int) and crt < 5:
        score += 10
        notes.append("few certificates")

    lp = features.get("linkedin.presence")
    if lp is False:
        score += 5
        notes.append("no LinkedIn org page")

    # Org identity mismatch from patterns
    if features.get("org.match") is False:
        if str(features.get("org.reason") or "") in ("email_regex_fail", "missing_email"):
            notes.append("org identity mismatch")
            score += 20

    # New: org roster enrichment (Smile Clinic, vendors, insurers, etc.)
    org_meta = features.get("org")
    if isinstance(org_meta, dict) and org_meta:
        cat = org_meta.get("category")
        trust = org_meta.get("trust_tier")
        company = org_meta.get("company") or org_meta.get("org")
        display_name = org_meta.get("display_name")

        label_parts: List[str] = []
        if isinstance(cat, str) and cat:
            label_parts.append(cat.replace("_", " "))
        if isinstance(company, str) and company:
            label_parts.append(company)

        label = " ".join(label_parts) if label_parts else "contact"
        note = f"Known {label}"
        if display_name:
            note += f": {display_name}"
        if trust:
            note += f" (trust={trust})"
        notes.append(note)
        # For now, org roster is explanatory only; no score delta yet.

    if features.get("typosquatting.suspect") is True:
        notes.append("typosquatting suspected")
        score += 30

    if features.get("whitelist.hit") is True:
        score = 0
        notes.append("whitelisted")

    acct = str(features.get("account.status") or "")
    if acct.lower() in ("blocked", "deny"):
        score = max(score, 90)
        notes.append("account blocked")
    elif acct.lower() in ("allow", "ok"):
        score = min(score, 5)
        notes.append("account ok")

    score = max(0, min(100, score))
    return score, notes


def _yn(v) -> str:
    return "yes" if v is True else ("no" if v is False else "n/a")


def _render_flat_kv(features: Dict[str, Any]) -> str:
    lines: List[str] = []
    rs = features.get("risk.score")
    if isinstance(rs, int):
        lines.append(f"risk: {rs}")

    ty = features.get("typosquatting", {})
    if isinstance(ty, dict):
        lines.append(f"typosquatting: {_yn(ty.get('suspect'))}")
        if ty.get("closest_to"):
            lines.append(f"closest: {ty.get('closest_to')}")

    wl = features.get("whitelist", {})
    lines.append(f"whitelist: {_yn((wl or {}).get('hit'))}")

    if features.get("org.match") is not None:
        lines.append(f"org.match: {_yn(features.get('org.match'))}")
    if features.get("org.name"):
        lines.append(f"org.name: {features.get('org.name')}")

    if features.get("account", {}).get("status") is not None:
        lines.append(
            "account.status: "
            f"{features.get('account').get('status') or features.get('account.status')}"
        )

    lines.append(f"securitytxt: {_yn(features.get('securitytxt.present'))}")
    lines.append(f"list.unsubscribe: {_yn(features.get('list.unsubscribe'))}")
    lines.append(f"mime.has_ics: {_yn(features.get('mime.has_ics'))}")

    if features.get("abuseipdb.score") is not None:
        lines.append(f"abuseipdb: {features.get('abuseipdb.score')}")
    if features.get("linkedin.presence") is not None:
        lines.append(f"linkedin: {_yn(features.get('linkedin.presence'))}")
    if features.get("crtsh.count") is not None:
        lines.append(f"crtsh.count: {features.get('crtsh.count')}")
    if features.get("urlscan.total") is not None:
        lines.append(f"urlscan.total: {features.get('urlscan.total')}")

    if features.get("graph.first_time_domain") is not None:
        lines.append(
            f"first_time_domain: {_yn(features.get('graph.first_time_domain'))}"
        )
    if features.get("graph.first_time_addr") is not None:
        lines.append(
            f"first_time_addr: {_yn(features.get('graph.first_time_addr'))}"
        )
    if isinstance(features.get("graph.domain_seen"), int):
        lines.append(f"domain_seen: {features.get('graph.domain_seen')}")

    return "\n".join(lines)


def _flatten_dict(d, prefix=""):
    for k, v in (d or {}).items():
        key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            yield from _flatten_dict(v, key)
        else:
            yield key, v


def _features_table_md(features: Dict[str, Any]) -> str:
    rows = ["| Check | Value |", "|---|---|"]
    for k, v in _flatten_dict(features):
        try:
            val = json.dumps(v, ensure_ascii=False)
        except Exception:
            val = str(v)
        rows.append(f"| {k} | {val} |")
    return "\n".join(rows)


def _validate_compact_origin(c: Dict[str, Any]) -> Optional[str]:
    if not isinstance(c, dict):
        return "compact must be an object"
    if c.get("provenance") != "controller-mime-extract":
        return "compact missing required provenance 'controller-mime-extract'"
    if not ((c.get("from") or {}).get("addr")):
        return "compact.from.addr missing"
    if not ((c.get("envelope") or {}).get("client_ip")):
        if "envelope" not in c:
            return "compact.envelope missing"
    return None


def handler(event, context):
    t_start = time.time()
    try:
        def time_left() -> float:
            return BUDGET_S - (time.time() - t_start)

        c = _normalize_event_to_compact_obj(event)
        err = _validate_compact_origin(c)
        if err:
            msg = {
                "error": err,
                "hint": "Call 'controller-mime-extract.extractFromMIME' first and pass its 'compact' here.",
            }
            if _is_openapi_event(event):
                return _wrap_openapi_json(event, msg, status_code=400)
            return _wrap_function_response(event, msg)

        from_addr   = (c.get("from") or {}).get("addr")
        from_domain = (from_addr or "@").split("@")[-1] if from_addr else None
        client_ip   = (c.get("envelope") or {}).get("client_ip")

        claimed_org_domain = None
        if isinstance(event.get("sender"), dict):
            claimed_org_domain = event["sender"].get("domain")
        if not claimed_org_domain:
            claimed_org_domain = from_domain

        features: Dict[str, Any] = {}

        # Pattern-based org identity & typosquatting
        features.update(_org_identity_features(from_addr, claimed_org_domain))
        features.update(_typosquat_features(claimed_org_domain))

        # New: org roster enrichment (Smile Clinic + vendors)
        sender_meta = event.get("sender") if isinstance(event.get("sender"), dict) else {}
        sender_email = (sender_meta.get("email") or from_addr or "").lower()
        org_entity = _lookup_org_entity(sender_email)
        if org_entity:
            # Expose as nested org block for the controller & decision agent
            features["org"] = dict(org_entity)

        # Whitelist / account status from cfg
        wl_cfg = acc_cfg = None
        if CFG_BUCKET and time_left() > 0.20:
            if WL_KEY:
                wl_cfg = s3_get_json(CFG_BUCKET, WL_KEY)
            if ACC_KEY:
                acc_cfg = s3_get_json(CFG_BUCKET, ACC_KEY)

        if from_addr or from_domain:
            features["whitelist.hit"] = (
                whitelist_hit(wl_cfg, from_addr, from_domain)
                if wl_cfg is not None
                else None
            )
            st = account_status(acc_cfg, from_addr, from_domain) if acc_cfg is not None else None
            if st is not None:
                features["account.status"] = st

        # Domain-level cache + OSINT
        dom_item = (
            _ddb_get(DDB_DOM, "domain", from_domain)
            if (DDB_DOM and from_domain)
            else None
        )
        if dom_item and _expired(dom_item):
            dom_item = None
        if dom_item:
            for k, v in dom_item.items():
                if k in ("domain", "ttl"):
                    continue
                if "N" in v:
                    try:
                        features[k] = int(v["N"])
                    except Exception:
                        pass
                elif "S" in v:
                    features[k] = v["S"]
                elif "BOOL" in v:
                    features[k] = bool(v["BOOL"])
                elif "NULL" in v and v["NULL"] is True:
                    features[k] = None
            features["cache.domain_hit"] = True
        else:
            features["cache.domain_hit"] = False
            if from_domain and time_left() > 0.15:
                if time_left() > 0.20:
                    features.update(rdap_domain_meta(from_domain))
                if time_left() > 0.20:
                    li = linkedin_presence_heuristic(from_domain, time_left)
                    for k in (
                        "linkedin.presence",
                        "linkedin.url",
                        "linkedin.provider",
                        "linkedin.query",
                    ):
                        if k in li:
                            features[k] = li[k]
                if time_left() > 0.15:
                    features.update(securitytxt_present(from_domain))
                if time_left() > 0.20:
                    features.update(urlscan_presence(from_domain))
                if time_left() > 1.0:
                    features.update(crtsh_issuances(from_domain))

                if DDB_DOM:
                    item: Dict[str, Dict[str, Any]] = {
                        "domain": {"S": from_domain},
                        "ttl": {"N": str(NOW() + DDB_TTL_DOM)},
                        "domain.registered_iso": {
                            "S": str(features.get("domain.registered_iso") or "")
                        },
                        "domain.rdap_name": {
                            "S": str(features.get("domain.rdap_name") or "")
                        },
                        "securitytxt.present": {
                            "BOOL": bool(features.get("securitytxt.present", False))
                        },
                        "urlscan.total": {
                            "N": str(int(features.get("urlscan.total") or 0))
                        },
                    }
                    crt_val = features.get("crtsh.count", None)
                    item["crtsh.count"] = (
                        {"NULL": True}
                        if crt_val is None
                        else {"N": str(int(crt_val))}
                    )
                    lp = features.get("linkedin.presence", None)
                    item["linkedin.presence"] = (
                        {"NULL": True}
                        if lp is None
                        else {"BOOL": bool(lp)}
                    )
                    item["linkedin.url"] = {
                        "S": str(features.get("linkedin.url") or "")
                    }
                    _ddb_put(DDB_DOM, item)

        # IP-level cache + OSINT
        ip_item = (
            _ddb_get(DDB_IP, "ip", client_ip)
            if (DDB_IP and client_ip)
            else None
        )
        if ip_item and _expired(ip_item):
            ip_item = None
        if ip_item:
            if "abuseipdb.score" in ip_item and "N" in ip_item["abuseipdb.score"]:
                features["abuseipdb.score"] = int(
                    ip_item["abuseipdb.score"]["N"]
                )
            features["cache.ip_hit"] = True
        else:
            features["cache.ip_hit"] = False
            if client_ip and time_left() > 0.20:
                f_ip = abuse_ip(client_ip)
                features.update(f_ip)
                if DDB_IP:
                    item = {
                        "ip": {"S": client_ip},
                        "ttl": {"N": str(NOW() + DDB_TTL_IP)},
                    }
                    if f_ip.get("abuseipdb.score") is not None:
                        item["abuseipdb.score"] = {
                            "N": str(int(f_ip["abuseipdb.score"]))
                        }
                    _ddb_put(DDB_IP, item)

        # Sender graph features
        features.update(bump_sender_graph(from_addr, from_domain))

        # Misc flags from compact
        features.update(
            {
                "list.unsubscribe": bool(c.get("list_unsubscribe_present")),
                "mime.has_ics": bool(c.get("has_calendar_ics")),
            }
        )

        ids = {
            "from_addr": from_addr,
            "from_domain": from_domain,
            "claimed_org_domain": claimed_org_domain,
            "message_id": c.get("message_id"),
            "date_iso": c.get("date_iso"),
            "envelope_mail_from": (c.get("envelope") or {}).get("mail_from"),
            "envelope_client_ip": client_ip,
        }

        dt_ms = int((time.time() - t_start) * 1000)
        rscore, rnotes = risk_score(features)

        features_nested = dict(features)
        features_nested["risk"] = {"score": rscore, "notes": rnotes}
        features_nested["risk.score"] = rscore
        if rnotes:
            features_nested["risk.notes"] = rnotes
        features_nested["typosquatting"] = {
            "suspect": bool(features.get("typosquatting.suspect")),
            "closest_to": str(features.get("typosquatting.closest_to") or ""),
            "reason": str(features.get("typosquatting.reason") or ""),
        }
        features_nested["whitelist"] = {"hit": features.get("whitelist.hit")}
        features_nested["account"] = {"status": features.get("account.status")}
        features_nested["osint.elapsed_ms"] = dt_ms

        # Pre-render outputs for the Agent
        flat_kv = _render_flat_kv(features_nested)
        features_nested["flat.kv"] = flat_kv
        table_md = _features_table_md(features_nested)

        # Aliases for agent/frontend
        features_nested["table_md"] = table_md
        features_nested["features_table_md"] = table_md

        log.info(
            "intel: dom=%s ip=%s score=%s elapsed_ms=%s",
            from_domain,
            client_ip,
            rscore,
            dt_ms,
        )

        out = {
            "features": features_nested,
            "ids": ids,
            "flat_kv": flat_kv,
            "table_md": table_md,
            "features_table_md": table_md,
        }

        if _is_openapi_event(event):
            return _wrap_openapi_json(event, out, status_code=200)
        return _wrap_function_response(event, out)

    except Exception:
        log.exception("Unhandled")
        out = {"features": {}, "ids": {}}
        if _is_openapi_event(event):
            return _wrap_openapi_json(event, out, status_code=500)
        return _wrap_function_response(event, out)
