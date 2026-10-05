"""Pocketful Stage 3 Service.
Statements, effective vs recorded time, payment corrections, and immutable snapshot pagination.
"""
import copy
from datetime import datetime, timezone, timedelta
from decimal import Decimal
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import re
import secrets
import threading
from urllib.parse import parse_qs, urlsplit
import uuid


MAX_AMOUNT = 1_000_000_000
MAX_BALANCE = 2 ** 53
LOCK = threading.RLock()
HANDLE = re.compile(r"[a-z0-9_]{1,20}\Z")
STATUSES = ("pending", "paid", "declined", "cancelled")
AUTH_STATUSES = ("open", "captured", "voided", "expired")
RFC3339_REGEX = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\Z")


class APIError(Exception):
    def __init__(self, status, code):
        self.status, self.code = status, code


def fail(status=422, code="validation_failed"):
    raise APIError(status, code)


def require(condition, status=422, code="validation_failed"):
    if not condition:
        fail(status, code)


def parse_instant(val):
    if not isinstance(val, str) or not RFC3339_REGEX.match(val):
        fail(422, "validation_failed")
    try:
        dt = datetime.fromisoformat(val)
        if dt.tzinfo is None:
            fail(422, "validation_failed")
        return dt
    except Exception:
        fail(422, "validation_failed")


def parse_json(raw):
    def bad_constant(_):
        raise ValueError("non-JSON constant")
    return json.loads(raw, parse_float=Decimal, parse_constant=bad_constant)


def encode(value):
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, dict):
        return "{" + ",".join(json.dumps(k) + ":" + encode(v)
                              for k, v in sorted(value.items())) + "}"
    if isinstance(value, list):
        return "[" + ",".join(encode(v) for v in value) + "]"
    return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"))


def json_equal(a, b):
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    if isinstance(a, (int, Decimal)) and isinstance(b, (int, Decimal)):
        return a == b
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(json_equal(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(json_equal(x, y) for x, y in zip(a, b))
    return a == b


def integer(value, low=1, high=MAX_AMOUNT):
    require(not isinstance(value, bool) and isinstance(value, (int, Decimal)))
    require(low <= value <= high and value == int(value))
    return int(value)


def field(body, name, kind=str):
    if name not in body:
        fail()
    if not isinstance(body[name], kind):
        fail(400, "malformed_request")
    return body[name]


def note(body):
    value = body.get("note", "")
    require(isinstance(value, str) and len(value) <= 200)
    return value


def visibility(body):
    value = body.get("visibility", "public")
    require(value in ("public", "private"))
    return value


def now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def identity(prefix):
    return prefix + "_" + uuid.uuid4().hex


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt),
                            n=16384, r=8, p=1).hex()
    return {"algorithm": "scrypt-16384-8-1", "salt": salt, "digest": digest}


def empty_state(currency="EUR", minor_units=2, authorization_ttl_seconds=600):
    return {
        "currency": currency,
        "minor_units": minor_units,
        "authorization_ttl_seconds": authorization_ttl_seconds,
        "users": {},
        "tokens": {},
        "payments": {},
        "requests": {},
        "authorizations": {},
        "retries": {},
        "operators": [],
        "snapshots": {},
        "seeded_total": 0,
        "reset_time": now(),
    }


STATE = empty_state()


def is_expired(auth):
    try:
        exp = datetime.fromisoformat(auth["expires_at"])
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp <= datetime.now(timezone.utc):
            if auth["status"] == "open":
                auth["status"] = "expired"
                auth["remaining_amount"] = 0
                if not auth.get("closed_at"):
                    auth["closed_at"] = auth["expires_at"]
            return True
    except Exception:
        pass
    return False


def get_user_held(user_id):
    held = 0
    for auth in STATE["authorizations"].values():
        if auth["from_user_id"] == user_id and auth["status"] == "open":
            if is_expired(auth):
                continue
            held += auth.get("remaining_amount", 0)
    return held


def resolve_handle(handle):
    for user in STATE["users"].values():
        if user["handle"] == handle:
            return user
    fail(404, "not_found")


def payment(sender, receiver, amount, memo, visible, timestamp=None,
            request_id=None, settlement_id=None, payment_id=None, authorization_id=None,
            refund_of=None):
    t = timestamp or now()
    pid = payment_id or identity("p")
    rev1 = {
        "revision": 1,
        "payment_id": pid,
        "amount": amount,
        "effective_at": t,
        "recorded_at": t,
        "reason": ""
    }
    return {
        "payment_id": pid,
        "from_user_id": sender["id"],
        "from_handle": sender["handle"],
        "to_user_id": receiver["id"],
        "to_handle": receiver["handle"],
        "amount": amount,
        "currency": STATE["currency"],
        "note": memo,
        "visibility": visible,
        "request_id": request_id,
        "settlement_id": settlement_id,
        "authorization_id": authorization_id,
        "refund_of": refund_of,
        "created_at": t,
        "revisions": [rev1]
    }


def money_request(requester, payer, amount, memo, timestamp=None):
    return {
        "request_id": identity("rq"),
        "requester_id": requester["id"],
        "requester_handle": requester["handle"],
        "payer_id": payer["id"],
        "payer_handle": payer["handle"],
        "amount": amount,
        "currency": STATE["currency"],
        "note": memo,
        "status": "pending",
        "payment_id": None,
        "created_at": timestamp or now()
    }


def fixture(body):
    currency = field(body, "currency")
    units = integer(body.get("minor_units"), 0, 3)
    require(units in (0, 2, 3) and bool(currency))
    ttl = body.get("authorization_ttl_seconds", 600)
    require(isinstance(ttl, int) and ttl > 0)

    candidate = empty_state(currency, units, ttl)
    reset_dt = datetime.now(timezone.utc)
    candidate["reset_time"] = reset_dt.isoformat(timespec="microseconds")

    emails, handles = set(), set()
    for raw in field(body, "users", list):
        require(isinstance(raw, dict))
        uid, email, handle = (field(raw, k) for k in ("id", "email", "handle"))
        require(0 < len(uid) <= 64 and uid not in candidate["users"])
        require(email not in emails and handle not in handles and HANDLE.fullmatch(handle))
        user = {
            "id": uid, "email": email, "handle": handle,
            "display_name": field(raw, "display_name"),
            "balance": integer(raw.get("balance"), 0, MAX_BALANCE),
            "opening_balance": 0,
            "password": hash_password(field(raw, "password"))
        }
        candidate["users"][uid] = user
        emails.add(email)
        handles.add(handle)

    candidate["seeded_total"] = sum(u["balance"] for u in candidate["users"].values())
    operators = body.get("settlement_operator_ids", [])
    require(isinstance(operators, list))
    require(all(isinstance(x, str) and x in candidate["users"] for x in operators))
    candidate["operators"] = list(dict.fromkeys(operators))

    net_effects = {uid: 0 for uid in candidate["users"]}

    raw_payments = body.get("payments", [])
    require(isinstance(raw_payments, list))
    for raw in raw_payments:
        require(isinstance(raw, dict))
        pid = field(raw, "id")
        require(0 < len(pid) <= 64 and pid not in candidate["payments"])
        src, dst = field(raw, "from_user_id"), field(raw, "to_user_id")
        require(src in candidate["users"] and dst in candidate["users"])
        sender, receiver = candidate["users"][src], candidate["users"][dst]
        amt = integer(raw.get("amount"), 0)
        
        if "created_at" in raw:
            p_dt = parse_instant(raw["created_at"])
            if p_dt > reset_dt:
                fail(422, "validation_failed")
            p_time = raw["created_at"]
        else:
            p_time = candidate["reset_time"]

        rev1 = {
            "revision": 1,
            "payment_id": pid,
            "amount": amt,
            "effective_at": p_time,
            "recorded_at": p_time,
            "reason": ""
        }
        rec = {
            "payment_id": pid,
            "from_user_id": src,
            "from_handle": sender["handle"],
            "to_user_id": dst,
            "to_handle": receiver["handle"],
            "amount": amt,
            "currency": currency,
            "note": note(raw),
            "visibility": visibility(raw),
            "request_id": raw.get("request_id"),
            "settlement_id": raw.get("settlement_id"),
            "authorization_id": raw.get("authorization_id"),
            "refund_of": raw.get("refund_of"),
            "created_at": p_time,
            "revisions": [rev1]
        }
        candidate["payments"][pid] = rec
        net_effects[src] -= amt
        net_effects[dst] += amt

    for uid, user in candidate["users"].items():
        user["opening_balance"] = user["balance"] - net_effects[uid]
        require(user["opening_balance"] >= 0)

    raw_requests = body.get("requests", [])
    require(isinstance(raw_requests, list))
    for raw in raw_requests:
        require(isinstance(raw, dict))
        rid = field(raw, "id")
        require(0 < len(rid) <= 64 and rid not in candidate["requests"])
        src, dst = field(raw, "requester_id"), field(raw, "payer_id")
        require(src in candidate["users"] and dst in candidate["users"])
        sender, receiver = candidate["users"][src], candidate["users"][dst]
        status = raw.get("status", "pending")
        require(status in STATUSES)
        candidate["requests"][rid] = {
            "request_id": rid,
            "requester_id": src, "requester_handle": sender["handle"],
            "payer_id": dst, "payer_handle": receiver["handle"],
            "amount": integer(raw.get("amount"), 0),
            "currency": currency, "note": note(raw),
            "status": status,
            "payment_id": raw.get("payment_id"),
            "created_at": candidate["reset_time"]
        }

    raw_auths = body.get("authorizations", [])
    require(isinstance(raw_auths, list))
    for raw in raw_auths:
        require(isinstance(raw, dict))
        aid = field(raw, "id")
        require(0 < len(aid) <= 64 and aid not in candidate["authorizations"])
        src, dst = field(raw, "from_user_id"), field(raw, "to_user_id")
        require(src in candidate["users"] and dst in candidate["users"])
        amt = integer(raw.get("amount"), 1)
        stat = raw.get("status", "open")
        require(stat in AUTH_STATUSES)
        exp_at = field(raw, "expires_at")
        require(parse_instant(exp_at) is not None)
        rem = amt if stat == "open" else 0
        created_at = raw.get("created_at", candidate["reset_time"])
        candidate["authorizations"][aid] = {
            "authorization_id": aid,
            "from_user_id": src, "from_handle": candidate["users"][src]["handle"],
            "to_user_id": dst, "to_handle": candidate["users"][dst]["handle"],
            "amount": amt, "captured_amount": 0, "remaining_amount": rem,
            "currency": currency, "note": note(raw), "visibility": visibility(raw),
            "status": stat, "expires_at": exp_at, "payment_id": None,
            "payment_ids": [], "created_at": created_at,
            "closed_at": raw.get("closed_at")
        }

    for uid, user in candidate["users"].items():
        user_held = 0
        for auth in candidate["authorizations"].values():
            if auth["from_user_id"] == uid and auth["status"] == "open":
                exp = parse_instant(auth["expires_at"])
                if exp > reset_dt:
                    user_held += auth["amount"]
        if user_held > user["balance"]:
            fail(422, "validation_failed")

    return candidate


def import_snapshot(body):
    require(body.get("track") == "pocketful")
    v = body.get("format_version")
    require(type(v) is int and v in (1, 2, 3, 4))
    envelope = body.get("state")
    require(isinstance(envelope, dict) and envelope.get("encoding") == "json-v1")
    payload, digest = envelope.get("payload"), envelope.get("sha256")
    require(isinstance(payload, str) and isinstance(digest, str))
    require(hmac.compare_digest(hashlib.sha256(payload.encode()).hexdigest(), digest))
    try:
        candidate = parse_json(payload)
        candidate.setdefault("authorizations", {})
        candidate.setdefault("authorization_ttl_seconds", 600)
        candidate.setdefault("snapshots", {})
        candidate.setdefault("reset_time", now())
        users = candidate["users"]
        emails, handles = set(), set()
        for uid, user in users.items():
            require(isinstance(user, dict) and user["id"] == uid and 0 < len(uid) <= 64)
            require(HANDLE.fullmatch(user["handle"]) and user["handle"] not in handles)
            require(user["email"] not in emails)
            emails.add(user["email"])
            handles.add(user["handle"])
            integer(user["balance"], 0, MAX_BALANCE)
            user.setdefault("opening_balance", user["balance"])
        for p in candidate.get("payments", {}).values():
            p.setdefault("refund_of", None)
            if "revisions" not in p:
                t = p.get("created_at") or candidate["reset_time"]
                p["revisions"] = [{
                    "revision": 1,
                    "payment_id": p["payment_id"],
                    "amount": p["amount"],
                    "effective_at": t,
                    "recorded_at": t,
                    "reason": ""
                }]
        for a in candidate.get("authorizations", {}).values():
            a.setdefault("closed_at", None)
        require(sum(u["balance"] for u in users.values()) == candidate["seeded_total"])
        return candidate
    except Exception:
        fail()


def page(query, records, key):
    def count(name, default, minimum, maximum=None):
        value = query.get(name, [str(default)])[0]
        require(re.fullmatch(r"[0-9]+", value) is not None)
        value = Decimal(value)
        require(value >= minimum and (maximum is None or value <= maximum))
        return int(min(value, len(records) + 201))
    limit, offset = count("limit", 50, 1, 200), count("offset", 0, 0)
    records.sort(key=lambda r: r["created_at"], reverse=True)
    return {key: records[offset:offset + limit], "has_more": offset + limit < len(records)}


def authenticate(headers):
    token = None
    auth = headers.get("Authorization", "")
    parts = auth.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        token = parts[1]
    if not token and "Cookie" in headers:
        cookies = headers.get("Cookie", "").split(";")
        for c in cookies:
            pair = c.strip().split("=")
            if len(pair) == 2 and pair[0] == "token":
                token = pair[1]
                break
    if not token or token not in STATE["tokens"]:
        fail(401, "unauthenticated")
    return STATE["users"][STATE["tokens"][token]]


def auth_endpoint(path, body):
    email, password = field(body, "email"), field(body, "password")
    existing = next((u for u in STATE["users"].values() if u["email"] == email), None)
    if path == "/auth/signup":
        display = field(body, "display_name")
        require(re.fullmatch(r"[^@\s]+@[^@\s]+", email) and len(password) >= 8)
        if existing:
            fail(409, "email_taken")
        handle = re.sub(r"[^a-z0-9_]", "_", email.split("@")[0].lower())[:20]
        if any(u["handle"] == handle for u in STATE["users"].values()):
            fail(409, "handle_taken")
        user = {
            "id": identity("u"), "email": email, "display_name": display,
            "handle": handle, "balance": 0, "opening_balance": 0,
            "password": hash_password(password)
        }
        STATE["users"][user["id"]] = user
        status = 201
    else:
        if not existing:
            fail(401, "unauthenticated")
        actual = hash_password(password, existing["password"]["salt"])
        if not hmac.compare_digest(actual["digest"], existing["password"]["digest"]):
            fail(401, "unauthenticated")
        user, status = existing, 200
    token = secrets.token_urlsafe(32)
    STATE["tokens"][token] = user["id"]
    return status, {"user_id": user["id"], "display_name": user["display_name"], "handle": user["handle"], "token": token}


def get_payment_revision_at(payment_obj, known_at_dt):
    selected = None
    for rev in payment_obj.get("revisions", []):
        r_dt = parse_instant(rev["recorded_at"])
        if known_at_dt is None or r_dt <= known_at_dt:
            if selected is None or rev["revision"] > selected["revision"]:
                selected = rev
    return selected


def compute_historical_balance(user_id, as_of_dt, known_at_dt=None):
    bal = STATE["users"][user_id].get("opening_balance", 0)
    for p in STATE["payments"].values():
        if user_id not in (p["from_user_id"], p["to_user_id"]):
            continue
        rev = get_payment_revision_at(p, known_at_dt)
        if rev is None:
            continue
        eff_dt = parse_instant(rev["effective_at"])
        if as_of_dt is None or eff_dt <= as_of_dt:
            if user_id == p["to_user_id"]:
                bal += rev["amount"]
            if user_id == p["from_user_id"]:
                bal -= rev["amount"]
    return bal


def compute_historical_held(user_id, as_of_dt, known_at_dt=None):
    held = 0
    for auth in STATE["authorizations"].values():
        if auth["from_user_id"] != user_id:
            continue
        c_dt = parse_instant(auth["created_at"])
        if known_at_dt is not None and c_dt > known_at_dt:
            continue
        if as_of_dt is not None and c_dt > as_of_dt:
            continue
        
        amt = auth["amount"]
        captured = 0
        for pid in auth.get("payment_ids", []):
            p = STATE["payments"].get(pid)
            if not p:
                continue
            rev = get_payment_revision_at(p, known_at_dt)
            if rev is None:
                continue
            eff_dt = parse_instant(rev["effective_at"])
            if as_of_dt is None or eff_dt <= as_of_dt:
                captured += rev["amount"]
        
        is_closed = False
        closed_at = auth.get("closed_at")
        if closed_at:
            cl_dt = parse_instant(closed_at)
            is_closed = (as_of_dt is not None and cl_dt <= as_of_dt) or (as_of_dt is None)
        else:
            exp_dt = parse_instant(auth["expires_at"])
            is_closed = (as_of_dt is not None and exp_dt <= as_of_dt) or (as_of_dt is None and exp_dt <= datetime.now(timezone.utc))
        
        if is_closed:
            held += 0
        else:
            rem = max(0, amt - captured)
            held += rem
    return held


def check_boundaries_multi(overrides_dict, target_user_ids):
    instants = set()
    for pid, (new_amt, eff_dt) in overrides_dict.items():
        instants.add(eff_dt)
    for p in STATE["payments"].values():
        rev = get_payment_revision_at(p, None)
        if rev:
            instants.add(parse_instant(rev["effective_at"]))
    for a in STATE["authorizations"].values():
        instants.add(parse_instant(a["created_at"]))
        instants.add(parse_instant(a["expires_at"]))
        if a.get("closed_at"):
            instants.add(parse_instant(a["closed_at"]))

    for t_dt in sorted(instants):
        for uid in target_user_ids:
            bal = STATE["users"][uid].get("opening_balance", 0)
            for p in STATE["payments"].values():
                if uid not in (p["from_user_id"], p["to_user_id"]):
                    continue
                if p["payment_id"] in overrides_dict:
                    amt, eff_dt = overrides_dict[p["payment_id"]]
                else:
                    rev = get_payment_revision_at(p, None)
                    if rev is None:
                        continue
                    amt = rev["amount"]
                    eff_dt = parse_instant(rev["effective_at"])
                if eff_dt <= t_dt:
                    if uid == p["to_user_id"]:
                        bal += amt
                    if uid == p["from_user_id"]:
                        bal -= amt
            
            h = compute_historical_held(uid, t_dt, None)
            if bal < 0 or (bal - h) < 0:
                fail(409, "historical_overdraft")


def check_boundaries_for_correction(payment_id, new_amount, new_effective_dt, target_user_ids):
    check_boundaries_multi({payment_id: (new_amount, new_effective_dt)}, target_user_ids)


def commit_payment(sender, receiver, amount, memo, visible, request_id=None, authorization_id=None):
    available = sender["balance"] - get_user_held(sender["id"])
    if available < amount:
        fail(409, "insufficient_funds")
    require(receiver["balance"] + amount <= MAX_BALANCE)
    receipt = payment(sender, receiver, amount, memo, visible, request_id=request_id, authorization_id=authorization_id)
    sender["balance"] -= amount
    receiver["balance"] += amount
    STATE["payments"][receipt["payment_id"]] = receipt
    return receipt


def write(path, body, user):
    if path in ("/payments", "/requests"):
        amount, memo = integer(body.get("amount")), note(body)
        visible = visibility(body) if path == "/payments" else None
        handle = field(body, "to_handle" if path == "/payments" else "payer_handle")
        other = resolve_handle(handle)
        if other["id"] == user["id"]:
            fail(422, "self_payment" if path == "/payments" else "self_request")
        if path == "/payments":
            return commit_payment(user, other, amount, memo, visible)
        receipt = money_request(user, other, amount, memo)
        STATE["requests"][receipt["request_id"]] = receipt
        return receipt

    if path == "/authorizations":
        amount, memo, visible = integer(body.get("amount")), note(body), visibility(body)
        handle = field(body, "to_handle")
        other = resolve_handle(handle)
        if other["id"] == user["id"]:
            fail(422, "self_payment")
        available = user["balance"] - get_user_held(user["id"])
        if available < amount:
            fail(409, "insufficient_funds")
        ttl = STATE.get("authorization_ttl_seconds", 600)
        exp_at = (datetime.now(timezone.utc) + timedelta(seconds=ttl)).isoformat(timespec="microseconds")
        aid, t = identity("a"), now()
        receipt = {
            "authorization_id": aid,
            "from_user_id": user["id"], "from_handle": user["handle"],
            "to_user_id": other["id"], "to_handle": other["handle"],
            "amount": amount, "captured_amount": 0, "remaining_amount": amount,
            "currency": STATE["currency"], "note": memo, "visibility": visible,
            "status": "open", "expires_at": exp_at, "payment_id": None,
            "payment_ids": [], "created_at": t, "closed_at": None
        }
        STATE["authorizations"][aid] = receipt
        return receipt

    if path == "/splits":
        amount, memo = integer(body.get("amount")), note(body)
        handles = field(body, "participant_handles", list)
        require(len(handles) > 0)
        if not all(isinstance(h, str) for h in handles):
            fail(400, "malformed_request")
        require(len(set(handles)) == len(handles))
        participants = [resolve_handle(h) for h in handles]
        base, extra = divmod(amount, len(handles))
        shares = [{"handle": h, "amount": base + (i < extra)} for i, h in enumerate(handles)]
        timestamp = now()
        requests = [money_request(user, p, share["amount"], memo, timestamp)
                    for p, share in zip(participants, shares) if p["id"] != user["id"]]
        receipt = {
            "split_id": identity("sp"), "amount": amount, "currency": STATE["currency"],
            "note": memo, "shares": shares, "requests": requests, "created_at": timestamp
        }
        for req in requests:
            STATE["requests"][req["request_id"]] = req
        return receipt

    if path == "/settlements":
        transfers = body.get("transfers")
        require(isinstance(transfers, list) and 1 <= len(transfers) <= 32)
        staged, deltas = [], {}
        for transfer in transfers:
            require(isinstance(transfer, dict))
            amount, memo, visible = integer(transfer.get("amount")), note(transfer), visibility(transfer)
            sender = resolve_handle(field(transfer, "from_handle"))
            receiver = resolve_handle(field(transfer, "to_handle"))
            if sender["id"] == receiver["id"]:
                fail(422, "self_payment")
            staged.append((sender, receiver, amount, memo, visible))
            deltas[sender["id"]] = deltas.get(sender["id"], 0) - amount
            deltas[receiver["id"]] = deltas.get(receiver["id"], 0) + amount

        for uid, delta in deltas.items():
            avail = STATE["users"][uid]["balance"] - get_user_held(uid)
            if avail + delta < 0:
                fail(409, "insufficient_funds")

        sid, timestamp = identity("st"), now()
        payments = [payment(*entry, timestamp=timestamp, settlement_id=sid) for entry in staged]
        for uid, delta in deltas.items():
            STATE["users"][uid]["balance"] += delta
        for rec in payments:
            STATE["payments"][rec["payment_id"]] = rec
        return {"settlement_id": sid, "committed_at": timestamp, "payments": payments}

    m_auth = re.fullmatch(r"/authorizations/([^/]+)/(capture|void)", path)
    if m_auth:
        aid, action = m_auth.groups()
        auth = STATE["authorizations"].get(aid)
        if auth is None:
            fail(404, "not_found")
        if action == "void":
            if user["id"] != auth["from_user_id"]:
                fail(403, "forbidden")
            if auth["status"] == "voided":
                return auth
            if auth["status"] in ("captured", "expired") or is_expired(auth):
                fail(409, "authorization_not_open")
            auth["status"] = "voided"
            auth["remaining_amount"] = 0
            auth["closed_at"] = now()
            return auth
        else:  # capture
            if user["id"] != auth["to_user_id"]:
                fail(403, "forbidden")
            if is_expired(auth):
                fail(409, "authorization_expired")
            if auth["status"] != "open":
                fail(409, "authorization_not_open")
            raw_amt = body.get("amount")
            amt = auth["remaining_amount"] if raw_amt is None else integer(raw_amt)
            if amt > auth["remaining_amount"]:
                fail(422, "capture_exceeds_authorization")
            is_final = body.get("final", True)
            require(isinstance(is_final, bool))

            payer = STATE["users"][auth["from_user_id"]]
            receiver = STATE["users"][auth["to_user_id"]]
            payer["balance"] -= amt
            receiver["balance"] += amt
            receipt = payment(payer, receiver, amt, auth["note"], auth["visibility"],
                              authorization_id=aid)
            STATE["payments"][receipt["payment_id"]] = receipt
            auth["captured_amount"] += amt
            auth["remaining_amount"] -= amt
            auth["payment_id"] = receipt["payment_id"]
            auth["payment_ids"].append(receipt["payment_id"])
            if is_final or auth["remaining_amount"] == 0:
                auth["status"] = "captured"
                auth["remaining_amount"] = 0
                auth["closed_at"] = now()
            return receipt

    match = re.fullmatch(r"/requests/([^/]+)/(pay|decline|cancel)", path)
    if match:
        rid, action = match.groups()
        req = STATE["requests"].get(rid)
        if req is None:
            fail(404, "not_found")
        owner = req["requester_id" if action == "cancel" else "payer_id"]
        if user["id"] != owner:
            fail(403, "forbidden")
        if action == "pay":
            visible = visibility(body)
            if req["status"] != "pending":
                fail(409, "request_not_pending")
            receipt = commit_payment(user, STATE["users"][req["requester_id"]],
                                     req["amount"], req["note"], visible, request_id=rid)
            req.update(status="paid", payment_id=receipt["payment_id"])
            return receipt
        target = "cancelled" if action == "cancel" else "declined"
        if req["status"] not in ("pending", target):
            fail(409, "request_not_pending")
        req["status"] = target
        return req

    m_corr = re.fullmatch(r"/payments/([^/]+)/corrections", path)
    if m_corr:
        pid = m_corr.group(1)
        p = STATE["payments"].get(pid)
        if not p:
            fail(404, "not_found")
        if user["id"] != p["from_user_id"]:
            fail(403, "forbidden")
        if p.get("settlement_id") or p.get("authorization_id") or p.get("refund_of"):
            fail(422, "linked_payment_immutable")

        exp_rev = body.get("expected_revision")
        require(isinstance(exp_rev, int) and not isinstance(exp_rev, bool) and exp_rev > 0)
        curr_rev = len(p["revisions"])
        if exp_rev != curr_rev:
            fail(409, "stale_revision")

        new_amt = integer(body.get("amount"), 0, MAX_AMOUNT)
        total_refunded = sum(r["amount"] for r in STATE["payments"].values() if r.get("refund_of") == pid)
        if new_amt < total_refunded:
            fail(422, "refund_exceeds_payment")
        reason = field(body, "reason")
        require(isinstance(reason, str) and 1 <= len(reason) <= 200)

        eff_str = field(body, "effective_at")
        eff_dt = parse_instant(eff_str)
        now_dt = datetime.now(timezone.utc)
        if eff_dt > now_dt:
            fail(422, "validation_failed")

        sender = STATE["users"][p["from_user_id"]]
        receiver = STATE["users"][p["to_user_id"]]
        prev_amt = p["revisions"][-1]["amount"]
        diff = new_amt - prev_amt

        if diff > 0:
            avail = sender["balance"] - get_user_held(sender["id"])
            if avail < diff:
                fail(409, "insufficient_funds")
        elif diff < 0:
            avail = receiver["balance"] - get_user_held(receiver["id"])
            if avail < (-diff):
                fail(409, "insufficient_funds")

        check_boundaries_for_correction(pid, new_amt, eff_dt, (sender["id"], receiver["id"]))

        if diff > 0:
            sender["balance"] -= diff
            receiver["balance"] += diff
        elif diff < 0:
            sender["balance"] += (-diff)
            receiver["balance"] -= (-diff)

        p["amount"] = new_amt
        rec_str = now()
        new_rev_num = curr_rev + 1
        rev_entry = {
            "payment_id": pid,
            "revision": new_rev_num,
            "amount": new_amt,
            "effective_at": eff_str,
            "recorded_at": rec_str,
            "reason": reason
        }
        p["revisions"].append(rev_entry)
        return rev_entry

    m_ref = re.fullmatch(r"/payments/([^/]+)/refunds", path)
    if m_ref:
        pid = m_ref.group(1)
        p = STATE["payments"].get(pid)
        if not p:
            fail(404, "not_found")
        if user["id"] != p["to_user_id"]:
            fail(403, "forbidden")
        if p.get("refund_of") is not None:
            fail(422, "invalid_refund_target")
        refund_amt = integer(body.get("amount"), 1, MAX_AMOUNT)
        curr_corrected_amt = p["revisions"][-1]["amount"]
        already_refunded = sum(r["amount"] for r in STATE["payments"].values() if r.get("refund_of") == pid)
        if already_refunded + refund_amt > curr_corrected_amt:
            fail(422, "refund_exceeds_payment")
        original_sender = STATE["users"][p["from_user_id"]]
        avail = user["balance"] - get_user_held(user["id"])
        if avail < refund_amt:
            fail(409, "insufficient_funds")
        require(original_sender["balance"] + refund_amt <= MAX_BALANCE)
        user["balance"] -= refund_amt
        original_sender["balance"] += refund_amt
        t = now()
        receipt = payment(user, original_sender, refund_amt, p.get("note", ""), p.get("visibility", "public"),
                          timestamp=t, refund_of=pid)
        STATE["payments"][receipt["payment_id"]] = receipt
        return receipt

    if path == "/correction-batches":
        if user["id"] not in STATE["operators"]:
            fail(403, "forbidden")
        corrs = body.get("corrections")
        require(isinstance(corrs, list) and 1 <= len(corrs) <= 32)
        pids = [c.get("payment_id") for c in corrs if isinstance(c, dict)]
        require(len(pids) == len(corrs) and len(set(pids)) == len(pids))
        now_dt = datetime.now(timezone.utc)
        parsed_items = []
        for item in corrs:
            require(isinstance(item, dict))
            pid = field(item, "payment_id")
            p = STATE["payments"].get(pid)
            if not p:
                fail(404, "not_found")
            exp_rev = item.get("expected_revision")
            require(isinstance(exp_rev, int) and not isinstance(exp_rev, bool) and exp_rev > 0)
            if exp_rev != len(p["revisions"]):
                fail(409, "stale_revision")
            if p.get("authorization_id") or p.get("refund_of"):
                fail(422, "linked_payment_immutable")
            amt = integer(item.get("amount"), 0, MAX_AMOUNT)
            reason = field(item, "reason")
            require(isinstance(reason, str) and 1 <= len(reason) <= 200)
            eff_str = field(item, "effective_at")
            eff_dt = parse_instant(eff_str)
            if eff_dt > now_dt:
                fail(422, "validation_failed")
            already_refunded = sum(r["amount"] for r in STATE["payments"].values() if r.get("refund_of") == pid)
            if amt < already_refunded:
                fail(422, "refund_exceeds_payment")
            parsed_items.append({
                "payment_id": pid,
                "payment": p,
                "expected_revision": exp_rev,
                "amount": amt,
                "reason": reason,
                "effective_at_str": eff_str,
                "effective_at_dt": eff_dt
            })

        settlements_involved = {}
        for it in parsed_items:
            sid = it["payment"].get("settlement_id")
            if sid:
                settlements_involved.setdefault(sid, []).append(it)

        for sid, items_in_batch in settlements_involved.items():
            all_members = [p for p in STATE["payments"].values() if p.get("settlement_id") == sid]
            if len(items_in_batch) != len(all_members):
                fail(422, "incomplete_settlement")
            first_eff = items_in_batch[0]["effective_at_dt"]
            for member_item in items_in_batch:
                if member_item["effective_at_dt"] != first_eff:
                    fail(422, "validation_failed")

        deltas = {}
        overrides = {}
        target_user_ids = set()
        for it in parsed_items:
            p = it["payment"]
            prev_amt = p["revisions"][-1]["amount"]
            diff = it["amount"] - prev_amt
            src_id = p["from_user_id"]
            dst_id = p["to_user_id"]
            deltas[src_id] = deltas.get(src_id, 0) - diff
            deltas[dst_id] = deltas.get(dst_id, 0) + diff
            overrides[it["payment_id"]] = (it["amount"], it["effective_at_dt"])
            target_user_ids.add(src_id)
            target_user_ids.add(dst_id)

        for uid, delta in deltas.items():
            avail = STATE["users"][uid]["balance"] - get_user_held(uid)
            if avail + delta < 0:
                fail(409, "insufficient_funds")

        check_boundaries_multi(overrides, target_user_ids)

        for uid, delta in deltas.items():
            STATE["users"][uid]["balance"] += delta

        rec_str = now()
        batch_id = identity("cb")
        rev_list = []
        for it in parsed_items:
            p = it["payment"]
            p["amount"] = it["amount"]
            new_rev_num = len(p["revisions"]) + 1
            rev_entry = {
                "payment_id": it["payment_id"],
                "revision": new_rev_num,
                "amount": it["amount"],
                "effective_at": it["effective_at_str"],
                "recorded_at": rec_str,
                "reason": it["reason"],
                "correction_batch_id": batch_id
            }
            p["revisions"].append(rev_entry)
            rev_list.append(rev_entry)

        return {
            "correction_batch_id": batch_id,
            "recorded_at": rec_str,
            "revisions": rev_list
        }

    fail(404, "not_found")


def build_statement_entries(user_id, from_dt, to_dt, known_at_dt):
    selected_payments = []
    for p in STATE["payments"].values():
        if user_id not in (p["from_user_id"], p["to_user_id"]):
            continue
        rev = get_payment_revision_at(p, known_at_dt)
        if rev is None:
            continue
        selected_payments.append((p, rev))

    def sort_key(item):
        p, rev = item
        return (parse_instant(rev["effective_at"]), p["payment_id"])

    selected_payments.sort(key=sort_key)

    opening = STATE["users"][user_id].get("opening_balance", 0)
    for p, rev in selected_payments:
        eff_dt = parse_instant(rev["effective_at"])
        if from_dt is not None and eff_dt < from_dt:
            if user_id == p["to_user_id"]:
                opening += rev["amount"]
            if user_id == p["from_user_id"]:
                opening -= rev["amount"]

    running = opening
    entries = []
    for p, rev in selected_payments:
        eff_dt = parse_instant(rev["effective_at"])
        if from_dt is not None and eff_dt < from_dt:
            continue
        if to_dt is not None and eff_dt >= to_dt:
            continue
        
        amt = rev["amount"]
        if user_id == p["to_user_id"] and user_id == p["from_user_id"]:
            delta = 0
        elif user_id == p["to_user_id"]:
            delta = amt
        else:
            delta = -amt
        
        running += delta
        p_copy = copy.deepcopy(p)
        p_copy["amount"] = amt
        entries.append({
            "payment": p_copy,
            "delta": delta,
            "balance_after": running,
            "revision": rev["revision"],
            "effective_at": rev["effective_at"],
            "recorded_at": rev["recorded_at"]
        })

    closing = running
    return opening, entries, closing


def dispatch(method, path, query, headers, body):
    global STATE
    if method == "GET" and path == "/health":
        return 200, {"status": "ok"}
    if method == "POST" and path == "/_test/reset":
        STATE = fixture(body)
        return 204, None
    if method == "POST" and path == "/_test/import":
        STATE = import_snapshot(body)
        return 204, None
    if method == "GET" and path == "/_test/export":
        payload = encode(STATE)
        return 200, {
            "track": "pocketful", "format_version": 4,
            "state": {"encoding": "json-v1", "payload": payload,
                      "sha256": hashlib.sha256(payload.encode()).hexdigest()}
        }
    if method == "POST" and path in ("/auth/signup", "/auth/login"):
        return auth_endpoint(path, body)

    user = authenticate(headers)
    if method == "GET":
        if path == "/me":
            as_of_str = query.get("as_of", [None])[0]
            known_at_str = query.get("known_at", [None])[0]
            as_of_dt = parse_instant(as_of_str) if as_of_str is not None else None
            known_at_dt = parse_instant(known_at_str) if known_at_str is not None else None

            tot = compute_historical_balance(user["id"], as_of_dt, known_at_dt)
            h = compute_historical_held(user["id"], as_of_dt, known_at_dt)
            avail = tot - h
            res = {
                "user_id": user["id"], "display_name": user["display_name"],
                "handle": user["handle"], "balance": tot, "total": tot,
                "available": avail, "held": h, "currency": STATE["currency"],
                "minor_units": STATE["minor_units"]
            }
            if as_of_str is not None:
                res["as_of"] = as_of_str
            if known_at_str is not None:
                res["known_at"] = known_at_str
            return 200, res

        if path == "/statement":
            snap_token = query.get("snapshot", [None])[0]
            if snap_token is not None:
                if any(k in query for k in ("from", "to", "known_at")):
                    fail(422, "validation_failed")
                snap = STATE["snapshots"].get(snap_token)
                if snap is None or snap["user_id"] != user["id"]:
                    fail(404, "not_found")
                
                def get_count(name, default, minimum, maximum=None):
                    val = query.get(name, [str(default)])[0]
                    require(re.fullmatch(r"[0-9]+", val) is not None)
                    v_int = int(val)
                    require(v_int >= minimum and (maximum is None or v_int <= maximum))
                    return v_int

                limit = get_count("limit", 50, 1, 200)
                offset = get_count("offset", 0, 0)
                all_entries = snap["entries"]
                page_entries = all_entries[offset:offset + limit]
                has_more = (offset + limit) < len(all_entries)
                return 200, {
                    "opening_balance": snap["opening_balance"],
                    "entries": page_entries,
                    "closing_balance": snap["closing_balance"],
                    "has_more": has_more,
                    "snapshot": snap_token
                }
            else:
                from_str = query.get("from", [None])[0]
                to_str = query.get("to", [None])[0]
                known_at_str = query.get("known_at", [None])[0]
                from_dt = parse_instant(from_str) if from_str is not None else None
                to_dt = parse_instant(to_str) if to_str is not None else datetime.now(timezone.utc)
                known_at_dt = parse_instant(known_at_str) if known_at_str is not None else None

                opening, all_entries, closing = build_statement_entries(user["id"], from_dt, to_dt, known_at_dt)
                snap_id = identity("sn")
                STATE["snapshots"][snap_id] = {
                    "snapshot_id": snap_id,
                    "user_id": user["id"],
                    "opening_balance": opening,
                    "closing_balance": closing,
                    "entries": all_entries
                }

                def get_count(name, default, minimum, maximum=None):
                    val = query.get(name, [str(default)])[0]
                    require(re.fullmatch(r"[0-9]+", val) is not None)
                    v_int = int(val)
                    require(v_int >= minimum and (maximum is None or v_int <= maximum))
                    return v_int

                limit = get_count("limit", 50, 1, 200)
                offset = get_count("offset", 0, 0)
                page_entries = all_entries[offset:offset + limit]
                has_more = (offset + limit) < len(all_entries)
                return 200, {
                    "opening_balance": opening,
                    "entries": page_entries,
                    "closing_balance": closing,
                    "has_more": has_more,
                    "snapshot": snap_id
                }

        m_rev = re.fullmatch(r"/payments/([^/]+)/revisions", path)
        if m_rev:
            pid = m_rev.group(1)
            p = STATE["payments"].get(pid)
            if not p:
                fail(404, "not_found")
            if user["id"] not in (p["from_user_id"], p["to_user_id"]):
                fail(404, "not_found")
            return 200, {"revisions": copy.deepcopy(p.get("revisions", []))}

        if path == "/activity":
            visible = [p for p in STATE["payments"].values()
                       if p["visibility"] == "public" or user["id"] in (p["from_user_id"], p["to_user_id"])]
            return 200, page(query, visible, "payments")
        if path == "/requests":
            direction, status = query.get("direction", [None])[0], query.get("status", [None])[0]
            require(direction in (None, "incoming", "outgoing") and status in (None,) + STATUSES)
            records = [r for r in STATE["requests"].values()
                       if ((direction != "incoming" and r["requester_id"] == user["id"])
                           or (direction != "outgoing" and r["payer_id"] == user["id"]))
                       and (status is None or r["status"] == status)]
            return 200, page(query, records, "requests")
        if path == "/authorizations":
            for a in STATE["authorizations"].values():
                is_expired(a)
            direction, status = query.get("direction", [None])[0], query.get("status", [None])[0]
            require(direction in (None, "incoming", "outgoing") and status in (None,) + AUTH_STATUSES)
            records = [a for a in STATE["authorizations"].values()
                       if ((direction != "incoming" and a["from_user_id"] == user["id"])
                           or (direction != "outgoing" and a["to_user_id"] == user["id"]))
                       and (status is None or a["status"] == status)]
            return 200, page(query, records, "authorizations")
        fail(404, "not_found")

    if method != "POST":
        fail(404, "not_found")
    if path == "/settlements" and user["id"] not in STATE["operators"]:
        fail(403, "forbidden")

    idempotent = (
        path in ("/payments", "/requests", "/authorizations", "/splits", "/settlements", "/correction-batches")
        or bool(re.fullmatch(r"/requests/[^/]+/pay", path))
        or bool(re.fullmatch(r"/authorizations/[^/]+/capture", path))
        or bool(re.fullmatch(r"/payments/[^/]+/corrections", path))
        or bool(re.fullmatch(r"/payments/[^/]+/refunds", path))
    )
    if not idempotent:
        return 200, write(path, body, user)

    key = headers.get("Idempotency-Key", "")
    if not key:
        fail(400, "missing_idempotency_key")
    require(len(key) <= 255)
    scope = encode([user["id"], method, path, key])
    previous = STATE["retries"].get(scope)
    if previous is not None:
        if not json_equal(previous["body"], body):
            fail(409, "idempotency_key_reuse")
        return 200, previous["response"]

    receipt = write(path, body, user)
    STATE["retries"][scope] = {"body": copy.deepcopy(body), "response": copy.deepcopy(receipt)}
    return 201, receipt


HTML_APP = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Pocketful</title>
  <style>
    :root { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f8fafc; color: #0f172a; }
    * { box-sizing: border-box; }
    body { margin: 0; padding: 16px; display: flex; justify-content: center; }
    .container { width: 100%; max-width: 600px; background: #fff; padding: 24px; border-radius: 12px; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1); }
    header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #e2e8f0; padding-bottom: 12px; margin-bottom: 20px; }
    nav a { margin-right: 12px; color: #3b82f6; text-decoration: none; font-weight: 500; }
    nav a:hover { text-decoration: underline; }
    .card { background: #f1f5f9; padding: 16px; border-radius: 8px; margin-bottom: 20px; }
    .headline { font-size: 28px; font-weight: 700; color: #1e293b; margin: 4px 0; }
    .secondary-balance { font-size: 14px; color: #64748b; }
    .form-group { margin-bottom: 12px; }
    label { display: block; font-size: 14px; font-weight: 600; margin-bottom: 4px; color: #475569; }
    input, select { width: 100%; padding: 10px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 15px; }
    button { padding: 10px 16px; border: none; border-radius: 6px; background: #2563eb; color: #fff; font-weight: 600; cursor: pointer; }
    button:hover { background: #1d4ed8; }
    .btn-secondary { background: #64748b; }
    .btn-secondary:hover { background: #475569; }
    .error-box { background: #fee2e2; border: 1px solid #ef4444; color: #b91c1c; padding: 8px 12px; border-radius: 6px; font-size: 14px; margin-top: 8px; }
    .uncertain-box { background: #fef3c7; border: 1px solid #f59e0b; color: #b45309; padding: 8px 12px; border-radius: 6px; font-size: 14px; margin-top: 8px; }
    .item { border-bottom: 1px solid #e2e8f0; padding: 12px 0; display: flex; justify-content: space-between; align-items: center; }
    .item:last-child { border-bottom: none; }
    .empty-msg { text-align: center; color: #94a3b8; padding: 24px 0; }
  </style>
</head>
<body>
<div class="container">
  <div id="auth-header-container"></div>
  <div id="view-container"></div>
</div>

<script>
let currentUser = null;
let currentMe = null;
let lastPayKey = null;
let lastPayPayload = null;

function fmtMoney(minor, units, cur) {
  if (units === 0) return `${minor} ${cur}`;
  const s = String(minor).padStart(units + 1, "0");
  return `${s.slice(0, -units)}.${s.slice(-units)} ${cur}`;
}

function parseDecimal(str, units) {
  if (!str || typeof str !== "string") return null;
  const s = str.trim();
  if (units === 0) {
    if (!/^\d+$/.test(s)) return null;
    return parseInt(s, 10);
  }
  const parts = s.split(".");
  if (parts.length > 2) return null;
  if (!/^\d+$/.test(parts[0])) return null;
  if (parts.length === 1) return parseInt(parts[0], 10) * Math.pow(10, units);
  if (!/^\d+$/.test(parts[1]) || parts[1].length > units) return null;
  const d = parts[1].padEnd(units, "0");
  return parseInt(parts[0], 10) * Math.pow(10, units) + parseInt(d, 10);
}

function newKey() {
  return "k_" + Math.random().toString(36).substring(2) + Date.now();
}

function showError(parentId, testId, msg) {
  clearError(testId);
  const p = document.getElementById(parentId);
  if (!p) return;
  const el = document.createElement("div");
  el.className = "error-box";
  el.setAttribute("data-testid", testId);
  el.textContent = msg;
  p.appendChild(el);
}

function showUncertain(parentId, testId, msg) {
  clearError(testId);
  const p = document.getElementById(parentId);
  if (!p) return;
  const el = document.createElement("div");
  el.className = "uncertain-box";
  el.setAttribute("data-testid", testId);
  el.textContent = msg;
  p.appendChild(el);
}

function clearError(testId) {
  document.querySelectorAll(`[data-testid='${testId}']`).forEach(el => el.remove());
}

function dirtyPay() {
  lastPayKey = null;
  lastPayPayload = null;
  clearError("pay-error");
  clearError("pay-uncertain");
}

function getStoredToken() {
  let match = document.cookie.match(new RegExp('(^| )token=([^;]+)'));
  if (match) return match[2];
  return localStorage.getItem("pocketful_token");
}

function setStoredToken(tok) {
  if (tok) {
    localStorage.setItem("pocketful_token", tok);
    document.cookie = `token=${tok}; path=/; SameSite=Lax`;
  } else {
    localStorage.removeItem("pocketful_token");
    document.cookie = "token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 UTC;";
  }
}

async function api(path, opts = {}) {
  const tok = getStoredToken();
  const headers = Object.assign({}, opts.headers || {});
  if (tok) headers["Authorization"] = "Bearer " + tok;
  if (opts.body && typeof opts.body === "object" && !(opts.body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(opts.body);
  }
  opts.headers = headers;
  return fetch(path, opts);
}

function renderAuthHeader() {
  const c = document.getElementById("auth-header-container");
  if (!currentUser) {
    c.innerHTML = "";
    return;
  }
  c.innerHTML = `
    <header>
      <div>
        <span data-testid="current-user" style="font-weight:600;">${currentUser.display_name}</span>
        <span data-testid="current-handle" style="margin-left:6px; color:#64748b; font-size:14px;">${currentUser.handle}</span>
      </div>
      <div>
        <button data-testid="logout-button" id="btn-logout" class="btn-secondary" style="padding:6px 12px; font-size:13px;" onclick="handleLogout()">Logout</button>
      </div>
    </header>
    <nav style="margin-bottom:16px;">
      <a href="/" onclick="nav(event, '/')">Home</a>
      <a href="/requests" onclick="nav(event, '/requests')">Requests</a>
      <a href="/split" onclick="nav(event, '/split')">Split</a>
      <a href="/authorizations" onclick="nav(event, '/authorizations')">Holds</a>
    </nav>
  `;
}

function handleLogout() {
  setStoredToken(null);
  currentUser = null;
  currentMe = null;
  renderAuthHeader();
  window.history.replaceState({}, "", "/login");
  renderLoginView();
}

function nav(e, route) {
  if (e) e.preventDefault();
  window.history.pushState({}, "", route);
  routeView();
}

window.onpopstate = () => routeView();

async function routeView() {
  const path = window.location.pathname;
  if (path === "/login") { renderLoginView(); return; }
  if (path === "/signup") { renderSignupView(); return; }

  const tok = getStoredToken();
  if (!tok) {
    window.history.replaceState({}, "", "/login");
    renderLoginView();
    return;
  }

  try {
    const res = await api("/me");
    if (!res.ok) throw new Error("unauth");
    currentMe = await res.json();
    currentUser = { id: currentMe.user_id, display_name: currentMe.display_name, handle: currentMe.handle };
  } catch (err) {
    setStoredToken(null);
    currentUser = null;
    currentMe = null;
    renderAuthHeader();
    window.history.replaceState({}, "", "/login");
    renderLoginView();
    return;
  }

  renderAuthHeader();
  if (path === "/requests") {
    renderRequestsView();
  } else if (path === "/split") {
    renderSplitView();
  } else if (path === "/authorizations") {
    renderAuthorizationsView();
  } else {
    renderHomeView();
  }
}

function renderLoginView() {
  renderAuthHeader();
  const c = document.getElementById("view-container");
  c.innerHTML = `
    <h2>Log in to Pocketful</h2>
    <form id="form-login" onsubmit="handleLoginSubmit(event)">
      <div class="form-group">
        <label>Email</label>
        <input type="email" data-testid="login-email" id="login-email" required>
      </div>
      <div class="form-group">
        <label>Password</label>
        <input type="password" data-testid="login-password" id="login-password" required>
      </div>
      <button type="submit" data-testid="login-submit">Log in</button>
      <div id="err-login-anchor"></div>
    </form>
    <p style="margin-top:16px; font-size:14px;">Don't have an account? <a href="/signup" onclick="nav(event, '/signup')">Sign up</a></p>
  `;
}

async function handleLoginSubmit(e) {
  e.preventDefault();
  clearError("auth-error");
  const email = document.getElementById("login-email").value;
  const password = document.getElementById("login-password").value;
  const res = await api("/auth/login", { method: "POST", body: { email, password } });
  if (res.ok) {
    const data = await res.json();
    setStoredToken(data.token);
    currentUser = { id: data.user_id, display_name: data.display_name, handle: data.handle };
    renderAuthHeader();
    nav(null, "/");
  } else {
    showError("err-login-anchor", "auth-error", "Invalid credentials");
  }
}

function renderSignupView() {
  renderAuthHeader();
  const c = document.getElementById("view-container");
  c.innerHTML = `
    <h2>Create account</h2>
    <form id="form-signup" onsubmit="handleSignupSubmit(event)">
      <div class="form-group">
        <label>Display Name</label>
        <input type="text" data-testid="signup-display-name" id="signup-display-name" required>
      </div>
      <div class="form-group">
        <label>Email</label>
        <input type="email" data-testid="signup-email" id="signup-email" required>
      </div>
      <div class="form-group">
        <label>Password</label>
        <input type="password" data-testid="signup-password" id="signup-password" minlength="8" required>
      </div>
      <button type="submit" data-testid="signup-submit">Sign up</button>
      <div id="err-signup-anchor"></div>
    </form>
    <p style="margin-top:16px; font-size:14px;">Already have an account? <a href="/login" onclick="nav(event, '/login')">Log in</a></p>
  `;
}

async function handleSignupSubmit(e) {
  e.preventDefault();
  clearError("auth-error");
  const display_name = document.getElementById("signup-display-name").value;
  const email = document.getElementById("signup-email").value;
  const password = document.getElementById("signup-password").value;
  const res = await api("/auth/signup", { method: "POST", body: { display_name, email, password } });
  if (res.ok) {
    const data = await res.json();
    setStoredToken(data.token);
    currentUser = { id: data.user_id, display_name: data.display_name, handle: data.handle };
    renderAuthHeader();
    nav(null, "/");
  } else {
    showError("err-signup-anchor", "auth-error", "Sign up failed");
  }
}

function renderHomeView() {
  const c = document.getElementById("view-container");
  c.innerHTML = `
    <div class="card">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <span style="font-size:14px; font-weight:600; color:#475569;">Available to spend</span>
        <button data-testid="wallet-refresh" onclick="refreshDashboard()" class="btn-secondary" style="padding:4px 10px; font-size:12px;">Refresh</button>
      </div>
      <div class="headline" data-testid="wallet-available" id="txt-available" data-amount="${currentMe.available}">${fmtMoney(currentMe.available, currentMe.minor_units, currentMe.currency)}</div>
      <div class="secondary-balance">
        Total balance: <span data-testid="wallet-balance" id="txt-balance" data-amount="${currentMe.balance}">${fmtMoney(currentMe.balance, currentMe.minor_units, currentMe.currency)}</span>
        <span id="wrap-held"></span>
      </div>
    </div>

    <h3>Pay Someone</h3>
    <form id="form-pay" onsubmit="handlePaySubmit(event)" class="card" style="background:#fff; border:1px solid #e2e8f0;">
      <div class="form-group">
        <label>Recipient Handle</label>
        <input type="text" data-testid="pay-handle" id="pay-handle" required oninput="dirtyPay()">
      </div>
      <div class="form-group">
        <label>Amount</label>
        <input type="text" data-testid="pay-amount" id="pay-amount" required oninput="dirtyPay()">
      </div>
      <div class="form-group">
        <label>Note</label>
        <input type="text" data-testid="pay-note" id="pay-note" oninput="dirtyPay()">
      </div>
      <div class="form-group">
        <label>Visibility</label>
        <select data-testid="pay-visibility" id="pay-visibility" onchange="dirtyPay()">
          <option value="public">public</option>
          <option value="private">private</option>
        </select>
      </div>
      <button type="submit" data-testid="pay-submit">Send Payment</button>
      <div id="err-pay-anchor"></div>
    </form>

    <h3>Request Money</h3>
    <form id="form-req" onsubmit="handleRequestSubmit(event)" class="card" style="background:#fff; border:1px solid #e2e8f0;">
      <div class="form-group">
        <label>Payer Handle</label>
        <input type="text" data-testid="request-handle" id="req-handle" required>
      </div>
      <div class="form-group">
        <label>Amount</label>
        <input type="text" data-testid="request-amount" id="req-amount" required>
      </div>
      <div class="form-group">
        <label>Note</label>
        <input type="text" data-testid="request-note" id="req-note">
      </div>
      <button type="submit" data-testid="request-submit">Request</button>
      <div id="err-req-anchor"></div>
    </form>

    <h3>Activity Feed</h3>
    <div id="feed-container"></div>
  `;
  updateHeldDisplay();
  refreshDashboard();
}

function updateHeldDisplay() {
  const wrap = document.getElementById("wrap-held");
  if (!wrap) return;
  if (currentMe && currentMe.held > 0) {
    wrap.innerHTML = ` <span style="margin-left:10px;">Held: <span data-testid="wallet-held" data-amount="${currentMe.held}">${fmtMoney(currentMe.held, currentMe.minor_units, currentMe.currency)}</span></span>`;
  } else {
    wrap.innerHTML = "";
  }
}

async function refreshDashboard() {
  if (!currentMe) return;
  const meRes = await api("/me");
  if (meRes.ok) {
    currentMe = await meRes.json();
    const cur = currentMe.currency, u = currentMe.minor_units;
    const txtBal = document.getElementById("txt-balance");
    if (txtBal) {
      txtBal.textContent = fmtMoney(currentMe.balance, u, cur);
      txtBal.setAttribute("data-amount", String(currentMe.balance));
    }
    const txtAvail = document.getElementById("txt-available");
    if (txtAvail) {
      txtAvail.textContent = fmtMoney(currentMe.available, u, cur);
      txtAvail.setAttribute("data-amount", String(currentMe.available));
    }
    updateHeldDisplay();
  }

  const actRes = await api("/activity?limit=50");
  if (actRes.ok) {
    const actData = await actRes.json();
    renderActivityFeed(actData.payments || []);
  }
}

function renderActivityFeed(payments) {
  const c = document.getElementById("feed-container");
  if (!c) return;
  c.innerHTML = "";
  if (!payments || payments.length === 0) {
    c.innerHTML = `<div class="empty-msg" data-testid="empty-activity">No activity yet</div>`;
    return;
  }
  const list = document.createElement("div");
  list.setAttribute("data-testid", "activity-list");
  payments.forEach(p => {
    const item = document.createElement("div");
    item.className = "item";
    item.setAttribute("data-testid", `activity-item-${p.payment_id}`);
    item.setAttribute("data-visibility", p.visibility);
    item.innerHTML = `
      <div>
        <div data-testid="activity-parties-${p.payment_id}" style="font-weight:600;">${p.from_handle} &rarr; ${p.to_handle}</div>
        <div data-testid="activity-note-${p.payment_id}" style="font-size:13px; color:#64748b;">${p.note || ""}</div>
      </div>
      <div data-testid="activity-amount-${p.payment_id}" style="font-weight:700;">${fmtMoney(p.amount, currentMe.minor_units, currentMe.currency)}</div>
    `;
    list.appendChild(item);
  });
  c.appendChild(list);
}

async function handlePaySubmit(e) {
  e.preventDefault();
  clearError("pay-error");
  clearError("pay-uncertain");

  const handle = document.getElementById("pay-handle").value.trim();
  const rawAmt = document.getElementById("pay-amount").value.trim();
  const memo = document.getElementById("pay-note").value;
  const vis = document.getElementById("pay-visibility").value;

  const amt = parseDecimal(rawAmt, currentMe.minor_units);
  if (amt === null || amt <= 0) {
    showError("err-pay-anchor", "pay-error", "Invalid amount");
    return;
  }

  const payload = { to_handle: handle, amount: amt, note: memo, visibility: vis };
  if (!lastPayKey) {
    lastPayKey = newKey();
    lastPayPayload = payload;
  }

  try {
    const res = await api("/payments", {
      method: "POST",
      headers: { "Idempotency-Key": lastPayKey },
      body: payload
    });
    if (res.ok) {
      clearError("pay-error");
      clearError("pay-uncertain");
      await refreshDashboard();
    } else {
      const err = await res.json().catch(() => ({}));
      showError("err-pay-anchor", "pay-error", (err.error && err.error.message) || "Payment refused");
      await refreshDashboard();
    }
  } catch (netErr) {
    showUncertain("err-pay-anchor", "pay-uncertain", "Payment state uncertain. Retry to verify.");
  }
}

async function handleRequestSubmit(e) {
  e.preventDefault();
  clearError("request-error");
  const handle = document.getElementById("req-handle").value.trim();
  const rawAmt = document.getElementById("req-amount").value.trim();
  const memo = document.getElementById("req-note").value;

  const amt = parseDecimal(rawAmt, currentMe.minor_units);
  if (amt === null || amt <= 0) {
    showError("err-req-anchor", "request-error", "Invalid amount");
    return;
  }

  const res = await api("/requests", {
    method: "POST",
    headers: { "Idempotency-Key": newKey() },
    body: { payer_handle: handle, amount: amt, note: memo }
  });
  if (res.ok) {
    document.getElementById("req-handle").value = "";
    document.getElementById("req-amount").value = "";
    document.getElementById("req-note").value = "";
    clearError("request-error");
    await refreshDashboard();
  } else {
    const err = await res.json().catch(() => ({}));
    showError("err-req-anchor", "request-error", (err.error && err.error.message) || "Request failed");
  }
}

function renderRequestsView() {
  const c = document.getElementById("view-container");
  c.innerHTML = `
    <h2>Requests</h2>
    <div id="err-requests-global"></div>
    <div id="requests-content"></div>
  `;
  loadRequests();
}

async function loadRequests(preserveError = false) {
  if (!preserveError) clearError("request-error");
  const res = await api("/requests?limit=100");
  if (!res.ok) return;
  const data = await res.json();
  const allReqs = data.requests || [];
  const incoming = allReqs.filter(r => r.payer_id === currentUser.id);
  const outgoing = allReqs.filter(r => r.requester_id === currentUser.id);

  const c = document.getElementById("requests-content");
  if (!c) return;

  if (allReqs.length === 0) {
    c.innerHTML = `
      <div class="empty-msg" data-testid="empty-requests">No pending or past requests</div>
      <h3>Incoming Requests</h3>
      <div id="incoming-list" data-testid="incoming-list"></div>
      <h3 style="margin-top:24px;">Outgoing Requests</h3>
      <div id="outgoing-list" data-testid="outgoing-list"></div>
    `;
    return;
  }

  c.innerHTML = `
    <h3>Incoming Requests</h3>
    <div id="incoming-list" data-testid="incoming-list"></div>
    <h3 style="margin-top:24px;">Outgoing Requests</h3>
    <div id="outgoing-list" data-testid="outgoing-list"></div>
  `;

  const inList = document.getElementById("incoming-list");
  incoming.forEach(r => inList.appendChild(makeRequestItem(r, true)));

  const outList = document.getElementById("outgoing-list");
  outgoing.forEach(r => outList.appendChild(makeRequestItem(r, false)));
}

function makeRequestItem(r, isIncoming) {
  const div = document.createElement("div");
  div.className = "item";
  div.setAttribute("data-testid", `request-item-${r.request_id}`);
  div.setAttribute("data-status", r.status);

  let btns = "";
  if (r.status === "pending") {
    if (isIncoming) {
      btns = `
        <button data-testid="request-pay-${r.request_id}" onclick="actionReq('${r.request_id}','pay')">Pay</button>
        <button data-testid="request-decline-${r.request_id}" class="btn-secondary" onclick="actionReq('${r.request_id}','decline')" style="margin-left:6px;">Decline</button>
      `;
    } else {
      btns = `
        <button data-testid="request-cancel-${r.request_id}" class="btn-secondary" onclick="actionReq('${r.request_id}','cancel')">Cancel</button>
      `;
    }
  }

  div.innerHTML = `
    <div>
      <div>${isIncoming ? "From: " + r.requester_handle : "To: " + r.payer_handle} [Status: ${r.status}]</div>
      <div data-testid="request-amount-${r.request_id}" style="font-weight:700;">${fmtMoney(r.amount, currentMe.minor_units, currentMe.currency)}</div>
    </div>
    <div>${btns}</div>
  `;
  return div;
}

async function actionReq(rid, act) {
  clearError("request-error");
  const opts = { method: "POST" };
  if (act === "pay") {
    opts.headers = { "Idempotency-Key": newKey() };
    opts.body = { visibility: "public" };
  }
  const res = await api(`/requests/${rid}/${act}`, opts);
  if (res.ok) {
    clearError("request-error");
    await loadRequests(false);
  } else {
    showError("err-requests-global", "request-error", `Action ${act} refused`);
    await loadRequests(true);
  }
}

function renderSplitView() {
  const c = document.getElementById("view-container");
  c.innerHTML = `
    <h2>Split a Bill</h2>
    <form id="form-split" onsubmit="handleSplitSubmit(event)" class="card" style="background:#fff; border:1px solid #e2e8f0;">
      <div class="form-group">
        <label>Amount</label>
        <input type="text" data-testid="split-amount" id="split-amount" required oninput="calcSplitPreview()">
      </div>
      <div class="form-group">
        <label>Handles (comma-separated)</label>
        <input type="text" data-testid="split-handles" id="split-handles" required oninput="calcSplitPreview()">
      </div>
      <div class="form-group">
        <label>Note</label>
        <input type="text" data-testid="split-note" id="split-note">
      </div>
      <div id="split-preview-anchor"></div>
      <button type="submit" data-testid="split-submit">Submit Split</button>
      <div id="err-split-anchor"></div>
    </form>
  `;
}

function calcSplitPreview() {
  const rawAmt = document.getElementById("split-amount").value.trim();
  const rawHandles = document.getElementById("split-handles").value.trim();
  const anchor = document.getElementById("split-preview-anchor");
  clearError("split-error");

  if (!rawAmt || !rawHandles) {
    anchor.innerHTML = "";
    return;
  }
  const handles = rawHandles.split(",").map(h => h.trim()).filter(Boolean);
  const amt = parseDecimal(rawAmt, currentMe.minor_units);
  if (amt === null || amt <= 0 || handles.length === 0) {
    anchor.innerHTML = "";
    return;
  }
  const n = handles.length;
  const base = Math.floor(amt / n);
  const extra = amt % n;

  let itemsHtml = "";
  handles.forEach((h, i) => {
    const shareAmt = base + (i < extra ? 1 : 0);
    itemsHtml += `<div><span>${h}: </span><span data-testid="split-share-${h}" style="font-weight:600;">${fmtMoney(shareAmt, currentMe.minor_units, currentMe.currency)}</span></div>`;
  });

  anchor.innerHTML = `
    <div class="card" data-testid="split-preview" style="margin-bottom:12px;">
      <h4 style="margin:0 0 8px 0;">Preview Shares:</h4>
      ${itemsHtml}
    </div>
  `;
}

async function handleSplitSubmit(e) {
  e.preventDefault();
  clearError("split-error");
  const rawAmt = document.getElementById("split-amount").value.trim();
  const handles = document.getElementById("split-handles").value.split(",").map(h => h.trim()).filter(Boolean);
  const memo = document.getElementById("split-note").value;

  const amt = parseDecimal(rawAmt, currentMe.minor_units);
  if (amt === null || amt <= 0 || handles.length === 0) {
    showError("err-split-anchor", "split-error", "Invalid split input");
    return;
  }

  const res = await api("/splits", {
    method: "POST",
    headers: { "Idempotency-Key": newKey() },
    body: { amount: amt, participant_handles: handles, note: memo }
  });
  if (res.ok) {
    nav(null, "/requests");
  } else {
    const err = await res.json().catch(() => ({}));
    showError("err-split-anchor", "split-error", (err.error && err.error.message) || "Split refused");
  }
}

function renderAuthorizationsView() {
  const c = document.getElementById("view-container");
  c.innerHTML = `
    <h2>Payment Holds & Authorizations</h2>
    <div id="err-auth-anchor"></div>
    <div id="authorizations-content"></div>
  `;
  loadAuthorizations();
}

async function loadAuthorizations() {
  clearError("authorization-error");
  const res = await api("/authorizations?limit=100");
  if (!res.ok) return;
  const data = await res.json();
  const list = data.authorizations || [];
  const c = document.getElementById("authorizations-content");
  if (!c) return;

  if (list.length === 0) {
    c.innerHTML = `<div class="empty-msg" data-testid="empty-authorizations">No authorizations found</div>`;
    return;
  }

  const container = document.createElement("div");
  container.setAttribute("data-testid", "authorization-list");
  list.forEach(a => {
    const div = document.createElement("div");
    div.className = "item";
    div.setAttribute("data-testid", `authorization-item-${a.authorization_id}`);
    div.setAttribute("data-status", a.status);

    let capturedHtml = "";
    if (a.status === "captured") {
      capturedHtml = `<div>Captured: <span data-testid="authorization-captured-${a.authorization_id}">${fmtMoney(a.captured_amount, currentMe.minor_units, currentMe.currency)}</span></div>`;
    }

    let actionsHtml = "";
    if (a.status === "open") {
      if (a.to_user_id === currentUser.id) {
        actionsHtml = `
          <div style="display:flex; gap:6px; align-items:center;">
            <input type="text" data-testid="authorization-capture-amount-${a.authorization_id}" id="cap-amt-${a.authorization_id}" value="${(a.remaining_amount / Math.pow(10, currentMe.minor_units)).toFixed(currentMe.minor_units)}" style="width:90px;">
            <button data-testid="authorization-capture-${a.authorization_id}" onclick="captureAuth('${a.authorization_id}')">Capture</button>
          </div>
        `;
      } else if (a.from_user_id === currentUser.id) {
        actionsHtml = `
          <button data-testid="authorization-void-${a.authorization_id}" class="btn-secondary" onclick="voidAuth('${a.authorization_id}')">Void</button>
        `;
      }
    }

    div.innerHTML = `
      <div>
        <div style="font-weight:600;">${a.from_handle} &rarr; ${a.to_handle} [Status: ${a.status}]</div>
        <div data-testid="authorization-amount-${a.authorization_id}" style="font-weight:700;">${fmtMoney(a.amount, currentMe.minor_units, currentMe.currency)}</div>
        ${capturedHtml}
        <div style="font-size:12px; color:#64748b;">Expires: <span data-testid="authorization-expires-${a.authorization_id}">${a.expires_at}</span></div>
      </div>
      <div>${actionsHtml}</div>
    `;
    container.appendChild(div);
  });
  c.innerHTML = "";
  c.appendChild(container);
}

async function captureAuth(aid) {
  clearError("authorization-error");
  const raw = document.getElementById(`cap-amt-${aid}`).value;
  const amt = parseDecimal(raw, currentMe.minor_units);
  const body = amt !== null ? { amount: amt } : {};
  const res = await api(`/authorizations/${aid}/capture`, {
    method: "POST",
    headers: { "Idempotency-Key": newKey() },
    body
  });
  if (res.ok) {
    await loadAuthorizations();
  } else {
    showError("err-auth-anchor", "authorization-error", "Capture refused");
  }
}

async function voidAuth(aid) {
  clearError("authorization-error");
  const res = await api(`/authorizations/${aid}/void`, { method: "POST" });
  if (res.ok) {
    await loadAuthorizations();
  } else {
    showError("err-auth-anchor", "authorization-error", "Void refused");
  }
}

routeView();
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def handle_request(self):
        try:
            route = urlsplit(self.path)
            accept = self.headers.get("Accept", "")

            # HTML UI routes
            if (
                "text/html" in accept
                or route.path in ("/", "/login", "/signup", "/split")
                or (route.path in ("/requests", "/authorizations") and "text/html" in accept)
            ):
                if self.command == "GET":
                    data = HTML_APP.encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    return

            body = {}
            if self.command == "POST":
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if length < 0:
                        raise ValueError("negative length")
                    raw = self.rfile.read(length)
                    if not raw and re.fullmatch(r"/requests/[^/]+/(cancel|decline)", route.path):
                        raw = b"{}"
                    body = parse_json(raw)
                    if not isinstance(body, dict):
                        raise ValueError("expected object")
                except (ValueError, UnicodeError, RecursionError):
                    fail(400, "malformed_request")

            with LOCK:
                status, response = dispatch(
                    self.command, route.path,
                    parse_qs(route.query, keep_blank_values=True), self.headers, body
                )
                data = b"" if status == 204 else encode(response).encode("utf-8")
        except APIError as error:
            status = error.status
            data = encode({"error": {"code": error.code, "message": error.code.replace("_", " ")}}).encode()
        except Exception:
            status = 500
            data = encode({"error": {"code": "internal_error", "message": "internal error"}}).encode()

        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = handle_request

    def log_message(self, *_):
        pass


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128


if __name__ == "__main__":
    Server(("0.0.0.0", int(os.environ.get("PORT", "8080"))), Handler).serve_forever()
