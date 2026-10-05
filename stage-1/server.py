"""Pocketful Stage 1. One process and one lock own the complete ledger."""
import copy
from datetime import datetime, timezone
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


class APIError(Exception):
    def __init__(self, status, code):
        self.status, self.code = status, code


def fail(status=422, code="validation_failed"):
    raise APIError(status, code)


def require(condition):
    if not condition:
        fail()


def parse_json(raw):
    def bad_constant(_):
        raise ValueError("non-JSON constant")
    return json.loads(raw, parse_float=Decimal, parse_constant=bad_constant)


def encode(value):
    """Encode exact parsed JSON numbers without a binary floating point round trip."""
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, dict):
        return "{" + ",".join(json.dumps(k) + ":" + encode(v)
                              for k, v in sorted(value.items())) + "}"
    if isinstance(value, list):
        return "[" + ",".join(encode(v) for v in value) + "]"
    return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"))


def json_equal(a, b):
    # Python's True == 1 must not turn different JSON bodies into a replay.
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


def empty_state(currency="EUR", minor_units=2):
    return {"currency": currency, "minor_units": minor_units, "users": {},
            "tokens": {}, "payments": {}, "requests": {}, "retries": {},
            "operators": [], "seeded_total": 0}


STATE = empty_state()


def resolve_handle(handle):
    for user in STATE["users"].values():
        if user["handle"] == handle:
            return user
    fail(404, "not_found")


def payment(sender, receiver, amount, memo, visible, timestamp=None,
            request_id=None, settlement_id=None, payment_id=None):
    return {"payment_id": payment_id or identity("p"),
            "from_user_id": sender["id"], "from_handle": sender["handle"],
            "to_user_id": receiver["id"], "to_handle": receiver["handle"],
            "amount": amount, "currency": STATE["currency"], "note": memo,
            "visibility": visible, "request_id": request_id,
            "settlement_id": settlement_id, "created_at": timestamp or now()}


def money_request(requester, payer, amount, memo, timestamp=None):
    return {"request_id": identity("rq"), "requester_id": requester["id"],
            "requester_handle": requester["handle"], "payer_id": payer["id"],
            "payer_handle": payer["handle"], "amount": amount,
            "currency": STATE["currency"], "note": memo, "status": "pending",
            "payment_id": None, "created_at": timestamp or now()}


def fixture(body):
    currency = field(body, "currency")
    units = integer(body.get("minor_units"), 0, 3)
    require(units in (0, 2, 3) and bool(currency))
    candidate = empty_state(currency, units)
    emails, handles = set(), set()
    for raw in field(body, "users", list):
        require(isinstance(raw, dict))
        uid, email, handle = (field(raw, k) for k in ("id", "email", "handle"))
        require(0 < len(uid) <= 64 and uid not in candidate["users"])
        require(email not in emails and handle not in handles and HANDLE.fullmatch(handle))
        user = {"id": uid, "email": email, "handle": handle,
                "display_name": field(raw, "display_name"),
                "balance": integer(raw.get("balance"), 0, MAX_BALANCE),
                "password": hash_password(field(raw, "password"))}
        candidate["users"][uid] = user
        emails.add(email)
        handles.add(handle)
    candidate["seeded_total"] = sum(u["balance"] for u in candidate["users"].values())
    operators = body.get("settlement_operator_ids", [])
    require(isinstance(operators, list))
    require(all(isinstance(x, str) and x in candidate["users"] for x in operators))
    candidate["operators"] = list(dict.fromkeys(operators))
    timestamp = now()
    for collection in ("payments", "requests"):
        records = body.get(collection, [])
        require(isinstance(records, list))
        for raw in records:
            require(isinstance(raw, dict))
            rid = field(raw, "id")
            require(0 < len(rid) <= 64 and rid not in candidate[collection])
            a, b = (("from_user_id", "to_user_id") if collection == "payments"
                    else ("requester_id", "payer_id"))
            source, target = field(raw, a), field(raw, b)
            require(source in candidate["users"] and target in candidate["users"])
            sender, receiver = candidate["users"][source], candidate["users"][target]
            rec = {a: source, b: target, "amount": integer(raw.get("amount"), 0),
                   "currency": currency, "note": note(raw), "created_at": timestamp}
            if collection == "payments":
                rec.update(payment_id=rid, from_handle=sender["handle"],
                           to_handle=receiver["handle"], visibility=visibility(raw),
                           request_id=raw.get("request_id"), settlement_id=raw.get("settlement_id"))
            else:
                status = raw.get("status", "pending")
                require(status in STATUSES)
                rec.update(request_id=rid, requester_handle=sender["handle"],
                           payer_handle=receiver["handle"], status=status,
                           payment_id=raw.get("payment_id"))
            candidate[collection][rid] = rec
    return candidate


def import_snapshot(body):
    """A self-contained, checksummed JSON envelope; never pickle or execute input."""
    require(body.get("track") == "pocketful")
    require(type(body.get("format_version")) is int and body["format_version"] == 1)
    envelope = body.get("state")
    require(isinstance(envelope, dict) and envelope.get("encoding") == "json-v1")
    payload, digest = envelope.get("payload"), envelope.get("sha256")
    require(isinstance(payload, str) and isinstance(digest, str))
    require(hmac.compare_digest(hashlib.sha256(payload.encode()).hexdigest(), digest))
    try:
        candidate = parse_json(payload)
        require(isinstance(candidate, dict) and candidate.keys() == empty_state().keys())
        require(isinstance(candidate["currency"], str))
        require(integer(candidate["minor_units"], 0, 3) in (0, 2, 3))
        for key in ("users", "tokens", "payments", "requests", "retries"):
            require(isinstance(candidate[key], dict))
        users = candidate["users"]
        emails, handles = set(), set()
        for uid, user in users.items():
            require(isinstance(user, dict) and user["id"] == uid and 0 < len(uid) <= 64)
            for key in ("email", "display_name", "handle"):
                require(isinstance(user[key], str))
            require(HANDLE.fullmatch(user["handle"]) and user["handle"] not in handles)
            require(user["email"] not in emails)
            emails.add(user["email"])
            handles.add(user["handle"])
            integer(user["balance"], 0, MAX_BALANCE)
            password = user["password"]
            require(password["algorithm"] == "scrypt-16384-8-1")
            require(re.fullmatch(r"[0-9a-f]{32}", password["salt"]))
            require(re.fullmatch(r"[0-9a-f]{128}", password["digest"]))
        require(sum(u["balance"] for u in users.values()) == candidate["seeded_total"])
        require(all(isinstance(token, str) and uid in users for token, uid in candidate["tokens"].items()))
        require(isinstance(candidate["operators"], list) and all(uid in users for uid in candidate["operators"]))
        for key, id_field, parties in (("payments", "payment_id", ("from_user_id", "to_user_id")),
                                        ("requests", "request_id", ("requester_id", "payer_id"))):
            for rid, rec in candidate[key].items():
                require(rec[id_field] == rid and all(rec[p] in users for p in parties))
                integer(rec["amount"], 0)
                note(rec)
                require(rec["currency"] == candidate["currency"])
                require(datetime.fromisoformat(rec["created_at"]).tzinfo is not None)
                if key == "payments":
                    visibility(rec)
                else:
                    require(rec["status"] in STATUSES)
        for key, retry in candidate["retries"].items():
            scope = parse_json(key)
            require(isinstance(scope, list) and len(scope) == 4 and scope[0] in users)
            require(scope[1] == "POST" and all(isinstance(x, str) for x in scope))
            require(isinstance(retry["body"], dict) and isinstance(retry["response"], dict))
        return candidate
    except (KeyError, TypeError, ValueError, OverflowError):
        fail()


def page(query, records, key):
    def count(name, default, minimum, maximum=None):
        value = query.get(name, [str(default)])[0]
        require(re.fullmatch(r"[0-9]+", value) is not None)
        # Avoid Python's digit-limit exception, even on absurdly large offsets.
        value = Decimal(value)
        require(value >= minimum and (maximum is None or value <= maximum))
        return int(min(value, len(records) + 201))
    limit, offset = count("limit", 50, 1, 200), count("offset", 0, 0)
    records.sort(key=lambda r: r["created_at"], reverse=True)
    return {key: records[offset:offset + limit], "has_more": offset + limit < len(records)}


def authenticate(headers):
    auth = headers.get("Authorization", "")
    parts = auth.split()
    if len(parts) != 2 or parts[0].lower() != "bearer" or parts[1] not in STATE["tokens"]:
        fail(401, "unauthenticated")
    return STATE["users"][STATE["tokens"][parts[1]]]


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
        user = {"id": identity("u"), "email": email, "display_name": display,
                "handle": handle, "balance": 0, "password": hash_password(password)}
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
    return status, {"user_id": user["id"], "display_name": user["display_name"], "token": token}


def commit_payment(sender, receiver, amount, memo, visible, request_id=None):
    if sender["balance"] < amount:
        fail(409, "insufficient_funds")
    require(receiver["balance"] + amount <= MAX_BALANCE)
    receipt = payment(sender, receiver, amount, memo, visible, request_id=request_id)
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
        receipt = {"split_id": identity("sp"), "amount": amount, "currency": STATE["currency"],
                   "note": memo, "shares": shares, "requests": requests, "created_at": timestamp}
        for request in requests:
            STATE["requests"][request["request_id"]] = request
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
        balances = {uid: STATE["users"][uid]["balance"] + delta for uid, delta in deltas.items()}
        if any(balance < 0 for balance in balances.values()):
            fail(409, "insufficient_funds")
        require(all(balance <= MAX_BALANCE for balance in balances.values()))
        sid, timestamp = identity("st"), now()
        payments = [payment(*entry, timestamp=timestamp, settlement_id=sid) for entry in staged]
        # Apply final net balances directly: no transient negative wallet exists.
        for uid, balance in balances.items():
            STATE["users"][uid]["balance"] = balance
        for rec in payments:
            STATE["payments"][rec["payment_id"]] = rec
        return {"settlement_id": sid, "committed_at": timestamp, "payments": payments}
    match = re.fullmatch(r"/requests/([^/]+)/(pay|decline|cancel)", path)
    if match:
        rid, action = match.groups()
        request = STATE["requests"].get(rid)
        if request is None:
            fail(404, "not_found")
        owner = request["requester_id" if action == "cancel" else "payer_id"]
        if user["id"] != owner:
            fail(403, "forbidden")
        if action == "pay":
            visible = visibility(body)
            if request["status"] != "pending":
                fail(409, "request_not_pending")
            receipt = commit_payment(user, STATE["users"][request["requester_id"]],
                                     request["amount"], request["note"], visible, rid)
            request.update(status="paid", payment_id=receipt["payment_id"])
            return receipt
        target = "cancelled" if action == "cancel" else "declined"
        if request["status"] not in ("pending", target):
            fail(409, "request_not_pending")
        request["status"] = target
        return request
    fail(404, "not_found")


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
        return 200, {"track": "pocketful", "format_version": 1,
                     "state": {"encoding": "json-v1", "payload": payload,
                               "sha256": hashlib.sha256(payload.encode()).hexdigest()}}
    if method == "POST" and path in ("/auth/signup", "/auth/login"):
        return auth_endpoint(path, body)
    user = authenticate(headers)
    if method == "GET":
        if path == "/me":
            return 200, {"user_id": user["id"], "display_name": user["display_name"],
                         "handle": user["handle"], "balance": user["balance"],
                         "currency": STATE["currency"], "minor_units": STATE["minor_units"]}
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
        fail(404, "not_found")
    if method != "POST":
        fail(404, "not_found")
    if path == "/settlements" and user["id"] not in STATE["operators"]:
        fail(403, "forbidden")
    idempotent = path in ("/payments", "/requests", "/splits", "/settlements") or bool(
        re.fullmatch(r"/requests/[^/]+/pay", path))
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


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def handle_api(self):
        try:
            route = urlsplit(self.path)
            body = {}
            if self.command == "POST":
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if length < 0:
                        raise ValueError("negative length")
                    raw = self.rfile.read(length)
                    # Body-less cancel/decline operations are conventional and valid.
                    if not raw and re.fullmatch(r"/requests/[^/]+/(cancel|decline)", route.path):
                        raw = b"{}"
                    body = parse_json(raw)
                    if not isinstance(body, dict):
                        raise ValueError("expected object")
                except (ValueError, UnicodeError, RecursionError):
                    fail(400, "malformed_request")
            # Encoding while holding the lock also freezes GET response objects.
            with LOCK:
                status, response = dispatch(self.command, route.path,
                                            parse_qs(route.query, keep_blank_values=True), self.headers, body)
                data = b"" if status == 204 else encode(response).encode("utf-8")
        except APIError as error:
            status = error.status
            data = encode({"error": {"code": error.code, "message": error.code.replace("_", " ")}}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = handle_api

    def log_message(self, *_):
        pass


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128


if __name__ == "__main__":
    Server(("0.0.0.0", int(os.environ.get("PORT", "8080"))), Handler).serve_forever()
