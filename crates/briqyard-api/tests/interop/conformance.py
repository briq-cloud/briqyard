#!/usr/bin/env python3
"""Standalone conformance consumer for the sealed v3.1 wire (SYL-268). Not an SDK.

Reads ../../testdata/sealed_v3_1/vectors.json (or $SEALED_VECTORS) and reproduces every
published value from first principles with hashlib and the `cryptography` package. The
Ed25519 seeds are RFC 8032 section 7.1 test vectors: public test material that signs nothing
real. Run: python3 -I conformance.py
"""

import base64
import hashlib
import json
import os
import re
import struct
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

MAX_SAFE = 9007199254740991
HERE = Path(__file__).resolve().parent
VECTORS = Path(
    os.environ.get("SEALED_VECTORS", HERE.parent.parent / "testdata" / "sealed_v3_1" / "vectors.json")
)
V = json.loads(VECTORS.read_text("utf-8"))

checks = 0
failures = []


def check(name, ok):
    global checks
    checks += 1
    if not ok:
        failures.append(name)


def equal(name, actual, expected):
    check(name, actual == expected)
    if actual != expected:
        print(f"  {name}: got {actual!r} want {expected!r}", file=sys.stderr)


def rejects(name, fn):
    try:
        fn()
    except Exception:
        check(name, True)
        return
    check(name, False)


class Refused(Exception):
    pass


def sha(data):
    return hashlib.sha256(data).digest()


def hexd(data):
    return sha(data).hex()


def b64u_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_decode(text, length):
    if not re.fullmatch(r"[A-Za-z0-9_-]+", text):
        raise Refused("base64url alphabet")
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if len(raw) != length or b64u_encode(raw) != text:
        raise Refused("base64url")
    return raw


def fill(k):
    return b64u_encode(bytes([k]) * 32)


def plain(c):
    return 0x20 <= c <= 0x7E and c not in (0x22, 0x5C)


# ---- C(t): strict canonical JSON ---------------------------------------------------------
def write_string(s):
    if not all(plain(ord(c)) for c in s):
        raise Refused("string alphabet")
    return '"' + s + '"'


def encode_value(v, depth):
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        if v < 0 or v > MAX_SAFE:
            raise Refused("integer")
        return str(v)
    if isinstance(v, str):
        return write_string(v)
    if depth > 24:
        raise Refused("depth")
    if isinstance(v, list):
        if len(v) > 256:
            raise Refused("array")
        return "[" + ",".join(encode_value(e, depth + 1) for e in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v.keys(), key=lambda k: k.encode("ascii"))
        return "{" + ",".join(write_string(k) + ":" + encode_value(v[k], depth + 1) for k in keys) + "}"
    raise Refused("type")


def C(v):
    out = encode_value(v, 1).encode("ascii")
    if len(out) > 65536:
        raise Refused("too large")
    return out


def H(v):
    return hexd(C(v))


class Parser:
    def __init__(self, data):
        self.b = data
        self.at = 0

    def peek(self):
        return self.b[self.at] if self.at < len(self.b) else -1

    def expect(self, c):
        if self.peek() != c:
            raise Refused("unexpected byte")
        self.at += 1

    def word(self, w, v):
        if not self.b[self.at : self.at + len(w)] == w.encode():
            raise Refused("literal")
        self.at += len(w)
        return v

    def value(self, depth):
        c = self.peek()
        if c == 0x7B:
            return self.object(depth)
        if c == 0x5B:
            return self.array(depth)
        if c == 0x22:
            return self.string()
        if c == 0x74:
            return self.word("true", True)
        if c == 0x66:
            return self.word("false", False)
        if c == 0x6E:
            return self.word("null", None)
        if 0x30 <= c <= 0x39:
            return self.integer()
        raise Refused("unexpected byte")

    def integer(self):
        start = self.at
        while 0x30 <= self.peek() <= 0x39:
            self.at += 1
        digits = self.b[start : self.at].decode("ascii")
        if self.peek() in (0x2E, 0x65, 0x45):
            raise Refused("float or exponent")
        if len(digits) > 1 and digits[0] == "0":
            raise Refused("leading zero")
        if len(digits) > 16 or int(digits) > MAX_SAFE:
            raise Refused("range")
        return int(digits)

    def string(self):
        self.expect(0x22)
        start = self.at
        while True:
            c = self.peek()
            if c < 0:
                raise Refused("unterminated")
            if c == 0x22:
                break
            if not plain(c):
                raise Refused("string alphabet")
            self.at += 1
        s = self.b[start : self.at].decode("ascii")
        self.at += 1
        return s

    def array(self, depth):
        if depth > 24:
            raise Refused("depth")
        self.expect(0x5B)
        items = []
        if self.peek() == 0x5D:
            self.at += 1
            return items
        while True:
            if len(items) >= 256:
                raise Refused("array")
            items.append(self.value(depth + 1))
            c = self.peek()
            self.at += 1
            if c == 0x5D:
                return items
            if c != 0x2C:
                raise Refused("unexpected byte")

    def object(self, depth):
        if depth > 24:
            raise Refused("depth")
        self.expect(0x7B)
        out = {}
        if self.peek() == 0x7D:
            self.at += 1
            return out
        previous = None
        while True:
            key = self.string()
            if previous is not None:
                if previous == key:
                    raise Refused("duplicate key")
                if previous > key:
                    raise Refused("unsorted keys")
            self.expect(0x3A)
            out[key] = self.value(depth + 1)
            previous = key
            c = self.peek()
            self.at += 1
            if c == 0x7D:
                return out
            if c != 0x2C:
                raise Refused("unexpected byte")


def decode_canonical(data):
    """Parse raw bytes strictly and require byte equality with C of the parsed value."""
    if len(data) > 65536 or data[:1] != b"{":
        raise Refused("not an object")
    parser = Parser(data)
    v = parser.value(1)
    if parser.at != len(data):
        raise Refused("trailing bytes")
    if C(v) != data:
        raise Refused("not canonical")
    return v


def decode_text(text):
    return decode_canonical(text.encode("latin-1"))


# ---- Sig(tag, T) ----------------------------------------------------------------------------
class Key:
    def __init__(self, name):
        entry = V["keys"][name]
        self.private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(entry["seed_hex"]))
        self.raw = self.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.kid = hexd(self.raw)
        equal(f"{name} public key", b64u_encode(self.raw), entry["public"])


def preimage(tag, kid, body):
    return b"\0".join([V["domain"].encode(), tag.encode(), kid.encode(), C(body)])


def sign_envelope(tag, body, key):
    return {"tag": tag, "kid": key.kid, "body": body, "sig": b64u_encode(key.private.sign(preimage(tag, key.kid, body)))}


def decode_envelope(data):
    env = decode_canonical(data)
    if list(env.keys()) != ["body", "kid", "sig", "tag"]:
        raise Refused("envelope shape")
    if not re.fullmatch(r"[0-9a-f]{64}", env["kid"]):
        raise Refused("kid")
    b64u_decode(env["sig"], 64)
    if not isinstance(env["tag"], str) or not isinstance(env["body"], dict):
        raise Refused("envelope shape")
    return env


def verify_envelope(data, expected_tag, pinned):
    env = decode_envelope(data)
    sig = b64u_decode(env["sig"], 64)
    if env["tag"] != expected_tag:
        raise Refused("wrong tag")
    if env["kid"] != pinned.kid:
        raise Refused("wrong key")
    try:
        Ed25519PublicKey.from_public_bytes(pinned.raw).verify(sig, preimage(env["tag"], env["kid"], env["body"]))
    except InvalidSignature:
        raise Refused("bad signature") from None
    return env


# ---- shared fixtures -----------------------------------------------------------------------
rk, bk, ak = Key("rk"), Key("bk"), Key("ak")
equal("rk kid is h(raw public key)", rk.kid, V["keys"]["rk"]["kid"])
PLAN = V["plan_hash_fill"] * 64
X = {"aud": V["x"]["aud"], "host": V["x"]["host"], "op": V["x"]["op_fill"] * 64, "serial": V["x"]["serial"]}


def proc(pid):
    p = V["proc"]
    return {"boot": p["boot"], "build": p["build"], "exe": p["exe_digit"] * 64, "pid": pid, "start": p["start"]}


# ---- 1. query.host envelope --------------------------------------------------------------
q = V["query"]
body = decode_text(q["body"])
equal("query body is exactly C(body)", C(body).decode("latin-1"), q["body"])
reordered = {"preview": None, "plan": PLAN, "q": {"x": {"serial": 1, "op": X["op"], "host": X["host"], "aud": X["aud"]}, "nonce": fill(0)}}
equal("reordering before encoding gives the same bytes", C(reordered).decode("latin-1"), q["body"])
equal("signature preimage hash", hexd(preimage(q["tag"], rk.kid, body)), q["preimage_hash"])
env = sign_envelope(q["tag"], body, rk)
equal("signature", env["sig"], q["sig"])
equal("H(envelope)", H(env), q["envelope_hash"])
text = C(env)
verify_envelope(text, q["tag"], rk)
check("envelope verifies under the pinned Rk", True)
rejects("keys swapped on the wire: pinned Bk refuses an Rk envelope", lambda: verify_envelope(text, q["tag"], bk))
rejects("a different expected tag refuses", lambda: verify_envelope(text, "query.authority", rk))
for n in q["negatives"]:
    mutated = text.decode("latin-1")
    if "append" in n:
        mutated += n["append"]
    else:
        check(f"{n['id']}: fixture contains the text to mutate", n["find"] in mutated)
        mutated = mutated.replace(n["find"], n["replace"], 1)
    data = mutated.encode("latin-1")
    if n["expect"] == "decode":
        rejects(f"negative {n['id']} fails raw-byte decoding", lambda d=data: decode_envelope(d))
        rejects(f"negative {n['id']} never verifies", lambda d=data: verify_envelope(d, q["tag"], rk))
    else:
        own = decode_envelope(data)["tag"]
        rejects(f"negative {n['id']} refuses under the expected tag", lambda d=data: verify_envelope(d, q["tag"], rk))
        rejects(f"negative {n['id']} refuses under its own tag (signature does not cover it)", lambda d=data, t=own: verify_envelope(d, t, rk))

# ---- 2. native registration, ACK and the C(H(Reg)) distinction ------------------------------
r = V["native_reg"]
reg = json.loads(r["text"])
native = json.dumps(
    {k: reg[k] for k in ("authority", "epoch", "key_id", "public_key", "host_instance", "generation")},
    separators=(",", ":"),
).encode("ascii")
equal("native bytes are the six fields in displayed order", native.decode("ascii"), r["text"])
equal("public_key is the Rk key", bytes(reg["public_key"]), rk.raw)
equal("legacy reg_hash is SHA-256 of the native bytes", hexd(native), r["reg_hash"])
ack_digest = b64u_encode(sha(native))
equal("Ack.digest", ack_digest, r["ack_digest"])
equal("ctx.reg_hash is the same digest in hex", b64u_decode(ack_digest, 32).hex(), r["reg_hash"])
canonical = C(reg)
check("C(Reg) is sorted, not native order", canonical.decode("ascii").startswith(r["canonical_prefix"]))
check("C(Reg) differs from the native bytes", canonical != native)
equal("H(Reg) under canonical order", hexd(canonical), r["canonical_h_reg"])
check("H(Reg) is not the native digest", hexd(canonical) != r["reg_hash"])
rejects("legacy order is refused wherever C is required", lambda: decode_canonical(native))
check("canonical order decodes", decode_canonical(canonical)["generation"] == 2)

# ---- 3. trial -----------------------------------------------------------------------------------
T = V["trial"]
trial = decode_text(T["c"])
equal("C(Trial) is the exact canonical bytes", C(trial).decode("latin-1"), T["c"])
equal("H(Trial)", H(trial), T["hash"])
origin_hash = hexd(b"briqyard/trial-origin/v3" + b"\0" + T["origin"].encode("ascii"))
equal("gateway_origin_hash", origin_hash, T["origin_hash"])
equal("Trial.gateway_origin_hash", trial["gateway_origin_hash"], origin_hash)


def u(n):
    return struct.pack(">Q", n)


def s(t):
    raw = t.encode("utf-8")
    return u(len(raw)) + raw


nonce = trial["nonce"]
pre = b"briqyard-exec-request-v1" + b"\0" + u(4) + s("/bin/busybox") + s("printf") + s("%s") + s(nonce) + u(0) + s("") + s("") + u(1000)
equal("command preimage", pre.hex(), T["command_preimage_hex"])
equal("command_hash", hexd(pre), T["command_hash"])
equal("Trial.command_hash", trial["command_hash"], T["command_hash"])
equal("native request_digest is the same 32 bytes in base64url", b64u_encode(sha(pre)), T["native_request_digest"])
equal("request JSON", C({"cmd": ["/bin/busybox", "printf", "%s", nonce], "cwd": "", "env": {}, "stdin": "", "timeout_ms": 1000, "wake": False}).decode("ascii"), T["request_json"])

ra = sign_envelope("trial3.receiver", trial, rk)
ba = sign_envelope("trial3.api", trial, bk)
equal("H(RA)", H(ra), T["ra_hash"])
equal("H(BA)", H(ba), T["ba_hash"])
rejects("swapped approval keys refuse", lambda: verify_envelope(C(sign_envelope("trial3.receiver", trial, bk)), "trial3.receiver", rk))
check("using grant_id as delegation_intent changes the commitment", H({**trial, "delegation_intent": trial["grant_id"]}) != T["hash"])

equal("grant_hash", hexd(T["grant_text"].encode("ascii")), T["grant_hash"])
equal("projection_hash", hexd(T["projection_text"].encode("ascii")), T["projection_hash"])
issued = sign_envelope("trial3.issued", {"trial": H(trial), "grant_hash": T["grant_hash"], "projection_hash": T["projection_hash"]}, bk)
equal("H(Issued)", H(issued), T["issued_hash"])
equal("H(Job)", H({"approvals": {"api": ba, "receiver": ra}, "issued": issued}), T["job_hash"])
equal("outcome", hexd(T["outcome_preimage"].encode("ascii")), T["outcome"])
equal(
    "outcome preimage is native field order",
    T["outcome_preimage"],
    json.dumps({"stdout": nonce, "stderr": "", "exit_code": 0, "timed_out": False}, separators=(",", ":")),
)


def status(fill_byte):
    return sign_envelope(
        "trial3.status",
        {
            "q": {"nonce": fill(fill_byte), "x": X},
            "plan": PLAN,
            "trial": H(trial),
            "proc": proc(18),
            "bind_hash": trial["bind_hash"],
            "run": trial["run"],
            "grant_id": trial["grant_id"],
            "delegation_intent": trial["delegation_intent"],
            "request_hash": trial["command_hash"],
            "grant_hash": T["grant_hash"],
            "projection_hash": T["projection_hash"],
            "phase": "finished",
            "outcome": T["outcome"],
        },
        ak,
    )


sb, sr = status(T["status_b_nonce_fill"]), status(T["status_r_nonce_fill"])
equal("B-challenged Ak signature", sb["sig"], T["status_b_sig"])
equal("H(B-challenged status)", H(sb), T["status_b_hash"])
equal("H(R-challenged status)", H(sr), T["status_r_hash"])
check("the two verifiers' status envelopes differ", H(sb) != H(sr))
equal("final.read.trial is H of the complete B-challenged status", H(sb), T["final_read_trial"])
equal("client.enable.trial is H(Trial), never H(Status)", H(trial), T["client_enable_trial"])
check("client.enable.trial differs from final.read.trial", T["client_enable_trial"] != T["final_read_trial"])
verify_envelope(C(sb), "trial3.status", ak)
rejects("a status never verifies under Rk", lambda: verify_envelope(C(sb), "trial3.status", rk))

t = T["timeout"]


def allowed(now_ms):
    room = 1000 * t["exp"] - now_ms - 1000
    return min(1000, 60000, 1000 * t["max_duration_seconds"], room)


equal("timeout: nowMs 1999999998000 sends exactly 1000", allowed(t["send"]["now_ms"]), 1000)
equal("timeout: nowMs 1999999998001 has room 999", allowed(t["refuse"]["now_ms"]), t["refuse"]["room"])
check("timeout: 999 ms is refused, never sent shortened", allowed(t["refuse"]["now_ms"]) != 1000)

# ---- 4. custody fixture --------------------------------------------------------------------------
c = V["custody"]


def wire(**extra):
    base = {
        "x": X,
        "plan": PLAN,
        "resource": c["capture"]["resource"],
        "owner": fill(c["capture"]["owner_fill"]),
        "custodian": proc(c["capture"]["custodian_pid"]),
        "old": proc(c["capture"]["old_pid"]),
        "next": None,
        "challenge": fill(c["capture"]["challenge_fill"]),
        "slot": c["capture"]["slot"],
    }
    base.update(extra)
    return base


capture = sign_envelope("custody.capture", {"wire": wire()}, rk)
request = wire(next=proc(c["request"]["next_pid"]), challenge=fill(c["request"]["challenge_fill"]))
matched = sign_envelope("custody.match", {"wire": request, "capture": H(capture), "same": True}, rk)
exited = sign_envelope("custody.exit", {"wire": request, "match": H(matched), "exited": True}, rk)
equal("H(Capture)", H(capture), c["capture_hash"])
equal("H(Rk signed matched)", H(matched), c["matched_hash"])
equal("H(Rk signed exited)", H(exited), c["exited_hash"])
equal("matched and exited repeat the same wire", matched["body"]["wire"], exited["body"]["wire"])
for name, extra in (
    ("owner", {"owner": fill(9)}),
    ("challenge", {"challenge": fill(4)}),
    ("slot", {"slot": 28}),
    ("no returned successor", {"next": None}),
):
    other = H(sign_envelope("custody.match", {"wire": {**request, **extra}, "capture": H(capture), "same": True}, rk))
    check(f"a different {name} is a different match, never the published one", other != c["matched_hash"])

if failures:
    print(f"FAILED {len(failures)} of {checks} checks:", file=sys.stderr)
    for f in failures:
        print(f"  - {f}", file=sys.stderr)
    sys.exit(1)
print(f"python conformance: {checks} checks passed")
