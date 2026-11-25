#!/usr/bin/env python3
"""Local teaching sandbox for JMessage Assignment 2, Parts 2 and 3 (KIT-SPEC §§3-5).

Two honest reference clients, `alice` and `bob`, run inside one process. The
student acts as a malicious relay over a loopback HTTP API: inspect, deliver,
drop, and inject protocol bodies. The sandbox never exposes plaintext, keys, a
padding/MAC distinction, or any raw client event; the only observable signals
are the wire messages the bots emit and the limited status in §5.7.

    python sandbox.py --mode negotiation --port 0
    python sandbox.py --mode record --port 0

One process owns exactly one challenge: fresh keys, a fresh secret, a fresh
run id. There is no reset, reseed, or check endpoint. Restart for a new run.

Local testing knob: `JMESSAGE_SANDBOX_LIMITS` may hold a JSON object that
lowers or raises the published limits for this process only (staff tests use
it to reach a budget quickly). `/adv/info` reports the limits in effect.
Grading runs its own sandbox, so the variable changes nothing a grader sees.

This file is deliberately self-contained apart from `jmessage_reference`, which
sits beside it in the extracted kit. It holds no attack, no answer key, and no
secret-guessing service.
"""
import argparse
import json
import os
import secrets
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from jmessage_reference import Client
from jmessage_reference._support.transport import PeerKeyUnavailable

API_VERSION = 1
BOTS = ("alice", "bob")
SECRET_ALPHABET = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
SECRET_MIN, SECRET_MAX = 48, 63                      # §4: exercises every padding length

# Wire type bytes we parse from bodies for the observer and the trace only
# (never for policy). These are the public message types; see the protocol spec.
T_HELLO, T_REPLY, T_FINISH, T_REJECT = 0x01, 0x02, 0x03, 0x04
T_DATA, T_RECEIPT, T_RESEND = 0x10, 0x11, 0x12
TYPE_NAMES = {T_HELLO: "HELLO", T_REPLY: "REPLY", T_FINISH: "FINISH",
              T_REJECT: "REJECT", T_DATA: "DATA", T_RECEIPT: "RECEIPT",
              T_RESEND: "RESEND"}

LIMITS = {                                            # §7.1 published limits
    "deliveries": 65536,
    "requests": 200000,
    "pending_messages": 1024,
    "payload_chars": 8192,
    "request_body_bytes": 16384,
}


class SandboxError(Exception):
    """Carries an HTTP status and a stable error code (§5.8); no private state."""
    def __init__(self, status, code):
        super().__init__(code)
        self.status, self.code = status, code


def b64(raw: bytes) -> str:
    import base64
    return base64.b64encode(raw).decode("ascii")


def unb64(text: str) -> bytes:
    import base64
    if not isinstance(text, str):
        raise SandboxError(400, "bad_payload")
    try:
        return base64.b64decode(text, validate=True)
    except Exception:
        raise SandboxError(400, "bad_payload")


class Challenge:
    """One run: two bots, one secret, the adversary queue, and the observer.

    All access is serialized by `self.lock`: every bot `receive` and every
    state read happens under it, so the protocol runs strictly serially
    (§4.3) and counters stay consistent.
    """

    def __init__(self, mode):
        if mode not in ("negotiation", "record"):
            raise ValueError(mode)
        self.mode = mode
        self.run_id = secrets.token_hex(16)
        self.lock = threading.RLock()
        self.started = False
        self.invalid = False                          # a 500 invalidates the run

        n = secrets.randbelow(SECRET_MAX - SECRET_MIN + 1) + SECRET_MIN
        self._secret = "".join(secrets.choice(SECRET_ALPHABET) for _ in range(n))

        self._id = {name: Ed25519PrivateKey.generate() for name in BOTS}
        self.clients = {}
        for name in BOTS:
            jm1_only = (mode == "record" and name == "alice")   # §4.2 compat option
            self.clients[name] = Client(
                name, self._id[name].private_bytes_raw(), self._lookup,
                self._make_emit(name), lambda: 0.0, jm1_only=jm1_only)  # frozen clock §4.3

        self._queue = []                 # [{id, from, to, payload}], FIFO by id
        self._next_id = 1
        self.counts = {"deliveries": 0, "requests": 0}
        self.limit_hit = None

        # Observer state, built only from emitted wire bytes and events.
        self._established = {name: {} for name in BOTS}   # name -> {sid: suite}
        self._alice_initiator_sids = set()                # §4.1 challenge lineage
        self._target = None                               # captured challenge DATA envelope
        self._last_wire = None        # §7.2 wire detail of the current operation, for the trace

    # ----- bot wiring (the only place events are seen) --------------------

    def _lookup(self, peer):
        """Authenticated fixture keys (§3); never attacker-supplied directory data."""
        if peer not in self._id:
            raise PeerKeyUnavailable(peer)
        return self._id[peer].public_key().public_bytes_raw()

    def _make_emit(self, name):
        """Return `name`'s emit. Records wire sends and non-secret event metadata.

        Raw event text is private (§3). For `send` we keep the body; for every
        other event we keep only type/sid/suite/seq. In particular an `error`
        event's message can contain the queued secret verbatim, so its text is
        dropped here and never stored, logged, or returned.
        """
        def emit(ev):
            kind = ev.get("type")
            if kind == "send":
                self._enqueue(name, ev["to"], ev["body"])
            elif kind == "established":
                self._established[name][ev["sid"]] = ev["suite"]
        return emit

    def _enqueue(self, frm, to, body):
        """Append a bot emission to the attacker queue and update the observer."""
        if len(self._queue) >= LIMITS["pending_messages"]:
            self.limit_hit = "pending_messages"
            raise SandboxError(429, "pending_limit")
        env = {"id": self._next_id, "from": frm, "to": to, "payload": b64(body)}
        self._next_id += 1
        self._queue.append(env)
        self._observe_emission(frm, body, env)

    def _observe_emission(self, frm, body, env):
        """Track lineage and the challenge target from raw bytes only (no policy)."""
        if frm != "alice" or not body:
            return
        t = body[0]
        if t in (T_HELLO, T_FINISH):
            self._alice_initiator_sids.add(body[1:17])    # alice is initiator of this sid
        elif t == T_DATA and self._target is None:
            # DATA = u8 type || bytes[16] sid || u64 seq || protected
            sid, seq = body[1:17], int.from_bytes(body[17:25], "big")
            if sid in self._alice_initiator_sids and seq == 0:
                self._target = dict(env)                  # the one challenge record (§5.7)

    # ----- wire description for the transport trace (§7.2) ----------------

    def _describe(self, frm, to, body, env_id=None):
        """A non-secret descriptor of one wire message: endpoints, type, bytes.

        The body is the public wire record (handshake bytes or an encrypted
        DATA record); it is never plaintext and never event text. For DATA we
        also surface the session id and sequence number the attacker can read
        off the wire. This is exactly what the queue and `emitted` already
        expose, recorded so the trace can be replayed after the fact.
        """
        d = {"from": frm, "to": to,
             "type": TYPE_NAMES.get(body[0] if body else None, f"0x{body[0]:02x}" if body else "empty"),
             "len": len(body), "b64": b64(body)}
        if env_id is not None:
            d["id"] = env_id
        if body and body[0] == T_DATA and len(body) >= 25:
            d["sid"] = body[1:17].hex()
            d["seq"] = int.from_bytes(body[17:25], "big")
        return d

    def _describe_env(self, env):
        return self._describe(env["from"], env["to"], unb64(env["payload"]), env.get("id"))

    # ----- lifecycle ------------------------------------------------------

    def start(self):
        """§5.2: run the per-mode setup once and return the emitted envelopes."""
        if self.started:
            raise SandboxError(409, "already_started")
        self.started = True
        before = len(self._queue)
        # Both modes send the secret through the reference's own text queue, so
        # FINISH precedes the challenge DATA and "exactly once" is free (§4.1).
        if self.mode == "negotiation":
            self.clients["alice"].send_text("bob", self._secret)   # emits HELLO
            emitted = self._queue[before:]
        else:
            self._setup_record_mode()
            emitted = [self._target] if self._target else []
        self._last_wire = {"emitted": [self._describe_env(e) for e in emitted]}
        return emitted

    def _setup_record_mode(self):
        """§4.2: relay an honest JM1 handshake to completion, then withhold the DATA.

        Everything except the challenge DATA is delivered (one message at a
        time, re-reading the queue so emissions are picked up), so both FINISH
        reaches Bob and both bots establish. The setup traffic is not counted
        as adversary deliveries. Only the one challenge DATA is left queued,
        with Bob still expecting sequence zero.
        """
        self.clients["alice"].send_text("bob", self._secret)       # HELLO (JM1 only)
        for _ in range(50):
            deliverable = [e for e in self._queue
                           if not (unb64(e["payload"])[:1] == bytes([T_DATA])
                                   and e["from"] == "alice")]
            if not deliverable:
                break
            env = deliverable[0]
            self._queue.remove(env)
            self._deliver_body(env["from"], env["to"], unb64(env["payload"]))
        else:
            raise SandboxError(500, "record_setup_failed")
        # Leave exactly the challenge DATA queued for the attacker.
        self._queue = [e for e in self._queue
                       if self._target and e["id"] == self._target["id"]]

    def _deliver_body(self, frm, to, body):
        """Pass decoded bytes to one bot's receive (§4.3, serial, non-reentrant)."""
        self.clients[to].receive(frm, to, body)

    # ----- adversary operations (under lock, via the handler) -------------

    def info(self):
        return {
            "api_version": API_VERSION, "run_id": self.run_id, "mode": self.mode,
            "started": self.started,
            "public_keys": {n: b64(self._id[n].public_key().public_bytes_raw())
                            for n in BOTS},
            "limits": dict(LIMITS),
        }

    def queue_snapshot(self):
        return {"messages": [dict(e) for e in self._queue]}

    def deliver(self, msg_id):
        env = self._take(msg_id)
        body = unb64(env["payload"])
        # Record the bytes actually delivered to Bob before running delivery, so
        # the trace holds them even if the recipient then errors (§7.2).
        self._last_wire = {"delivered": self._describe(env["from"], env["to"], body, msg_id)}
        self._charge_delivery()
        emitted = self._run_delivery(env["from"], env["to"], body)
        self._last_wire["emitted"] = [self._describe_env(e) for e in emitted]
        return {"delivered_id": msg_id, "emitted": emitted}

    def inject(self, frm, to, payload):
        if frm not in BOTS or to not in BOTS or frm == to:
            raise SandboxError(400, "bad_names")
        body = unb64(payload)
        inj_id = self._next_id
        self._next_id += 1
        # Record the attacker's injected bytes before delivery (§7.2): this is
        # how the write-up reconstructs its modifications and probe contents.
        self._last_wire = {"injected": self._describe(frm, to, body, inj_id)}
        self._charge_delivery()
        emitted = self._run_delivery(frm, to, body)
        self._last_wire["emitted"] = [self._describe_env(e) for e in emitted]
        return {"delivered_id": inj_id, "emitted": emitted}

    def drop(self, msg_id):
        self._take(msg_id)
        return {}

    def status(self):
        neg, suite = self._shared_challenge_session()
        return {
            "mode": self.mode,
            "negotiation": ({"sid": neg.hex(), "suite": suite} if neg else None),
            "target": (dict(self._target) if self._target else None),
            "counts": {**self.counts, "pending_messages": len(self._queue)},
            "limit_hit": self.limit_hit,
        }

    # ----- observer helpers ----------------------------------------------

    def _shared_challenge_session(self):
        """Return (sid, suite) both bots established in the challenge lineage, else (None, None).

        Record mode reports its single established session too; its `mode`
        keeps the runner from reading that as a downgrade (§5.7).
        """
        for sid, suite in self._established["alice"].items():
            if sid in self._established["bob"]:
                if self.mode == "record" or sid in self._alice_initiator_sids:
                    return sid, suite
        return None, None

    # ----- plumbing -------------------------------------------------------

    def _take(self, msg_id):
        for i, env in enumerate(self._queue):
            if env["id"] == msg_id:
                return self._queue.pop(i)
        raise SandboxError(404, "unknown_id")

    def _charge_delivery(self):
        if self.counts["deliveries"] >= LIMITS["deliveries"]:
            self.limit_hit = "deliveries"
            raise SandboxError(429, "delivery_limit")
        self.counts["deliveries"] += 1

    def _run_delivery(self, frm, to, body):
        """Deliver to one bot; return the envelopes it emitted (left queued, §5.4)."""
        before = len(self._queue)
        try:
            self._deliver_body(frm, to, body)
        except SandboxError:
            raise
        except Exception:
            # A bot crash is a sandbox/backend failure; invalidate the run.
            self.invalid = True
            raise SandboxError(500, "bot_error")
        return [dict(e) for e in self._queue[before:]]


class Handler(BaseHTTPRequestHandler):
    server_version = "jmessage-sandbox/1"

    def log_message(self, *a):                         # no request logging (no secret leak)
        pass

    # one Challenge per server, shared
    @property
    def ch(self):
        return self.server.challenge

    def _send(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > LIMITS["request_body_bytes"]:
            raise SandboxError(413, "body_too_large")
        raw = self.rfile.read(n) if n else b""
        if not raw:
            return {}
        try:
            obj = json.loads(raw)
        except Exception:
            raise SandboxError(400, "bad_json")
        if not isinstance(obj, dict):
            raise SandboxError(400, "bad_json")
        return obj

    def _require_empty(self, obj):
        if obj != {}:
            raise SandboxError(400, "bad_json")

    def _check_payload(self, obj):
        p = obj.get("payload")
        if not isinstance(p, str) or len(p) > LIMITS["payload_chars"]:
            raise SandboxError(413, "payload_too_large")

    def _count_request(self, method, path):
        """Charge one request (§5.8). Once the budget is spent, `GET /adv/status`
        stays readable so the runner and the student can see what happened; it
        is no longer charged and replenishes nothing."""
        if self.ch.counts["requests"] >= LIMITS["requests"]:
            self.ch.limit_hit = "requests"
            if method == "GET" and path == "/adv/status":
                return
            raise SandboxError(429, "request_limit")
        self.ch.counts["requests"] += 1

    def _dispatch(self, method, path):
        ch = self.ch
        with ch.lock:
            ch._last_wire = None        # reset per operation; set by start/deliver/inject
            if ch.invalid:
                raise SandboxError(500, "run_invalid")
            # /adv/info needs no run header and is not counted toward requests
            # only to the extent the runner's readiness probe is excluded; all
            # post-readiness requests are counted (§5.8). We count everything
            # except info, matching "except GET /adv/info" for the header rule.
            if path == "/adv/info" and method == "GET":
                return 200, ch.info(), None
            if self.headers.get("X-JMessage-Run") != ch.run_id:
                raise SandboxError(409, "bad_run")
            self._count_request(method, path)
            if not ch.started and not (path == "/adv/start" and method == "POST"):
                raise SandboxError(409, "not_started")

            if method == "POST" and path == "/adv/start":
                self._require_empty(self._body())
                return 200, {"emitted": ch.start()}, ch._last_wire
            if method == "GET" and path == "/adv/queue":
                return 200, ch.queue_snapshot(), None
            if method == "GET" and path == "/adv/status":
                return 200, ch.status(), None
            if method == "POST" and path.startswith("/adv/deliver/"):
                self._require_empty(self._body())
                return 200, ch.deliver(self._id_from(path, "/adv/deliver/")), ch._last_wire
            if method == "POST" and path.startswith("/adv/drop/"):
                self._require_empty(self._body())
                return 200, ch.drop(self._id_from(path, "/adv/drop/")), None
            if method == "POST" and path == "/adv/inject":
                obj = self._body()
                self._check_payload(obj)
                if set(obj) != {"from", "to", "payload"}:
                    raise SandboxError(400, "bad_fields")
                return 200, ch.inject(obj["from"], obj["to"], obj["payload"]), ch._last_wire
            raise SandboxError(404, "unknown_route")

    def _id_from(self, path, prefix):
        tail = path[len(prefix):]
        if not tail.isdigit():
            raise SandboxError(404, "unknown_id")
        return int(tail)

    def _serve(self, method):
        path = self.path.split("?")[0]
        try:
            status, obj, wire = self._dispatch(method, path)
            self._trace(method, path, status, obj, wire)
            self._send(status, obj)
        except SandboxError as e:
            # A deliver/inject that crashed the recipient still recorded the
            # bytes it delivered before failing; include them.
            self._trace(method, path, e.status, {"error": e.code},
                        getattr(self.ch, "_last_wire", None))
            self._send(e.status, {"error": e.code})
        except Exception:
            self._trace(method, path, 500, {"error": "internal"}, None)
            self._send(500, {"error": "internal"})

    def _trace(self, method, path, status, obj, wire=None):
        """Append one non-secret line to the chronological transport trace (§7.2).

        Records the operation number, request, status, envelope ids, and the
        public wire bytes involved: what the attacker delivered or injected and
        what each bot emitted in response, as base64 with a parsed type. Bodies
        are the public wire records (handshake or encrypted DATA), never
        plaintext and never event text, so the secret is not exposed. This lets
        the write-up reconstruct the original offer, the interventions, and
        representative probe responses, and distinguishes what was delivered to
        Bob from what Alice emitted.
        """
        tp = getattr(self.server, "trace_path", None)
        if not tp:
            return
        line = {"method": method, "path": path, "status": status}
        if isinstance(obj, dict):
            if "delivered_id" in obj:
                line["delivered_id"] = obj["delivered_id"]
            if "error" in obj:
                line["error"] = obj["error"]
        if wire:
            line.update(wire)
        with self.server.trace_lock:
            self.server.trace_n += 1
            line = {"op": self.server.trace_n, **line}
            with open(tp, "a") as fh:
                fh.write(json.dumps(line) + "\n")

    def do_GET(self):
        self._serve("GET")

    def do_POST(self):
        self._serve("POST")


def main(argv=None):
    ap = argparse.ArgumentParser(description="JMessage A2 exercise sandbox")
    ap.add_argument("--mode", required=True, choices=("negotiation", "record"))
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--truth-path", default=None,
                    help="private: write the secret here for a trusted local "
                         "supervisor (§5.8). Never passed to the attack worker.")
    ap.add_argument("--trace-path", default=None,
                    help="append a chronological transport trace here (§7.2).")
    args = ap.parse_args(argv)

    override = os.environ.get("JMESSAGE_SANDBOX_LIMITS")
    if override:
        try:
            entries = json.loads(override).items()
        except (ValueError, AttributeError):
            raise SystemExit("JMESSAGE_SANDBOX_LIMITS must be a JSON object")
        for key, value in entries:
            if key not in LIMITS or isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise SystemExit(f"bad JMESSAGE_SANDBOX_LIMITS entry: {key!r}")
            LIMITS[key] = value

    challenge = Challenge(args.mode)
    if args.truth_path:
        # The private supervisor channel: readable only by the coordinator that
        # chose the path, never by the attack worker or over the network.
        with open(args.truth_path, "w") as fh:
            json.dump({"secret_hex": challenge._secret.encode().hex()}, fh)
    httpd = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    httpd.challenge = challenge
    httpd.trace_path = args.trace_path
    httpd.trace_lock = threading.Lock()
    httpd.trace_n = 0
    host, port = httpd.server_address
    ready = {"api_version": API_VERSION, "run_id": challenge.run_id,
             "base_url": f"http://{host}:{port}"}
    sys.stdout.write(json.dumps(ready) + "\n")
    sys.stdout.flush()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
