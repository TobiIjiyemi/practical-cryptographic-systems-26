#!/usr/bin/env python3
"""Transport-only helper for the exercise sandbox adversary API (KIT-SPEC §6).

`ExerciseAPI` is thin networking glue: it supplies the run header, strictly
decodes JSON and base64, preserves response order, and raises on any non-200.
It performs no automatic delivery, retry, reset, or attack, and it exposes no
private supervisor channel. In decoded envelopes `body: bytes` replaces
`payload`; `id`, `from`, `to` are unchanged. Public keys from `info()` and the
`negotiation` sid from `status()` are returned as raw bytes.
"""
import base64
import json
import urllib.request


class ExerciseAPIError(Exception):
    """A non-200 HTTP response: carries the status and the stable error code."""
    def __init__(self, status, code):
        super().__init__(f"{status} {code}")
        self.status, self.code = status, code


class ExerciseTransportError(Exception):
    """The request did not complete. NEVER an empty observation (§4.3)."""


def _decode_env(env):
    out = dict(env)
    out["body"] = base64.b64decode(out.pop("payload"), validate=True)
    return out


class ExerciseAPI:
    def __init__(self, base_url, run_id):
        self.base_url = base_url.rstrip("/")
        self.run_id = run_id

    def _request(self, method, path, body=None, *, with_run=True):
        url = self.base_url + path
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(url, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if with_run:
            req.add_header("X-JMessage-Run", self.run_id)
        try:
            with urllib.request.urlopen(req) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            try:
                code = json.loads(e.read()).get("error", "unknown")
            except Exception:
                code = "unknown"
            raise ExerciseAPIError(e.code, code)
        except urllib.error.URLError as e:
            raise ExerciseTransportError(str(e))

    # ----- documented operations -----------------------------------------

    def info(self):
        d = self._request("GET", "/adv/info", with_run=False)
        d["public_keys"] = {k: base64.b64decode(v) for k, v in d["public_keys"].items()}
        return d

    def start(self):
        d = self._request("POST", "/adv/start", {})
        return [_decode_env(e) for e in d["emitted"]]

    def queue(self):
        d = self._request("GET", "/adv/queue")
        return [_decode_env(e) for e in d["messages"]]

    def deliver(self, message_id):
        d = self._request("POST", f"/adv/deliver/{message_id}", {})
        return [_decode_env(e) for e in d["emitted"]]

    def drop(self, message_id):
        self._request("POST", f"/adv/drop/{message_id}", {})
        return None

    def inject(self, sender, recipient, body):
        payload = base64.b64encode(body).decode("ascii")
        d = self._request("POST", "/adv/inject",
                          {"from": sender, "to": recipient, "payload": payload})
        return [_decode_env(e) for e in d["emitted"]]

    def status(self):
        d = self._request("GET", "/adv/status")
        neg = d.get("negotiation")
        if neg:
            neg = {"sid": bytes.fromhex(neg["sid"]), "suite": neg["suite"]}
        d["negotiation"] = neg
        if d.get("target"):
            d["target"] = _decode_env(d["target"])
        return d
