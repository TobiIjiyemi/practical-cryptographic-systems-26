# Adversary API reference

Two ways to drive the sandbox: the Python helper `ExerciseAPI` (recommended),
and the raw HTTP it speaks. Your entry points receive an `ExerciseAPI`.

## Python helper (`exercise_api.py`)

```python
api.info()                        # configuration dict (see below)
api.queue()                       # list of decoded envelopes, enqueue order
api.deliver(message_id)           # deliver one queued envelope; returns emitted envelopes
api.drop(message_id)              # drop one queued envelope; returns None
api.inject(sender, recipient, body)   # deliver bytes now; returns emitted envelopes
api.status()                      # limited completion status
```

A **decoded envelope** is `{"id": int, "from": str, "to": str, "body": bytes}`
— `body` replaces the wire `payload`, already base64-decoded. Public keys from
`info()` are raw `bytes`; `status()["negotiation"]["sid"]` is `bytes`.

The helper raises `ExerciseAPIError(status, code)` on any non-200 response and
`ExerciseTransportError` if the request did not complete. A transport failure is
never a silent "nothing happened" — don't treat it as an oracle answer. The
helper does no delivery, retry, or reset on its own; the runner calls `start`.

## Operations

- **`info()`** — `api_version`, `run_id`, `mode` (`negotiation` or `record`),
  `started`, `public_keys` for `alice` and `bob`, and `limits`. No secret, no
  private key.
- **`queue()`** — a non-destructive snapshot of the pending envelopes, in
  enqueue order. Nothing is delivered, decrypted, or consumed by looking.
- **`deliver(id)`** — remove that envelope and hand its exact bytes to the named
  recipient. Returns every envelope the recipient emitted, in order, each with a
  new id; those stay queued. Delivering a message never delivers its responses.
  An unknown, already-delivered, or dropped id is a 404. Costs one delivery.
- **`inject(from, to, body)`** — deliver `body` (raw `bytes`) to `to` as if from
  `from`, immediately. Only `alice` and `bob`, and they must differ. The body is
  not validated: a malformed or truncated protocol body reaches the bot and
  produces its specified behaviour. Returns emitted envelopes (left queued).
  Costs one delivery, even if the body is discarded.
- **`drop(id)`** — remove a queued envelope without delivering it. Costs a
  request, not a delivery. There is no edit-in-place: to change a message, save
  its fields, drop it, and inject the replacement.
- **`status()`** — `mode`; `negotiation` (null, or `{"sid": bytes, "suite":
  1|2}` once both bots establish the same challenge session); `target` (null, or
  the captured challenge DATA envelope once both bots have established its
  session); `counts`; and `limit_hit`. The status is derived from the bots' real
  state — you cannot set it — and it does **not** tell padding and MAC failures
  apart.

## Reading the bots' reactions

An empty emitted list is a real, synchronous observation: the recipient emitted
nothing. It is not a reason to wait or poll. Both silence and an emitted RESEND
come back as HTTP 200. The only thing that distinguishes a valid-padding record
from an invalid one is whether the recipient emitted a RESEND; nothing in an
HTTP status or error code encodes it.

## Raw HTTP (if you are not using the helper)

Loopback JSON. Every `/adv/` request except `GET /adv/info` must carry the
header `X-JMessage-Run: <run_id>`. Binary bodies are standard base64 in a
`payload` field.

| Method & path | Body | Returns |
|---|---|---|
| `GET /adv/info` | — | configuration |
| `POST /adv/start` | `{}` | `{"emitted": [envelope, ...]}` |
| `GET /adv/queue` | — | `{"messages": [envelope, ...]}` |
| `POST /adv/deliver/<id>` | `{}` | `{"delivered_id": id, "emitted": [...]}` |
| `POST /adv/drop/<id>` | `{}` | `{}` |
| `POST /adv/inject` | `{"from","to","payload"}` | `{"delivered_id": id, "emitted": [...]}` |
| `GET /adv/status` | — | status |

A wire **envelope** is `{"id": int, "from": str, "to": str, "payload": str}`.
IDs are positive and strictly increasing within a run and are never reused; they
are transport identifiers, not sequence numbers.

### Status codes

| Code | Meaning |
|---|---|
| 200 | completed, including a protocol-level silent discard |
| 400 | invalid JSON, envelope shape, bot names, or base64 |
| 404 | unknown route or unavailable queue id |
| 409 | wrong/missing run header, an operation before `start`, or a repeated `start` |
| 413 | request body or base64 payload too large |
| 429 | a request, delivery, or queue limit is exhausted |
| 500 | sandbox/backend failure; this run is invalid |

Error bodies are `{"error": "<stable_code>"}` and carry no private state. Every
request after readiness counts toward the request budget, reads and drops
included.
