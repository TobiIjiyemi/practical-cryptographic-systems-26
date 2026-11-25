# JMessage Assignment 2 — exercise kit (Parts 2 and 3)

This kit completes Assignment 2. It contains the released reference client, a
local sandbox for the two security exercises, the helper and runner you use to
drive them, and the final-submission packager. Read `EXERCISES.md` for the
tasks, `API.md` for the adversary interface, and `REVIEW-LAB.md` for what the
review lab expects.

The starter kit from the original release is unchanged and still what you
develop your client in. This kit is separate; it does not overwrite your client
or your `checkpoint/`.

## 1. Setup

Use Python 3.12 or newer. Install the same pinned dependency as the starter:

```bash
python -m pip install -r requirements.txt
python check_environment.py
```

`check_environment.py` confirms your `cryptography` build actually supports
Ed25519, X25519, ML-KEM-768 and AES-GCM; a correct version number with a
backend missing ML-KEM would fail only mid-handshake. **Windows:** use WSL
(Windows Subsystem for Linux); the kit is tested on macOS and Linux.

## 2. What's here

| Path | What it is |
|---|---|
| `EXERCISES.md`, `API.md`, `REVIEW-LAB.md` | the tasks, the API, the review lab |
| `sandbox.py` | the local teaching sandbox (two honest bots + relay API) |
| `exercise_api.py` | the Python helper your attacks use |
| `run_exercises.py` | starts a fresh sandbox and runs your attack under limits |
| `exercises/attack.py` | **your work**: the entry points to fill in |
| `exercises/README.md` | **your work**: the explanation and evidence template |
| `reference_client.py`, `jmessage_reference/` | the released reference client |
| `package_final.py` | builds your final-submission archive |
| `AGENTS.md`, `CLAUDE.md` | guidance for a coding agent helping with Parts 2-3 |

## 3. Quick start

Your Parts 2–3 work lives in your **client directory** (the one holding your
`protocol.py` and `checkpoint/`), not in this kit. Set it up once by copying the
template directory there:

```bash
cp -r exercises/ /path/to/your-client/        # from this kit directory
```

Then run the runner **from this kit directory**. Point `--submission` at your
client directory and put each `--output` inside it as a top-level `run-*`
directory; that is the only place `package_final.py` collects run evidence from.

```bash
# Try the sandbox by hand first: start one and look at the readiness line.
python sandbox.py --mode negotiation --port 0
# -> prints one JSON line: {"api_version":1,"run_id":"...","base_url":"http://127.0.0.1:PORT"}

# Normally you let the runner drive it.
C=/path/to/your-client
python run_exercises.py --submission $C --part experiment --output $C/run-exp
python run_exercises.py --submission $C --part 2 --output $C/run-part2
python run_exercises.py --submission $C --part 3 --output $C/run-part3
python run_exercises.py --submission $C --part chain --output $C/run-chain
```

Each run makes a fresh sandbox with a new secret, writes `result.json` and a
`transport-trace.jsonl` into the output directory, and exits nonzero if the
requested exercise did not succeed. The output directory must not already
exist, so each run is kept separate. `--output` is resolved from your current
directory: a bare `--output run-part2` lands in this kit directory, not in your
submission, and the runner prints a note when that happens.

## 4. The reference client

`jmessage_reference` is the full reference implementation, packaged so it never
collides with your own `protocol.py`, `padding.py`, or `jmessage_support`. You
can run it as an ordinary client against the local relay or the course `echo`
user to check interoperability:

```bash
# Local relay (two terminals): start the starter's local_relay.py, then:
python reference_client.py --server http://127.0.0.1:8765 --username ref --register

# Course echo server:
python reference_client.py --server https://jmessage.practicalcrypto.org \
    --username <your-name> --register
```

To run the starter's `run_checks.py client_smoke` against the reference as the
peer, put this kit directory on `PYTHONPATH` and use
`--peer-module jmessage_reference`.

## 5. Submitting

From this kit directory:

```bash
python package_final.py --submission /path/to/your-client --output final.zip
```

This bundles your client, your preserved `checkpoint/`, `exercises/`, and the
run evidence in your client directory's top-level `run-*/` directories
(`result.json`, `transport-trace.jsonl`, the worker output, and any screenshots
your write-up cites), and excludes the staff kit, credentials, and any
anonymous-report material. Inspect the archive before submitting. Keep
anonymous-report files (the report, receipts, tags, attendance proof, and your
channel key) out of it; they go through the separate channel described in the
handout and the starter's `AGENTS.md`.

## 6. Troubleshooting

- **`check_environment.py` fails on ML-KEM.** Your `cryptography` wheel's
  OpenSSL lacks ML-KEM. Reinstall from `requirements.txt` in a clean virtual
  environment; on Linux prefer the manylinux wheel.
- **"output directory already exists".** Each run needs a new `--output`;
  rename or remove the old one.
- **The runner reports `not_implemented`.** You have not filled in that entry
  point yet. The other part still runs.
- **A run hangs and then reports a timeout.** Your attack is making too many
  sequential requests, or waiting on a response that will not come (an empty
  emitted list is a complete answer, not a reason to wait). See `API.md`.
- **The runner reports `limit`** (`result.json` names it in `limit_hit`). Your
  attack spent a per-run budget from `EXERCISES.md`, most often the request
  budget through a polling loop. The sandbox's status stays readable, so the
  `counts` in `result.json` show what was spent.
- **`package_final.py` says no `run-*/` evidence was found.** Your runs were
  written outside your client directory. Re-run with
  `--output /path/to/your-client/run-<name>`, or move the run directory there.
