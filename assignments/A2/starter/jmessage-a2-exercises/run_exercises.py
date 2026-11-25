#!/usr/bin/env python3
"""Run a submission's Parts 2-3 attacks against fresh sandboxes (KIT-SPEC §7).

    python run_exercises.py --submission DIR --part {2|3|chain|experiment} --output DIR

The coordinator starts a fresh sandbox, waits for its readiness line, calls
start itself, then runs the student's entry point in a SEPARATE worker process
under a wall-clock limit. It never imports student code. It writes result.json,
a chronological transport trace, and the worker's captured output.

Put --output inside the submission directory, as a top-level `run-*` directory
(`--output <submission>/run-part2`): that is the only place package_final.py
collects run evidence from. The runner prints a note otherwise.

This is the local development runner (KIT-SPEC §12.1, Thursday tier): it
isolates the worker as a separate process and enforces time, but not the OS-uid
isolation and independent block comparison of the grading path. It verifies
exact plaintext recovery against the sandbox's private truth channel.
"""
import argparse
import base64
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from exercise_api import ExerciseAPI, ExerciseAPIError, ExerciseTransportError  # noqa: E402

MODE_FOR_PART = {"2": "negotiation", "3": "record",
                 "chain": "negotiation", "experiment": "negotiation"}
TIME_LIMIT = {"2": 60, "3": 300, "chain": 360, "experiment": 60}


def _start_sandbox(mode, truth_path, trace_path):
    """Launch the sandbox subprocess; return (proc, ExerciseAPI, ready)."""
    proc = subprocess.Popen(
        [sys.executable, os.path.join(HERE, "sandbox.py"), "--mode", mode,
         "--port", "0", "--truth-path", truth_path, "--trace-path", trace_path],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    line = proc.stdout.readline()
    if not line:
        raise SystemExit("sandbox failed to start:\n" + proc.stderr.read())
    ready = json.loads(line)
    return proc, ExerciseAPI(ready["base_url"], ready["run_id"]), ready


def _read_result(path):
    """The worker's result file, or None if it is missing or unparseable."""
    try:
        with open(path) as fh:
            return json.load(fh)
    except Exception:
        return None


def _run_worker(job, limit):
    """Run the student worker as a subprocess under a wall-clock limit.

    The worker writes its structured result to job["result_path"]; the student's
    own stdout and stderr come back separately and never touch the result
    channel. Returns (result, worker_stdout, worker_stderr, elapsed_seconds).
    """
    proc = subprocess.Popen([sys.executable, os.path.join(HERE, "_worker.py")],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    start = time.monotonic()
    try:
        out, err = proc.communicate(json.dumps(job), timeout=limit)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        # A stage the worker completed before the limit (a chained downgrade)
        # is already in the result file; keep it and mark the run timed out.
        result = _read_result(job["result_path"]) or {}
        result.update(ok=False, timeout=True)
        return result, out, err, time.monotonic() - start
    elapsed = time.monotonic() - start
    result = _read_result(job["result_path"])
    if result is None:
        # No parseable result file means the worker died before writing one
        # (a crash or a killed process), not a stray print on stdout.
        result = {"ok": False, "error": "worker produced no result"}
    return result, out, err, elapsed


def _read_status(api):
    """The sandbox's status for verification, or (None, why) if it no longer
    answers: a 500 made the run invalid, or the sandbox went away. A spent
    request budget does not stop status reads (KIT-SPEC §5.8)."""
    try:
        return api.status(), None
    except (ExerciseAPIError, ExerciseTransportError) as e:
        return None, f"{type(e).__name__}: {e}"


def _worker_status(worker):
    for key in ("timeout", "limit", "infrastructure", "not_implemented"):
        if worker.get(key):
            return key
    return "error" if worker.get("error") else "ok"


def main(argv=None):
    ap = argparse.ArgumentParser(description="JMessage A2 exercise runner")
    ap.add_argument("--submission", required=True)
    ap.add_argument("--part", required=True, choices=tuple(MODE_FOR_PART))
    ap.add_argument("--output", required=True,
                    help="new directory for result.json and the trace; put it "
                         "inside the submission as <submission>/run-<name>")
    ap.add_argument("--time-limit", type=float, default=None, metavar="SECONDS",
                    help="override this part's wall-clock limit (local runs only)")
    args = ap.parse_args(argv)

    sub = os.path.abspath(args.submission)
    if not os.path.isfile(os.path.join(sub, "exercises", "attack.py")):
        raise SystemExit(f"no exercises/attack.py under {sub}")
    out = os.path.abspath(args.output)
    if os.path.exists(out):
        raise SystemExit(f"output directory already exists: {out}")
    if os.path.dirname(out) != sub or not os.path.basename(out).startswith("run-"):
        print(f"note: {out} is not a top-level run-*/ directory of the submission; "
              f"package_final.py will not collect its evidence. Use "
              f"--output {os.path.join(sub, 'run-<name>')} for a cited run.",
              file=sys.stderr)
    os.makedirs(out)
    limit = args.time_limit if args.time_limit else TIME_LIMIT[args.part]

    truth_path = os.path.join(out, ".truth.json")   # coordinator-only
    trace_path = os.path.join(out, "transport-trace.jsonl")
    mode = MODE_FOR_PART[args.part]
    proc, api, ready = _start_sandbox(mode, truth_path, trace_path)
    result_path = os.path.join(out, ".worker-result.json")   # coordinator-only
    try:
        api.start()
        job = {"base_url": api.base_url, "run_id": api.run_id, "part": args.part,
               "submission_dir": sub, "kit_src": HERE, "result_path": result_path}
        if args.part == "3":
            target = api.status()["target"]
            target = {"id": target["id"], "from": target["from"], "to": target["to"],
                      "payload": base64.b64encode(target["body"]).decode()}
            job["target"] = target
        worker, wout, werr, elapsed = _run_worker(job, limit)
        st, sandbox_error = _read_status(api)
        verdicts = _verify(args.part, st, worker, truth_path)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(truth_path):
            os.remove(truth_path)                   # never leave truth on disk

    result = {
        "kit_api_version": ready["api_version"], "run_id": ready["run_id"],
        "part": args.part, "mode": mode, "elapsed_seconds": round(elapsed, 3),
        "time_limit_seconds": limit,
        "counts": st["counts"] if st else None,
        "limit_hit": st["limit_hit"] if st else None,
        "sandbox_error": sandbox_error,
        "verdicts": verdicts,
        "sid": worker.get("sid_hex"),
        "plaintext_hex": worker.get("plaintext_hex"),
        "blocks": worker.get("blocks", []),
        "worker_status": _worker_status(worker),
        "worker_error": worker.get("error"),
        "note": "local development runner; grading uses OS-isolated workers and "
                "independent block comparison (KIT-SPEC §12.1).",
    }
    with open(os.path.join(out, "result.json"), "w") as fh:
        json.dump(result, fh, indent=2)
    with open(os.path.join(out, "worker-stdout.txt"), "w") as fh:
        fh.write((wout or "")[:8 * 1024 * 1024])
    with open(os.path.join(out, "worker-stderr.txt"), "w") as fh:
        fh.write((werr or "")[:8 * 1024 * 1024])
    for leftover in (result_path, result_path + ".tmp"):
        if os.path.exists(leftover):
            os.remove(leftover)                     # folded into result.json; don't ship

    print(json.dumps({"verdicts": verdicts, "worker_status": result["worker_status"],
                      "elapsed": result["elapsed_seconds"], "counts": result["counts"],
                      "limit_hit": result["limit_hit"], "output": out}, indent=2))
    ok = all(v in ("pass", "n/a") for v in verdicts.values())
    sys.exit(0 if ok else 1)


def _verify(part, st, worker, truth_path):
    """Per-dimension verdicts: `pass`, `fail`, `n/a`, or `unverified` when the
    sandbox no longer answers (see `sandbox_error`). Exact recovery is checked
    against the truth channel, which does not depend on the sandbox answering."""
    v = {}
    if part in ("2", "chain"):
        if st is None:
            v["negotiation"] = "unverified"
        else:
            neg = st["negotiation"]
            v["negotiation"] = "pass" if (neg and neg["suite"] == 1
                                          and worker.get("sid_hex") == neg["sid"].hex()) else "fail"
    if part in ("3", "chain"):
        truth = json.load(open(truth_path))["secret_hex"] if os.path.exists(truth_path) else None
        v["recovery"] = "pass" if (worker.get("plaintext_hex") == truth and truth) else "fail"
    if part == "experiment":
        v["experiment"] = "n/a"          # diagnostic: no execution verdict (§6)
    return v


if __name__ == "__main__":
    main()
