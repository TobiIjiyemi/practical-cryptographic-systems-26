#!/usr/bin/env python3
"""Attack worker: runs the student's entry point in its own process (KIT-SPEC §7).

The coordinator (run_exercises.py) never imports student code. It launches this
worker with a JSON job on stdin and reads the JSON result from a dedicated file
(job["result_path"]), NOT from stdout: the student's attack may print freely,
and those prints go to stdout/stderr, which the coordinator captures separately.
The worker sees only the documented HTTP API and, for Part 3, the captured
target; it has no truth channel and no sandbox internals.

Job (stdin): {base_url, run_id, part, submission_dir, kit_src, result_path, target?}
Result (result_path): {ok, sid_hex?, plaintext_hex?, blocks?, not_implemented?,
                       limit?, infrastructure?, error?}

The result file is replaced atomically and, in a chained run, written as soon as
the downgrade stage completes: if the coordinator then kills this process at the
wall-clock limit, the completed stage is still on record.
"""
import base64
import importlib.util
import json
import os
import sys


def _load_attack(submission_dir):
    path = os.path.join(submission_dir, "exercises", "attack.py")
    spec = importlib.util.spec_from_file_location("student_attack", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_result(path, result):
    """Replace the result file atomically (a kill mid-write keeps the old one)."""
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(result, fh)
    os.replace(tmp, path)


def _blocks_to_json(blocks):
    out = []
    for idx, raw in sorted((blocks or {}).items()):
        out.append({"index": int(idx), "plaintext_hex": bytes(raw).hex()})
    return out


def main():
    job = json.loads(sys.stdin.read())
    sub = job["submission_dir"]
    # Import path, highest priority first: the kit (so exercise_api is the kit's,
    # never a student override), then the submission root and its exercises/ dir
    # so a student's own helper modules import (`import helper`, `from exercises
    # import helper`) rather than raising ModuleNotFoundError.
    sys.path.insert(0, os.path.join(sub, "exercises"))
    sys.path.insert(0, sub)
    sys.path.insert(0, job["kit_src"])
    from exercise_api import ExerciseAPI, ExerciseAPIError, ExerciseTransportError
    api = ExerciseAPI(job["base_url"], job["run_id"])
    attack = _load_attack(sub)
    part = job["part"]

    result = {"ok": False}
    try:
        if part == "2":
            sid = attack.downgrade(api)
            result = {"ok": True, "sid_hex": bytes(sid).hex()}
        elif part == "experiment":
            attack.experiment(api)
            result = {"ok": True}
        elif part in ("3", "chain"):
            if part == "chain":
                sid = attack.downgrade(api)
                result["sid_hex"] = bytes(sid).hex()
                # Record the completed stage now, so a timeout during recovery
                # still reports the downgrade (the coordinator reads this file
                # after killing the worker).
                _write_result(job["result_path"], dict(result, stage="recover"))
                st = api.status()
                target = st["target"]
            else:
                target = job["target"]
                target["body"] = base64.b64decode(target.pop("payload"))
            rec = attack.recover(api, target)
            pt = rec.get("plaintext")
            result["ok"] = True
            result["plaintext_hex"] = None if pt is None else bytes(pt).hex()
            result["blocks"] = _blocks_to_json(rec.get("blocks"))
    except NotImplementedError as e:
        # Keep completed stages (especially the chained downgrade's sid) so
        # the coordinator can still verify them after a later stage fails.
        result.update(ok=False, not_implemented=True, error=str(e))
    except ExerciseAPIError as e:
        # A spent budget (429) or a sandbox failure (500) is not a student bug;
        # name it so the coordinator reports it separately (KIT-SPEC §7.2).
        result.update(ok=False, error=f"ExerciseAPIError: {e}")
        if e.status == 429:
            result["limit"] = e.code
        elif e.status == 500:
            result["infrastructure"] = e.code
    except ExerciseTransportError as e:
        result.update(ok=False, error=f"ExerciseTransportError: {e}",
                      infrastructure="transport")
    except Exception as e:                        # student bug
        result.update(ok=False, error=f"{type(e).__name__}: {e}")
    # Emit the result on its own channel so nothing the student printed to
    # stdout can corrupt it (a stray print() must not break the run).
    _write_result(job["result_path"], result)


if __name__ == "__main__":
    main()
