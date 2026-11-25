#!/usr/bin/env python3
"""Package the A2 final submission: client, checkpoint, and Parts 2-3 exercises.

    python package_final.py --submission /path/to/submission --output final.zip

Builds one archive with no extra enclosing directory, containing the handout's
top-level files, any supporting student modules, the preserved `checkpoint/`
snapshot, and selected `exercises/` and run-evidence files. It validates
structure, not success or prose.

Collection is an explicit manifest (KIT-SPEC §8), not "whatever is present": a
file ships only if it matches a named include rule (required docs, the
checkpoint's source and required docs, student `.py` source, the exercise
template and screenshots, and selected run evidence -- `result.json` and the transport
trace). An arbitrary suffix under `exercises/` is not evidence that a file
should ship, so stray material such as a `channel-key.pem` or a
`contribution-log.md` dropped beside the attack is left out.

It never ships private material: virtual environments, caches, VCS data, the
local identity store, course credentials, the staff kit (the reference package
and these drivers), or anonymous-report material (the report, contribution
logs, receipts, tags, attendance proofs, and channel private keys). Grading
substitutes its own support and helper code, so a submitted copy is not trusted.
"""
import argparse
import os
from pathlib import Path
import zipfile

# Handout §7 top-level files (checkpoint/ and exercises/ use include rules below).
REQUIRED = ("protocol.py", "padding.py", "padding_first_attempt.py",
            "design.md", "written.md", "ai-usage.md")
REQUIRED_EXERCISES = ("exercises/attack.py", "exercises/README.md")

# Directories never walked for student source.
SKIP_DIRS = {".git", ".svn", ".hg", ".venv", "venv", "env", ".jmessage",
             "__pycache__", ".anon-report", ".agent-notes", "node_modules",
             ".pytest_cache", ".mypy_cache"}
# Supplied kit material that must never ride along in a submission.
SKIP_TOPLEVEL = {"jmessage_reference", "sandbox.py", "exercise_api.py",
                 "run_exercises.py", "_worker.py", "reference_client.py",
                 "package_final.py", "check_environment.py", "requirements.txt",
                 "run_checks.py", "client.py", "local_relay.py",
                 "package_submission.py"}
# Private anonymous-report artefacts (handout §7, AGENTS integrity). These are
# a hard backstop: they are excluded everywhere, even under checkpoint/, and
# even if some future include rule would otherwise match them.
SKIP_NAMES = {"agent-report.md", "attendance.json",
              "contribution-log.md", "contribution_log.md"}
SKIP_SUFFIXES = (".receipt.json", ".pem", ".key", ".tag")

# Screenshots the write-up may index as evidence (KIT-SPEC §7.2, §8).
IMAGE_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".pdf")


def _check_symlinks(root, path):
    if path.is_symlink():
        raise ValueError(f"refusing symlink: {path.relative_to(root)}")
    for parent in path.parents:
        if parent == root.parent:
            break
        if parent.is_symlink():
            raise ValueError(f"refusing symlinked directory: {parent.relative_to(root)}")


def _excluded(rel: Path) -> bool:
    parts = rel.parts
    if any(p in SKIP_DIRS for p in parts):
        return True
    if any(p.startswith(".") for p in parts):
        return True
    if parts[0] in SKIP_TOPLEVEL:
        return True
    if rel.name in SKIP_NAMES or rel.name.endswith(SKIP_SUFFIXES):
        return True
    return False


def _is_run_evidence(rel: Path) -> bool:
    """Selected run artefacts: the JSON result and the transport trace (§7.2, §8).

    The write-up cites `run-*/result.json` and `run-*/transport-trace.jsonl`;
    those plus the captured worker output and any referenced screenshots ship.
    Full oracle logs are not required and nothing else under a run dir ships.
    """
    if not rel.parts[0].startswith("run-"):
        return False
    return (rel.name in ("result.json", "transport-trace.jsonl",
                         "worker-stdout.txt", "worker-stderr.txt")
            or rel.suffix.lower() in IMAGE_SUFFIXES)


def _manifest_keep(rel: Path) -> bool:
    """The explicit include manifest (KIT-SPEC §8): what may ship beyond the
    required files. Everything not matched here is left out, so an unexpected
    file type never rides along just because it sits under exercises/."""
    top = rel.parts[0]
    # Match the original checkpoint packager's source/document allowlist.
    # Preserve the selected bytes; arbitrary files such as key.json or receipts
    # must not ship just because they were copied into the snapshot directory.
    if top == "checkpoint":
        if len(rel.parts) < 2:
            return False
        snapshot = Path(*rel.parts[1:])
        if _excluded(snapshot) or any(p in {"tests", "checkpoint", "exercises"}
                                      for p in snapshot.parts[:-1]):
            return False
        return snapshot.as_posix() in REQUIRED or snapshot.suffix == ".py"
    # Student source modules: top-level, bundled support packages, and exercise
    # helpers -- but not a .py buried inside a run-evidence directory.
    if rel.suffix == ".py" and not top.startswith("run-"):
        return True
    # Screenshots the student's explanation indexes.
    if top == "exercises" and rel.suffix.lower() in IMAGE_SUFFIXES:
        return True
    # Selected run evidence (result + transcript).
    if _is_run_evidence(rel):
        return True
    return False


def collect(root: Path):
    """Return the sorted list of archive paths to include (relative, POSIX)."""
    chosen = {}
    # Required top-level files and exercise files (must be present).
    for name in REQUIRED + REQUIRED_EXERCISES:
        p = root / name
        _check_symlinks(root, p)
        if not p.is_file():
            raise ValueError(f"missing required file: {name}")
        chosen[name] = p
    # Everything else by the explicit manifest, outside excluded/private trees.
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if _excluded(rel) or not _manifest_keep(rel):
            continue
        _check_symlinks(root, path)
        chosen[rel.as_posix()] = path
    # The preserved checkpoint snapshot is required (KIT-SPEC §8).
    if not any(k == "checkpoint" or k.startswith("checkpoint/") for k in chosen):
        raise ValueError("missing preserved checkpoint/ snapshot")
    return sorted(chosen.items())


def package(submission, output):
    root = Path(submission).resolve()
    output = Path(output)
    if output.exists():
        raise FileExistsError(f"refusing to overwrite {output}")
    items = collect(root)
    seen = set()
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED) as z:
        for arcname, path in items:
            if arcname in seen:
                raise ValueError(f"duplicate archive path: {arcname}")
            seen.add(arcname)
            z.write(path, arcname)
    return items


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--submission", required=True)
    ap.add_argument("--output", default="final.zip")
    args = ap.parse_args(argv)
    try:
        items = package(args.submission, args.output)
    except (ValueError, FileExistsError, OSError) as e:
        ap.exit(1, f"Packaging failed: {e}\n")
    print(f"Wrote {len(items)} files to {args.output}:")
    for arcname, path in items:
        print(f"  {os.path.getsize(path):>8}  {arcname}")
    if not any(arcname.startswith("run-") for arcname, _ in items):
        print("Note: no run-*/ evidence found at the top of the submission directory. "
              "If exercises/README.md cites a run, re-run with "
              "--output <submission>/run-<name> and package again.")
    print("Inspect the archive before submitting. It excludes the staff kit, "
          "credentials, and anonymous-report material.")


if __name__ == "__main__":
    main()
