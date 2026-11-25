#!/usr/bin/env python3
"""A worked example of driving the sandbox: relay one honest negotiation.

This shows the queue/deliver/inject mechanics and the status fields, without
any attack. Run it directly from the extracted kit:

    python tests/honest_relay_example.py

It launches a negotiation-mode sandbox, calls start, and faithfully forwards
every message between the bots (the thing an honest relay does), then prints
the suite the two bots negotiated. An attacker does not forward faithfully —
see EXERCISES.md.
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
KIT = os.path.dirname(HERE)
sys.path.insert(0, KIT)
from exercise_api import ExerciseAPI  # noqa: E402


def main():
    proc = subprocess.Popen(
        [sys.executable, os.path.join(KIT, "sandbox.py"), "--mode", "negotiation",
         "--port", "0"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        ready = json.loads(proc.stdout.readline())
        api = ExerciseAPI(ready["base_url"], ready["run_id"])
        api.start()                      # Alice's HELLO is now queued
        # Honest relay: deliver whatever is pending until nothing new appears.
        for step in range(50):
            pending = api.queue()
            if not pending:
                break
            env = pending[0]
            emitted = api.deliver(env["id"])
            print(f"step {step}: delivered id={env['id']} "
                  f"{env['from']}->{env['to']} ({len(env['body'])} B); "
                  f"bot emitted {len(emitted)} message(s)")
        st = api.status()
        neg = st["negotiation"]
        if neg:
            print(f"negotiated suite: {neg['suite']} "
                  f"({'JM2 hybrid' if neg['suite'] == 2 else 'JM1 legacy'})")
        else:
            print("no shared session established")
        print(f"counts: {st['counts']}")
    finally:
        proc.terminate()


if __name__ == "__main__":
    main()
