#!/usr/bin/env python3
"""compare_runs.py -- verify the 5 drill runs are deterministic.

Reads pack/ledger/invariants-run{N}.json for N=1..5 and checks that
every field except the run number is identical. Also checks that
each run's log ends with ALL CHECKS PASSED and that the final state
hashes differ across runs (expected: fresh random test keys each
run, so identical hashes would indicate a broken RNG or replayed
state, not determinism).

Usage: python3 compare_runs.py
Exit 0 iff invariants are identical across all 5 runs and all 5
logs report all checks passed.
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LEDGER = os.path.join(HERE, "..", "ledger")
LOGS = os.path.join(HERE, "..", "logs")


def main():
    invariants = []
    for n in range(1, 6):
        with open(os.path.join(LEDGER, "invariants-run%d.json" % n)) as f:
            invariants.append(json.load(f))
    base = {k: v for k, v in invariants[0].items() if k != "run"}
    ok = True
    for inv in invariants[1:]:
        rest = {k: v for k, v in inv.items() if k != "run"}
        if rest != base:
            ok = False
            print("MISMATCH run %s vs run 1:" % inv["run"])
            for k in sorted(set(base) | set(rest)):
                if base.get(k) != rest.get(k):
                    print("  %s: %r != %r" % (k, base.get(k), rest.get(k)))
    print("invariants identical across runs 1-5 (excluding run number): %s"
          % ok)
    print("shared invariants: %s" % json.dumps(base, sort_keys=True))

    hashes = []
    for n in range(1, 6):
        with open(os.path.join(LEDGER, "final-state-run%d.json" % n)) as f:
            state = json.load(f)
        with open(os.path.join(LOGS, "run-%d.log" % n)) as f:
            log = f.read()
        passed = "ALL CHECKS PASSED" in log
        print("run %d: log ALL CHECKS PASSED=%s, checkpoints=%d, "
              "validators=%d" % (n, passed, len(state["checkpoints"]),
                                 len(state["validators"])))
        if not passed:
            ok = False
        import hashlib
        h = hashlib.sha256(
            json.dumps(state, sort_keys=True,
                       separators=(",", ":")).encode()).hexdigest()
        hashes.append(h)
    print("recomputed final-state hashes (full SHA-256, from stored JSON):")
    for n, h in enumerate(hashes, 1):
        print("  run %d: %s" % (n, h))
    distinct = len(set(hashes)) == 5
    print("all 5 final-state hashes distinct (fresh random keys): %s"
          % distinct)
    if not distinct:
        ok = False
    print("DETERMINISM VERDICT: %s"
          % ("PASS -- identical outcomes, distinct random state per run"
             if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
