# Post-Quantum Crypto-Agility and Algorithm-Deprecation Framework

A framework for retiring a compromised or deprecated post-quantum
algorithm (ML-KEM, ML-DSA, or SLH-DSA) across validators, light
clients, and the ledger without a chain halt, with a runnable
deprecation drill and measured migration costs.

The worked example retires ML-DSA-65 (the deployed validator
signature scheme) in favour of SLH-DSA-SHA2-192s (same security
category, different mathematical family).

## Contents

- `framework.md` — algorithm inventory, deprecation triggers,
  migration phases (announcement → dual-signing → cutover →
  deprecation), key-rotation procedures, ledger activation via
  amendment, and rollback protection. Every substantive claim
  carries one label: [FAKTA], [ESTIMASI], or [ANALISIS].
- `cost-table.md` — measured key/signature sizes, verification
  times, cross-implementation results, and ledger-growth model.
- `citations.md` — primary sources (FIPS 203/204/205, NIST IR
  8547, CNSA 2.0, amendment documentation) with URLs and access
  dates.
- `scripts/deprecation_drill.py` — the staged deprecation drill.
  Simulates a compromised-algorithm announcement, migrates test
  keys and signatures to the replacement algorithm in stages, and
  verifies the migrated chain state (signatures + state hash) at
  each stage. All keys are freshly generated random test keys;
  no real keys are used.
- `scripts/measure_costs.py` — measures sizes and timings for the
  full algorithm inventory with liboqs 0.16.0 and asserts them
  against the FIPS tables.
- `scripts/compare_runs.py` — verifies the 5 drill runs are
  deterministic in their invariants.
- `scripts/build_drivers.sh` — rebuilds the C reference drivers
  in `bin/` from pinned upstream commits.
- `drivers/` — driver sources for the FIPS 204 / FIPS 205
  reference implementations (ML-DSA-65, SLH-DSA-SHA2-192s).
- `bin/` — prebuilt driver binaries (ML-DSA-65,
  SLH-DSA-SHA2-192s, plus ML-DSA-44 / SLH-DSA-SHA2-128s from the
  earlier interop work for reference).
- `logs/` — unedited stdout of the 5 drill runs (`run-1.log` …
  `run-5.log`), the cost measurement (`costs.log`), and the
  determinism comparison (`compare-runs.log`).
- `ledger/` — final simulated chain state after each drill run
  (`final-state-runN.json`) and the invariant block per run
  (`invariants-runN.json`).

## How to run

```sh
# 1. Rebuild the drivers (optional; prebuilt binaries in bin/)
bash scripts/build_drivers.sh

# 2. Run one drill (about 35 s)
python3 scripts/deprecation_drill.py 1 ledger

# 3. Measure costs (needs a python with liboqs-python installed)
python3 scripts/measure_costs.py

# 4. Compare 5 runs for determinism
python3 scripts/compare_runs.py
```

## Measured results (summary)

- Drill: 5 consecutive runs, 79 checks each, 79 passed, 0 failed.
  16 signatures verified per run; final state hash is a full
  64-hex SHA-256.
- Migration cost (measured, liboqs 0.16.0): ML-DSA-65 → 
  SLH-DSA-SHA2-192s: signature 3,309 B → 16,224 B (4.9×);
  signing 0.00014 s → 1.32 s (median); verification 0.000052 s
  → 0.0011 s (median). At quorum 4, signature bytes per
  checkpoint rise from 13,236 to 64,896.
- ML-DSA-65 signatures verify in both directions between the
  reference driver and liboqs. SLH-DSA-SHA2-192s signatures from
  the round-3 reference do NOT verify under liboqs (known
  pre-FIPS-205 divergence; see `cost-table.md` §4); the drill
  verifies each signature with the implementation that produced
  it.

## Verification

```sh
sha256sum -c SHA256SUMS
```
