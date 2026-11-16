# Measured migration-cost table

All numbers below are measured on this machine on 2026-11-16.
Source log: `logs/costs.log` (unedited output of
`scripts/measure_costs.py`, liboqs 0.16.0 via liboqs-python).
Drill timings are from `logs/run-1.log` … `logs/run-5.log`
(unedited output of `scripts/deprecation_drill.py`, C reference
drivers). Sizes were asserted equal to the FIPS tables by the
measurement script itself; every size assertion passed.

Claim labels: [FAKTA] verified fact with source; [ESTIMASI]
modelled number; [ANALISIS] interpretation. The per-checkpoint
and per-N-checkpoints rows are [ESTIMASI] (linear models from
measured sizes); all other rows are [FAKTA] (direct measurements).

## 1. Signature schemes — sizes (bytes)

[FAKTA] Measured with liboqs 0.16.0; asserted equal to FIPS 204
Table 2 (ML-DSA) and FIPS 205 Table 2 (SLH-DSA). All assertions
passed.

| Algorithm | Category | pk | sk | sig |
|---|---|---|---|---|
| ML-DSA-44 | 2 | 1,312 | 2,560 | 2,420 |
| ML-DSA-65 | 3 | 1,952 | 4,032 | 3,309 |
| ML-DSA-87 | 5 | 2,592 | 4,896 | 4,627 |
| SLH-DSA-SHA2-128s | 1 | 32 | 64 | 7,856 |
| SLH-DSA-SHA2-192s | 3 | 48 | 96 | 16,224 |
| SLH-DSA-SHA2-256s | 5 | 64 | 128 | 29,792 |

## 2. Signature schemes — timings (seconds, median)

[FAKTA] liboqs 0.16.0, this machine, 2026-11-16. ML-DSA n=50,
SLH-DSA-128s n=20, SLH-DSA-192s/256s n=5.

| Algorithm | Sign (median) | Verify (median) |
|---|---|---|
| ML-DSA-44 | 0.000066 | 0.000034 |
| ML-DSA-65 | 0.000141 | 0.000052 |
| ML-DSA-87 | 0.000151 | 0.000074 |
| SLH-DSA-SHA2-128s | 0.7189 | 0.000744 |
| SLH-DSA-SHA2-192s | 1.3152 | 0.001105 |
| SLH-DSA-SHA2-256s | 1.1642 | 0.001541 |

[FAKTA] The same SLH-DSA-SHA2-192s signing operation measured
through the sphincsplus round-3 C reference driver in the drill
takes a median of 4.04–4.17 s per signature across the 5 runs
(n=8 per run), versus 1.32 s under liboqs. Verification through
the reference driver is a median of 0.0048–0.0054 s, versus
0.0011 s under liboqs. Implementation choice changes signing
latency by ~3×; both are reported, neither is hidden.

[ANALISIS] SLH-DSA-256s signing measured slightly faster than
SLH-DSA-192s under liboqs (1.16 s vs 1.32 s, n=5 each). With n=5
this difference is within run-to-run variation and is not treated
as a real ordering; a larger sample would be needed to rank the
two. The robust conclusion is that both are on the order of one
second, i.e. ~10,000× slower to sign than ML-DSA-65.

## 3. Key encapsulation — sizes and timings

[FAKTA] Measured with liboqs 0.16.0; asserted equal to FIPS 203
Table 3. All assertions passed. n=50.

| Algorithm | pk | sk | ct | ss | Encap (median s) | Decap (median s) |
|---|---|---|---|---|---|---|
| ML-KEM-512 | 800 | 1,632 | 768 | 32 | 0.0000145 | 0.0000153 |
| ML-KEM-768 | 1,184 | 2,400 | 1,088 | 32 | 0.0000204 | 0.0000225 |
| ML-KEM-1024 | 1,568 | 3,168 | 1,568 | 32 | 0.0000249 | 0.0000285 |

[FAKTA] Moving key establishment from ML-KEM-768 (the NIST
recommended default) to ML-KEM-1024 costs +384 B public key,
+768 B secret key, +480 B ciphertext, and ~22% more encap time /
~27% more decap time at these medians. All ML-KEM operations
stay under 30 microseconds.

## 4. Cross-implementation verification

[FAKTA] Measured 2026-11-16 (`logs/costs.log`).

| Check | Result |
|---|---|
| ML-DSA-65 reference-driver signature → liboqs verify | VALID |
| ML-DSA-65 liboqs signature → reference-driver verify | VALID |
| SLH-DSA-SHA2-192s reference-driver (round-3) signature → liboqs verify | INVALID |
| SLH-DSA-SHA2-192s reference-driver sizes vs FIPS 205 Table 2 (pk 48 / sk 96 / sig 16,224) | MATCH |

[ANALISIS] The SLH-DSA INVALID is the known round-3-reference
vs FIPS-205 divergence (robust thash masking, context-string
encoding), previously measured at the 128s parameter set. It does
not affect the drill, which verifies every signature with the
same implementation that produced it. It does mean the pack makes
no cross-implementation SLH-DSA claim for the round-3 reference.

## 5. Ledger-growth impact

[ESTIMASI] Linear model from the measured signature sizes in §1,
quorum 4 signatures per checkpoint, signature bytes only (no
other checkpoint fields). The drill's simulated ledger uses 5
validators with quorum 4 (80%).

| Scheme per checkpoint | Signature bytes / checkpoint |
|---|---|
| Old: ML-DSA-65 only | 13,236 |
| Dual-signing: ML-DSA-65 + SLH-DSA-SHA2-192s | 78,132 |
| New: SLH-DSA-SHA2-192s only | 64,896 |

| Checkpoints | Old (MB) | Dual (MB) | New (MB) | New − Old (MB) |
|---|---|---|---|---|
| 10,000 | 132.36 | 781.32 | 648.96 | +516.60 |
| 100,000 | 1,323.60 | 7,813.20 | 6,489.60 | +5,166.00 |
| 1,000,000 | 13,236.00 | 78,132.00 | 64,896.00 | +51,660.00 |

[FAKTA] Validator key storage (pk + sk): ML-DSA-65 5,984 B;
SLH-DSA-SHA2-192s 144 B; both keys during dual-signing 6,128 B.
Key storage shrinks by 97.6% under the replacement; signature
storage grows 4.9× per checkpoint.

## 6. Drill run summary

[FAKTA] `scripts/deprecation_drill.py`, 5 consecutive runs,
2026-11-16. Each run: 79 checks, 79 passed, 0 failed. Stages:
GENESIS → ANNOUNCE → DUAL-SIGNING → CUTOVER → DEPRECATION.
16 signatures verified per run across 3 checkpoints (4 + 8 + 4);
final verification re-verifies all 16. Determinism verdict from
`scripts/compare_runs.py`: PASS — invariants identical across
all 5 runs; final-state hashes distinct per run (fresh random
test keys each run, as expected).

| Run | Checks passed | Final state hash (SHA-256, full) |
|---|---|---|
| 1 | 79 / 79 | 62988121307bf6846a726d59acb3e140513dd38e1f9aec9a0d749cb413501b48 |
| 2 | 79 / 79 | 225eb0d35eae217d209b4d0c5f66ecbba62a0a6efe9862fe6b2b76e9db693aa2 |
| 3 | 79 / 79 | 9b5af012657c95d30af10571ce2418773b10018aa2e41c28e6021f50a733f15d |
| 4 | 79 / 79 | c22646abdda348905461212b9f0e92de5bc8d37409a9d7ace0ba78f4cf55c285 |
| 5 | 79 / 79 | 60dceb8c901eed855aac53b9781724651628a77a8ec5a99d8c9bb7ba50335b27 |

## 7. How to reproduce

```sh
# Cost measurement (needs a python with liboqs-python; the venv
# used here is recorded in logs/costs.log header)
python3 scripts/measure_costs.py

# Deprecation drill, one run (about 35 s; needs gcc-built drivers
# in bin/, or rebuild them first with scripts/build_drivers.sh)
python3 scripts/deprecation_drill.py 1 ledger

# Five-run determinism comparison
python3 scripts/compare_runs.py
```

All logs in `logs/` are the unedited stdout of these commands.
