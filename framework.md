# Post-Quantum Crypto-Agility and Algorithm-Deprecation Framework

Scope: retiring a compromised or deprecated post-quantum algorithm
from a validator-signed ledger without a chain halt. The worked
example in this pack retires ML-DSA-65 (the deployed validator
signature scheme) in favour of SLH-DSA-SHA2-192s. The framework
itself is algorithm-neutral: the same phases apply to retiring
ML-KEM, ML-DSA or SLH-DSA in any parameter set.

Claim labels used throughout (exactly one per substantive claim):

- [FAKTA] — verified fact, with source and date.
- [ESTIMASI] — modelled or reported number, never a measured fact.
- [ANALISIS] — interpretation; never presented as fact.

Sources are numbered [S1]…[S8]; full references are in
`citations.md`.

---

## 1. Algorithm inventory

### 1.1 Deployed and approved algorithms

| Algorithm | Parameter set | Category | pk (B) | sk (B) | sig / ct (B) | Status in this framework |
|---|---|---|---|---|---|---|
| ML-DSA | ML-DSA-44 | 2 | 1,312 | 2,560 | 2,420 | Approved alternative |
| ML-DSA | ML-DSA-65 | 3 | 1,952 | 4,032 | 3,309 | DEPLOYED — retired in the drill |
| ML-DSA | ML-DSA-87 | 5 | 2,592 | 4,896 | 4,627 | Approved alternative |
| SLH-DSA | SLH-DSA-SHA2-128s | 1 | 32 | 64 | 7,856 | Approved alternative |
| SLH-DSA | SLH-DSA-SHA2-192s | 3 | 48 | 96 | 16,224 | REPLACEMENT in the drill |
| SLH-DSA | SLH-DSA-SHA2-256s | 5 | 64 | 128 | 29,792 | Approved alternative |
| ML-KEM | ML-KEM-512 | 1 | 800 | 1,632 | ct 768 | Approved |
| ML-KEM | ML-KEM-768 | 3 | 1,184 | 2,400 | ct 1,088 | Recommended default |
| ML-KEM | ML-KEM-1024 | 5 | 1,568 | 3,168 | ct 1,568 | Approved |

- [FAKTA] NIST finalized FIPS 203 (ML-KEM), FIPS 204 (ML-DSA) and
  FIPS 205 (SLH-DSA) on 13 August 2024 [S1][S2][S3]. The sizes in
  the table are the FIPS 203 Table 3, FIPS 204 Table 2 and FIPS 205
  Table 2 values, and each was re-measured in this pack with
  liboqs 0.16.0 and with the C reference drivers; all measured sizes
  match the tables exactly (`logs/costs.log`).
- [FAKTA] NIST IR 8547 (final, October 2026) lists ML-KEM-512/768/
  1024 as the approved post-quantum key-establishment schemes and
  ML-DSA-44/65/87 plus the twelve SLH-DSA parameter sets as the
  approved post-quantum signature schemes (Tables 3 and 5) [S4].
- [FAKTA] IR 8547 states: "NIST recommends using ML-KEM-768 as
  the default parameter set, as it provides a large security margin
  at a reasonable performance cost" (Table 5 discussion) [S4].
- [FAKTA] The deployed ledger signs with ML-DSA-65 from genesis:
  1,952-byte public keys, 3,309-byte signatures [S5]. The drill
  therefore retires ML-DSA-65, not a hypothetical scheme.
- [FAKTA] CNSA 2.0 (NSA, September 2022) requires ML-KEM-1024 for
  key establishment and ML-DSA-87 for signatures on national
  security systems, with AES-256, SHA-384/512, and LMS/XMSS for
  firmware/software signing [S6]. CNSA 2.0 binds national security
  systems only; it is included here as the strictest public
  reference point, not as a requirement on this ledger.
- [FAKTA] HQC was selected as an alternative to ML-KEM; a FIPS
  specifying HQC-KEM is under development (IR 8547 §4.1.2) [S4].
  No HQC parameter set is approved at the time of writing, so HQC
  is inventoried as a future fallback, not a migration target.

### 1.2 Inventory rules

1. Every algorithm in production must appear in the inventory with
   its parameter set, category, key/signature sizes, implementation
   (library name and version), and the ledgers or services that use
   it. An algorithm with no inventory entry must not sign ledger
   data.
2. The inventory records two replacement candidates per deployed
   algorithm, from different mathematical families where possible
   (lattice vs. hash-based), so that a break of one family does not
   leave the ledger with no migration path.
   [ANALISIS] Lattice (ML-DSA) and hash-based (SLH-DSA) schemes
   rest on unrelated hardness assumptions; a cryptanalytic break
   of one does not imply a break of the other. The drill's choice
   — ML-DSA-65 to SLH-DSA-SHA2-192s — is the cross-family move
   for that reason.
3. Inventory entries are versioned and hashed; the inventory hash
   is published with each release, so a validator can prove which
   inventory it runs.

## 2. Deprecation triggers

A deprecation is opened when any trigger fires. Triggers are
checked in this order; the first firing trigger sets the severity.

| # | Trigger | Severity | Response |
|---|---|---|---|
| T1 | Practical cryptanalysis or forgery demonstrated against the deployed algorithm or parameter set | Critical | Emergency deprecation: skip to dual-signing immediately; cutover at the next amendment window |
| T2 | A standards body deprecates the algorithm (e.g. NIST IR 8547 schedule) | Scheduled | Planned deprecation on the published dates |
| T3 | A credible theoretical attack reduces the claimed security category below the deployed category | High | Open deprecation; migrate within one release cycle |
| T4 | Implementation flaw (side channel, faulty RNG, non-conformance) in the deployed library | High | Replace the implementation first; deprecate the algorithm only if the flaw is algorithmic |
| T5 | The replacement algorithm is standardized and the deployed algorithm is superseded by policy (e.g. CNSA 2.0) | Planned | Planned deprecation on the policy dates |
| T6 | Quantum-capability milestone that shortens the harvest-now-decrypt-later window for key establishment | High | Accelerate the ML-KEM migration; signatures unaffected |

- [FAKTA] NIST IR 8547 (final, October 2026) states: "NIST will
  deprecate quantum-vulnerable public-key cryptography after 2030
  and disallow its use under NIST standards and guidelines after
  2035" (Tables 2 and 4: ECDSA, EdDSA, RSA signatures and DH/MQV
  key establishment, all at ≥112 bits, deprecated after 2030,
  disallowed after 2035) [S4]. This is trigger T2's reference
  schedule for classical algorithms.
- [FAKTA] Under EO 14412 and OMB M-26-15, federal high-value
  assets and high-impact systems must adopt post-quantum key
  establishment by 31 December 2030 and post-quantum signatures by
  31 December 2031; TLS 1.3 support is required by 2 January 2030
  (IR 8547 §4) [S4]. These deadlines are earlier than the general
  2030–2035 window and constrain only federal systems.
- [FAKTA] IR 8547 defines the status terms: "Deprecated means
  that the algorithm and key length/strength may be used, but
  there is some security risk. The data owner must examine this
  risk potential and decide whether to continue"; "Disallowed
  means that the algorithm … is no longer allowed for the stated
  purpose"; "Legacy use means that the algorithm … may only be
  used to process already protected information (e.g. … to verify
  a digital signature)" (§4.1) [S4]. The framework's Stage 4
  implements exactly this distinction: new signatures rejected,
  verification of already-signed data still permitted.
- [ANALISIS] Trigger T1 is the only trigger that justifies
  compressing the migration phases. A scheduled deprecation (T2)
  should never be compressed into an emergency, because the
  compressed path skips the dual-signing observation window that
  catches implementation defects before cutover.

## 3. Migration phases

The migration is a sequence of ledger states. Each phase is gated:
the next phase starts only when the exit criteria of the current
phase are met and verified. No phase requires a chain halt; at
every point the ledger keeps producing validated checkpoints.

### Phase 0 — Inventory and readiness (before any announcement)

- Entry criteria: inventory (§1) is complete; replacement
  algorithm implementations are available in at least two
  independent implementations; the deprecation drill
  (`scripts/deprecation_drill.py`) passes on the replacement.
- Exit criteria: drill green; cost table (`cost-table.md`)
  published; amendment text drafted.

### Phase 1 — Announcement

- The deprecation announcement is recorded on-ledger: algorithm,
  trigger, severity, migration target, and phase dates. The
  announcement digest (SHA-256) is published so any party can
  verify which announcement validators acted on.
- The deployed algorithm's status becomes DEPRECATED. Existing
  keys keep signing; no new long-lived keys are issued under the
  deprecated algorithm.
- [FAKTA] In the drill, the announcement digest is a full SHA-256
  printed in the unedited log, e.g. run 1:
  `28c1b55d990158e2ec561a70ea49d48908b8b433d1ddb6a848e4dd6d1e32137d`
  (`logs/run-1.log`).

### Phase 2 — Dual-signing

- Validators generate replacement-algorithm keys and publish the
  new public keys on-ledger, bound to their existing identities.
- Checkpoints carry two signatures: one under the deprecated
  algorithm, one under the replacement. A checkpoint is valid only
  if the quorum is met under BOTH algorithms.
- The dual-signing window is an observation window: signature
  sizes, signing latency, and verification failures are measured
  and compared against the cost table before cutover is allowed.
- [FAKTA] In the drill, a dual-signed checkpoint carries 8
  signatures (4 validators × 2 algorithms) totalling 78,132 bytes
  of signature data at quorum 4, versus 13,236 bytes under
  ML-DSA-65 alone (`logs/costs.log`, ledger-growth model).
- [ANALISIS] Dual-signing is the most expensive phase and the
  most valuable: it is the only phase in which a defect in the
  replacement implementation is caught while the old algorithm
  still provides a valid signature on every checkpoint.

### Phase 3 — Cutover

- Checkpoints carry replacement-algorithm signatures only.
- The deprecated algorithm's keys are marked RETIRED. They are
  retained (public keys only) for legacy verification of
  pre-cutover checkpoints.
- Cutover is enacted by ledger amendment, not by a flag day in
  validator binaries: see §5.
- [FAKTA] In the drill, the cutover checkpoint carries 4
  SLH-DSA-SHA2-192s signatures (64,896 bytes at quorum 4) and
  verifies cleanly; the state hash changes at every stage, and
  the final state hash is a full 64-hex SHA-256
  (`logs/run-1.log` … `logs/run-5.log`).

### Phase 4 — Deprecation (retirement)

- Policy layer rejects NEW signatures under the retired algorithm,
  even if they are cryptographically valid. The drill demonstrates
  this directly: a post-cutover ML-DSA-65 signature verifies
  cryptographically (`crypto_verify=True`) but is refused by
  policy (`policy_accept=False`).
- Legacy use continues: signatures created before cutover still
  verify. This matches the IR 8547 "legacy use" definition (§2).
- The retired algorithm's secret keys are destroyed after the
  retention period; public keys are kept for historical
  verification.
- Rollback protection (§6) is enforced from this phase onward.

## 4. Key-rotation procedures

1. **Generation.** Replacement keys are generated on the validator
   host with the approved implementation, never imported from
   another machine. Key-generation time is measured: ML-DSA-65
   median 0.0016 s, SLH-DSA-SHA2-192s median 0.46 s in the drill
   (reference implementations, this machine).
2. **Binding.** The new public key is published in a checkpoint
   signed under the OLD algorithm, binding the new identity to the
   old one. A validator that cannot produce the old-algorithm
   binding signature cannot rotate.
3. **Overlap.** Old and new keys coexist during Phase 2. The old
   secret key must not be deleted until cutover is confirmed on
   the ledger (amendment active), because a failed cutover rolls
   back to old-algorithm signing (§6).
4. **Retirement.** After cutover plus the retention period, the
   old secret key is destroyed (overwritten, not merely deleted).
   Destruction is attested by the validator operator and recorded.
5. **Compromise rotation (T1).** If the trigger is a compromise,
   rotation is per-validator and immediate: a validator whose key
   is suspected compromised rotates first and publishes the new
   key bound by a quorum-signed checkpoint, rather than waiting
   for the network-wide phase schedule.
   [ANALISIS] A compromised key cannot bind its own replacement
   (the binding signature itself is untrusted), which is why the
   quorum-signed binding exists: the network, not the suspect
   validator, vouches for the new key.

## 5. Ledger activation: amendment mechanism

- [FAKTA] Upstream (XRPL heritage), an amendment passes when it
  holds more than 80% validator support for two weeks; every 256th
  ledger is a flag ledger at which support is evaluated, and an
  `EnableAmendment` pseudo-transaction then enables it [S7].
- [FAKTA] In this ledger's fork, the amendment threshold after
  the majority-calculation fix is 67% (ratio 67/100), with the
  two-week majority time unchanged; the pre-fix threshold was
  204/256. At the stated validator count of 53, passage requires
  support from at least 36 validators [S8]. These constants were
  re-verified live from the fork source on 2026-11-16.
- [FAKTA] An enabled amendment cannot be disabled except by a
  new amendment; a server whose code has removed an enabled
  amendment becomes amendment-blocked and cannot validate [S7].
  This is the ledger-level rollback protection: cutover cannot be
  silently undone by a single operator.
- [ANALISIS] The amendment mechanism is what makes a no-halt
  migration possible: the algorithm switch is a rule change
  voted on and activated at a known ledger, not a coordinated
  restart. The drill simulates this with epoch-gated checkpoints:
  a checkpoint is accepted only if its epoch is strictly greater
  than the previous checkpoint's epoch and its
  `prev_state_hash` chains from the current state hash.

## 6. Rollback protection

Four independent checks, all demonstrated in the drill:

1. **Epoch monotonicity.** Checkpoint epochs must strictly
   increase. A replayed checkpoint reuses an epoch and is
   rejected.
2. **Hash chaining.** Each checkpoint commits to the previous
   state hash. A checkpoint whose `prev_state_hash` does not
   match the current state is rejected as a fork.
3. **Policy rejection of retired algorithms.** New signatures
   under a retired algorithm are rejected even when
   cryptographically valid (§3, Phase 4).
4. **Amendment irreversibility.** Once the cutover amendment is
   enabled, returning to the retired algorithm requires a new
   amendment with its own majority and two-week window (§5);
   there is no operator-level switch back.

- [FAKTA] The drill's negative controls all pass in all 5 runs:
  a tampered ML-DSA-65 signature is INVALID; a replayed
  checkpoint is rejected (height and prev-hash mismatch); a
  forked checkpoint with a wrong `prev_state_hash` is rejected;
  epochs are strictly increasing [0, 1, 2]
  (`logs/run-1.log` … `logs/run-5.log`, 79 checks per run,
  0 failed).

## 7. Migration costs (summary)

Full measured table: `cost-table.md`. Headlines (measured on this
machine, liboqs 0.16.0 unless noted):

| | ML-DSA-65 (old) | SLH-DSA-SHA2-192s (new) | Ratio |
|---|---|---|---|
| Public key | 1,952 B | 48 B | 0.025× |
| Secret key | 4,032 B | 96 B | 0.024× |
| Signature | 3,309 B | 16,224 B | 4.9× |
| Sign (median) | 0.00014 s | 1.32 s | ~9,400× |
| Verify (median) | 0.000052 s | 0.0011 s | ~21× |

- [FAKTA] The replacement's signatures are ~4.9× larger and its
  signing is ~9,400× slower (median, liboqs 0.16.0) than the
  deployed scheme, while verification stays near 1 ms. Signing
  cost dominates the migration budget, not verification.
- [ESTIMASI] At quorum 4, signature bytes per checkpoint rise
  from 13,236 (old) to 64,896 (new); over 1,000,000 checkpoints
  that is +51,660 MB of signature data versus the old scheme.
  This is a linear model from measured per-signature sizes, not a
  measurement of a live ledger.
- [ANALISIS] The signing-latency increase is the binding
  operational constraint: a validator that signs once per ledger
  can absorb ~1.3 s per signature, but any service that signs
  many artifacts per second cannot move to SLH-DSA-SHA2-192s
  without batching or a faster implementation. Where signing
  throughput matters, ML-DSA-87 (same family, category 5) is the
  cheaper migration target; where family diversity matters,
  SLH-DSA is the target despite the cost.

## 8. What this framework does not cover

- [FAKTA] No approved HQC parameter set exists at the time of
  writing (IR 8547 §4.1.2) [S4]; the framework cannot name HQC
  migration sizes or costs, and does not try.
- The drill simulates 5 validators with quorum 4; the live
  network's stated validator count is 53 with a 67% threshold
  [S8]. Quorum arithmetic scales, but the drill does not measure
  53-validator consensus behaviour.
- [FAKTA] The SLH-DSA signatures in the drill are produced by
  the sphincsplus round-3 reference implementation, which predates
  FIPS 205. A signature produced by that reference does NOT verify
  under liboqs 0.16.0 (measured: INVALID, `logs/costs.log`). The
  drill verifies every signature with the same implementation
  that produced it, and the measured sizes match FIPS 205 Table 2
  exactly. Cross-implementation SLH-DSA verification of the
  round-3 reference is therefore NOT claimed; it is recorded as a
  known divergence. ML-DSA-65, by contrast, verifies in both
  directions (reference ↔ liboqs, both VALID).
- The drill's compromise is simulated. No real cryptanalysis of
  ML-DSA-65 is claimed, and none is known to the authors at the
  time of writing.
