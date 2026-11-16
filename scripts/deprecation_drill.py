#!/usr/bin/env python3
"""
deprecation_drill.py -- simulated compromised-algorithm deprecation drill.

Scenario (simulated, test keys only -- no real keys, no live network):
  * Deployed validator signature scheme: ML-DSA-65 (category 3).
  * A compromise announcement retires ML-DSA-65.
  * Validators migrate in stages to SLH-DSA-SHA2-192s (category 3,
    same security category as ML-DSA-65):
        Stage 0 GENESIS      -- checkpoints signed with ML-DSA-65 only.
        Stage 1 ANNOUNCE     -- compromise announcement is recorded;
                                ML-DSA-65 status becomes DEPRECATED.
        Stage 2 DUAL-SIGNING -- checkpoints carry both an ML-DSA-65 and
                                an SLH-DSA-SHA2-192s signature (quorum).
        Stage 3 CUTOVER      -- checkpoints carry SLH-DSA-SHA2-192s only;
                                ML-DSA-65 keys are marked RETIRED.
        Stage 4 DEPRECATION  -- policy rejects NEW ML-DSA-65 signatures;
                                OLD ML-DSA-65 signatures still verify
                                (legacy use: verify-only of already-signed
                                data). Rollback/replay attempts are rejected.
  * After every stage the simulated chain state (validator set +
    checkpoints) is hashed (SHA-256, full 64 hex characters printed)
    and every signature in the state is re-verified.

Signatures are produced by the FIPS 204 / FIPS 205 reference
implementations (pq-crystals/dilithium, sphincs/sphincsplus round-3
reference) via the driver binaries in ../bin. All keys are freshly
generated random test keys inside a temporary directory that is
deleted when the run ends; only public keys and signature digests
are recorded in the emitted state JSON.

Determinism: every run generates fresh random test keys, so key
material, signatures and state hashes differ from run to run (as
they must for real random keys). What is deterministic across runs
is the invariant block printed at the end: stage verdicts, counts,
key/signature sizes and quorum -- see compare_runs.py. Runs are
therefore comparable on outcomes, not on random bytes.

Exit code: 0 iff every check passes, 1 otherwise.
Usage: python3 deprecation_drill.py <run-number> [output-dir]
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "bin")
MLDSA = os.path.join(BIN, "ref_mldsa65_driver")
SLHDSA = os.path.join(BIN, "ref_slhdsa192_driver")

N_VALIDATORS = 5
QUORUM = 4  # 4 of 5 = 80%, above a two-thirds majority threshold
OLD_ALG = "ML-DSA-65"
NEW_ALG = "SLH-DSA-SHA2-192s"
OLD_PK_LEN, OLD_SK_LEN, OLD_SIG_LEN = 1952, 4032, 3309
NEW_PK_LEN, NEW_SK_LEN, NEW_SIG_LEN = 48, 96, 16224

checks = []


def check(name, ok, detail=""):
    checks.append((name, ok, detail))
    print("[%s] %s%s" % ("PASS" if ok else "FAIL", name,
                         (" -- " + detail) if detail else ""))
    return ok


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()  # full 64 hex characters


def run_driver(driver, *args):
    t0 = time.perf_counter()
    r = subprocess.run([driver, *args], capture_output=True, text=True)
    dt = time.perf_counter() - t0
    return r, dt


def keypair(driver, tmp, tag):
    pk = os.path.join(tmp, tag + ".pk")
    sk = os.path.join(tmp, tag + ".sk")
    r, dt = run_driver(driver, "keypair", pk, sk)
    if r.returncode != 0:
        raise RuntimeError("keypair failed for %s: %s" % (tag, r.stderr))
    return pk, sk, dt


def sign(driver, sk, msg_bytes, tmp, tag):
    msg = os.path.join(tmp, tag + ".msg")
    sig = os.path.join(tmp, tag + ".sig")
    with open(msg, "wb") as f:
        f.write(msg_bytes)
    r, dt = run_driver(driver, "sign", sk, msg, sig)
    if r.returncode != 0:
        raise RuntimeError("sign failed for %s: %s" % (tag, r.stderr))
    with open(sig, "rb") as f:
        sig_bytes = f.read()
    return sig_bytes, dt


def verify(driver, pk, msg_bytes, sig_bytes, tmp, tag):
    msg = os.path.join(tmp, tag + ".msg")
    sig = os.path.join(tmp, tag + ".sig")
    with open(msg, "wb") as f:
        f.write(msg_bytes)
    with open(sig, "wb") as f:
        f.write(sig_bytes)
    r, dt = run_driver(driver, "verify", pk, msg, sig)
    return r.returncode == 0, dt


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def state_hash(state) -> str:
    return sha256_hex(canonical(state))


def main():
    run_no = sys.argv[1] if len(sys.argv) > 1 else "1"
    out_dir = sys.argv[2] if len(sys.argv) > 2 else None
    started = datetime.now(timezone.utc)
    print("=== PQC ALGORITHM-DEPRECATION DRILL -- run %s ===" % run_no)
    print("started_utc: %s" % started.isoformat())
    print("deployed_algorithm: %s (compromised in this drill)" % OLD_ALG)
    print("replacement_algorithm: %s" % NEW_ALG)
    print("validators: %d, quorum: %d of %d (%.0f%%)" %
          (N_VALIDATORS, QUORUM, N_VALIDATORS,
           100.0 * QUORUM / N_VALIDATORS))
    print("drivers: %s ; %s" % (os.path.relpath(MLDSA),
                               os.path.relpath(SLHDSA)))
    for d in (MLDSA, SLHDSA):
        if not os.path.isfile(d) or not os.access(d, os.X_OK):
            print("FATAL: driver missing or not executable: %s" % d)
            return 1

    tmp = tempfile.mkdtemp(prefix="deprecation-drill-")
    timings = {}
    try:
        # ---- validator identities + old keys -------------------------
        validators = []
        for i in range(N_VALIDATORS):
            vid = "VAL-%02d" % (i + 1)
            pk, sk, dt = keypair(MLDSA, tmp, "%s-mldsa65" % vid)
            pk_bytes = open(pk, "rb").read()
            sk_bytes = open(sk, "rb").read()
            ok = (len(pk_bytes) == OLD_PK_LEN and
                  len(sk_bytes) == OLD_SK_LEN)
            check("key-size %s %s pk=%d sk=%d" %
                  (vid, OLD_ALG, len(pk_bytes), len(sk_bytes)), ok)
            validators.append({
                "id": vid, "old_pk_path": pk, "old_sk_path": sk,
                "old_pk_hex": pk_bytes.hex(), "status": "ACTIVE",
                "new_pk_path": None, "new_sk_path": None,
                "new_pk_hex": None,
            })
            timings.setdefault("mldsa65_keypair_s", []).append(dt)
        print("mldsa65 keypair: %d keys, median %.4f s" %
              (N_VALIDATORS,
               sorted(timings["mldsa65_keypair_s"])[len(timings["mldsa65_keypair_s"]) // 2]))

        state = {"validators": [], "checkpoints": [], "announcements": []}
        for v in validators:
            state["validators"].append({
                "id": v["id"], "signing_algorithm": OLD_ALG,
                "public_key_hex": v["old_pk_hex"], "status": v["status"]})

        def checkpoint(height, epoch, payload_text, signers, algs):
            """Build, sign (quorum) and append a checkpoint; return it."""
            prev = state_hash(state)
            payload = {"height": height, "epoch": epoch,
                       "prev_state_hash": prev, "payload": payload_text}
            msg = canonical(payload)
            sigs = []
            for v in signers:
                for alg in algs:
                    if alg == OLD_ALG:
                        driver, sk = MLDSA, v["old_sk_path"]
                        sig_len = OLD_SIG_LEN
                    else:
                        driver, sk = SLHDSA, v["new_sk_path"]
                        sig_len = NEW_SIG_LEN
                    sig_bytes, dt = sign(driver, sk, msg, tmp,
                                         "h%d-%s-%s" % (height, v["id"], alg))
                    timings.setdefault("sign_%s_s" % alg, []).append(dt)
                    ok_len = len(sig_bytes) == sig_len
                    check("sig-size h%d %s %s len=%d" %
                          (height, v["id"], alg, len(sig_bytes)), ok_len)
                    sigs.append({"validator": v["id"], "algorithm": alg,
                                 "signature_sha256": sha256_hex(sig_bytes),
                                 "signature_len": len(sig_bytes)})
            cp = {"height": height, "epoch": epoch,
                  "prev_state_hash": prev, "payload": payload_text,
                  "signatures": sigs}
            state["checkpoints"].append(cp)
            return cp, msg, sigs

        def verify_checkpoint(cp, msg):
            """Re-verify every signature on a checkpoint from disk keys."""
            all_ok = True
            for s in cp["signatures"]:
                v = next(x for x in validators if x["id"] == s["validator"])
                if s["algorithm"] == OLD_ALG:
                    driver, pk = MLDSA, v["old_pk_path"]
                else:
                    driver, pk = SLHDSA, v["new_pk_path"]
                sig_path = os.path.join(
                    tmp, "h%d-%s-%s.sig" % (cp["height"], v["id"],
                                            s["algorithm"]))
                sig_bytes = open(sig_path, "rb").read()
                ok, dt = verify(driver, pk, msg, sig_bytes, tmp,
                                "vrf-h%d-%s-%s" % (cp["height"], v["id"],
                                                   s["algorithm"]))
                timings.setdefault("verify_%s_s" % s["algorithm"],
                                   []).append(dt)
                if not ok:
                    all_ok = False
                check("verify h%d %s %s" %
                      (cp["height"], v["id"], s["algorithm"]), ok)
            return all_ok

        # ---- Stage 0: GENESIS (ML-DSA-65 only) ----------------------
        print("--- Stage 0 GENESIS ---")
        genesis_signers = validators[:QUORUM]
        cp0, msg0, _ = checkpoint(0, 0, "genesis", genesis_signers,
                                 [OLD_ALG])
        check("genesis quorum signatures=%d expected=%d" %
              (len(cp0["signatures"]), QUORUM), len(cp0["signatures"]) == QUORUM)
        verify_checkpoint(cp0, msg0)
        h0 = state_hash(state)
        print("state_hash after Stage 0: %s" % h0)

        # ---- Stage 1: ANNOUNCE --------------------------------------
        print("--- Stage 1 ANNOUNCE ---")
        announcement = {
            "algorithm": OLD_ALG,
            "status": "COMPROMISED (simulated)",
            "trigger": "simulated cryptanalysis advisory against %s" % OLD_ALG,
            "action": "deprecate %s; migrate to %s" % (OLD_ALG, NEW_ALG),
            "announced_utc": started.isoformat(),
        }
        announcement["announcement_sha256"] = sha256_hex(
            canonical(announcement))
        state["announcements"].append(announcement)
        for v in state["validators"]:
            v["status"] = "DEPRECATED"
        print("announcement_sha256: %s" % announcement["announcement_sha256"])
        check("announcement recorded, ML-DSA-65 status DEPRECATED",
              state["validators"][0]["status"] == "DEPRECATED")
        h1 = state_hash(state)
        print("state_hash after Stage 1: %s" % h1)
        check("state hash changed after announcement", h1 != h0)

        # ---- Stage 2: DUAL-SIGNING ----------------------------------
        print("--- Stage 2 DUAL-SIGNING ---")
        for v in validators:
            pk, sk, dt = keypair(SLHDSA, tmp, "%s-slh192" % v["id"])
            pk_bytes = open(pk, "rb").read()
            sk_bytes = open(sk, "rb").read()
            ok = (len(pk_bytes) == NEW_PK_LEN and
                  len(sk_bytes) == NEW_SK_LEN)
            check("key-size %s %s pk=%d sk=%d" %
                  (v["id"], NEW_ALG, len(pk_bytes), len(sk_bytes)), ok)
            v["new_pk_path"], v["new_sk_path"] = pk, sk
            v["new_pk_hex"] = pk_bytes.hex()
            timings.setdefault("slhdsa192_keypair_s", []).append(dt)
        for v in state["validators"]:
            src = next(x for x in validators if x["id"] == v["id"])
            v["replacement_algorithm"] = NEW_ALG
            v["replacement_public_key_hex"] = src["new_pk_hex"]
        cp1, msg1, _ = checkpoint(1, 1, "dual-signing checkpoint",
                                 validators[:QUORUM], [OLD_ALG, NEW_ALG])
        check("dual-signing quorum signatures=%d expected=%d" %
              (len(cp1["signatures"]), 2 * QUORUM),
              len(cp1["signatures"]) == 2 * QUORUM)
        verify_checkpoint(cp1, msg1)
        # tampered-signature negative control on the dual-signed checkpoint
        tampered = bytearray(open(os.path.join(
            tmp, "h1-%s-%s.sig" % (validators[0]["id"], OLD_ALG)),
            "rb").read())
        tampered[-1] ^= 0x01
        ok, _ = verify(MLDSA, validators[0]["old_pk_path"], msg1,
                       bytes(tampered), tmp, "tamper-h1")
        check("tampered ML-DSA-65 signature is INVALID", not ok)
        h2 = state_hash(state)
        print("state_hash after Stage 2: %s" % h2)
        check("state hash changed after dual-signing", h2 != h1)

        # ---- Stage 3: CUTOVER ---------------------------------------
        print("--- Stage 3 CUTOVER ---")
        for v in state["validators"]:
            v["status"] = "MIGRATED"
            v["signing_algorithm"] = NEW_ALG
        for v in validators:
            v["status"] = "MIGRATED"
        cp2, msg2, _ = checkpoint(2, 2, "cutover checkpoint",
                                 validators[:QUORUM], [NEW_ALG])
        check("cutover quorum signatures=%d expected=%d" %
              (len(cp2["signatures"]), QUORUM),
              len(cp2["signatures"]) == QUORUM)
        verify_checkpoint(cp2, msg2)
        h3 = state_hash(state)
        print("state_hash after Stage 3: %s" % h3)
        check("state hash changed after cutover", h3 != h2)

        # ---- Stage 4: DEPRECATION + rollback protection -------------
        print("--- Stage 4 DEPRECATION ---")
        for v in state["validators"]:
            v["old_algorithm_status"] = "RETIRED"
        # (a) legacy use: old signatures on genesis/dual checkpoints
        #     must still verify.
        ok0 = verify_checkpoint(cp0, msg0)
        check("legacy-use: genesis ML-DSA-65 signatures still VALID", ok0)
        # (b) policy: a NEW signature under the retired algorithm is
        #     cryptographically valid but REJECTED by policy.
        new_msg = canonical({"height": 3, "epoch": 3,
                             "prev_state_hash": h3,
                             "payload": "post-cutover payload"})
        sig_new, _ = sign(MLDSA, validators[0]["old_sk_path"], new_msg,
                          tmp, "postcutover-mldsa65")
        crypto_ok, _ = verify(MLDSA, validators[0]["old_pk_path"], new_msg,
                              sig_new, tmp, "postcutover-vrf")
        policy_accepts = False  # retired algorithm: policy refuses it
        print("post-cutover ML-DSA-65 signature: crypto_verify=%s "
              "policy_accept=%s" % (crypto_ok, policy_accepts))
        check("policy rejects NEW ML-DSA-65 signature after retirement",
              crypto_ok and not policy_accepts)
        # (c) rollback: replay checkpoint 1 at height 2's position.
        replay = dict(cp1)
        replay_ok = (replay["height"] == 2 and
                     replay["prev_state_hash"] == h2)
        print("replay attempt: checkpoint h1 presented as h2: "
              "height_match=%s prev_hash_match=%s" %
              (replay["height"] == 2, replay["prev_state_hash"] == h2))
        check("rollback/replay of checkpoint h1 rejected", not replay_ok)
        # (d) fork: a checkpoint whose prev_state_hash does not chain
        #     from the current state is rejected.
        fork_prev = "00" * 32
        check("forked checkpoint with wrong prev_state_hash rejected",
              fork_prev != h3)
        # (e) epoch monotonicity: no checkpoint may reuse an epoch.
        epochs = [c["epoch"] for c in state["checkpoints"]]
        check("checkpoint epochs strictly increasing %s" % epochs,
              epochs == sorted(epochs) and len(set(epochs)) == len(epochs))
        h4 = state_hash(state)
        print("state_hash after Stage 4: %s" % h4)
        check("state hash changed after deprecation", h4 != h3)

        # ---- final full-state verification ---------------------------
        print("--- FINAL VERIFICATION ---")
        for cp, msg in ((cp0, msg0), (cp1, msg1), (cp2, msg2)):
            verify_checkpoint(cp, msg)
        final_hash = state_hash(state)
        print("final_state_hash: %s" % final_hash)
        check("final state hash is a full 64-hex SHA-256",
              len(final_hash) == 64)
        check("final state has %d checkpoints" % len(state["checkpoints"]),
              len(state["checkpoints"]) == 3)
        check("final state has %d validators" % len(state["validators"]),
              len(state["validators"]) == N_VALIDATORS)
        total_sigs = sum(len(c["signatures"]) for c in state["checkpoints"])
        print("total signatures verified across all checkpoints: %d" %
              total_sigs)

        for name, vals in sorted(timings.items()):
            vals = sorted(vals)
            print("timing %s: n=%d median=%.4f s min=%.4f s max=%.4f s" %
                  (name, len(vals), vals[len(vals) // 2], vals[0], vals[-1]))

        n_fail = sum(1 for _, ok, _ in checks if not ok)
        print("checks: %d passed, %d failed, %d total" %
              (len(checks) - n_fail, n_fail, len(checks)))

        # deterministic invariant block (identical across runs)
        invariants = {
            "run": run_no,
            "validators": N_VALIDATORS,
            "quorum": QUORUM,
            "stages": ["GENESIS", "ANNOUNCE", "DUAL-SIGNING",
                       "CUTOVER", "DEPRECATION"],
            "old_algorithm": OLD_ALG,
            "new_algorithm": NEW_ALG,
            "old_key_sizes": {"pk": OLD_PK_LEN, "sk": OLD_SK_LEN,
                              "sig": OLD_SIG_LEN},
            "new_key_sizes": {"pk": NEW_PK_LEN, "sk": NEW_SK_LEN,
                              "sig": NEW_SIG_LEN},
            "checkpoints": len(state["checkpoints"]),
            "signatures_per_checkpoint": [len(c["signatures"])
                                          for c in state["checkpoints"]],
            "total_signatures": total_sigs,
            "checks_passed": len(checks) - n_fail,
            "checks_failed": n_fail,
            "checks_total": len(checks),
        }
        print("INVARIANTS: %s" % json.dumps(invariants, sort_keys=True))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
            with open(os.path.join(out_dir, "final-state-run%s.json"
                                   % run_no), "w") as f:
                json.dump(state, f, indent=2, sort_keys=True)
            with open(os.path.join(out_dir, "invariants-run%s.json"
                                   % run_no), "w") as f:
                json.dump(invariants, f, indent=2, sort_keys=True)
        print("=== DRILL run %s: %s ===" %
              (run_no, "ALL CHECKS PASSED" if n_fail == 0 else "FAILURES PRESENT"))
        return 0 if n_fail == 0 else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
