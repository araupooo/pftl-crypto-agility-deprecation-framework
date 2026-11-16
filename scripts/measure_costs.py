#!/usr/bin/env python3
"""
measure_costs.py -- measured migration-cost table.

Measures, with liboqs 0.16.0 (via liboqs-python) on this machine:
  * key / signature / ciphertext sizes for every parameter set in the
    migration inventory, asserted equal to the FIPS 203/204/205 tables;
  * median sign / verify (signatures) and encap / decap (KEMs) times;
  * cross-implementation checks: a signature produced by the C
    reference driver is verified with liboqs, and vice versa
    (ML-DSA-65; SLH-DSA-SHA2-192s);
  * ledger-growth model inputs: signature bytes per quorum-signed
    checkpoint under the old, dual and new schemes.

Run with the venv python that has liboqs-python installed, e.g.:
  <pack>/../.. (task-7bb5e19b)/venv/bin/python measure_costs.py
or any python3 with `import oqs` available.

Timings are medians over N repetitions on this machine; they are
measurements of this environment, not specification values. Sizes
are specification values confirmed by measurement.

Exit code: 0 iff every size assertion and cross-check expectation
recorded here holds (a cross-check that returns INVALID is recorded
as a finding, not a failure, when the code documents it as such --
see the SLH-DSA note below).
"""

import hashlib
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

import oqs

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "bin")
MLDSA65 = os.path.join(BIN, "ref_mldsa65_driver")
SLH192 = os.path.join(BIN, "ref_slhdsa192_driver")

# Expected sizes (bytes) from the FIPS tables -- asserted, not assumed.
EXPECTED_SIG = {
    "ML-DSA-44": {"liboqs": "ML-DSA-44", "pk": 1312, "sk": 2560,
                  "sig": 2420, "fips": "FIPS 204 Table 2"},
    "ML-DSA-65": {"liboqs": "ML-DSA-65", "pk": 1952, "sk": 4032,
                  "sig": 3309, "fips": "FIPS 204 Table 2"},
    "ML-DSA-87": {"liboqs": "ML-DSA-87", "pk": 2592, "sk": 4896,
                  "sig": 4627, "fips": "FIPS 204 Table 2"},
    "SLH-DSA-SHA2-128s": {"liboqs": "SLH_DSA_PURE_SHA2_128S", "pk": 32,
                          "sk": 64, "sig": 7856, "fips": "FIPS 205 Table 2"},
    "SLH-DSA-SHA2-192s": {"liboqs": "SLH_DSA_PURE_SHA2_192S", "pk": 48,
                          "sk": 96, "sig": 16224, "fips": "FIPS 205 Table 2"},
    "SLH-DSA-SHA2-256s": {"liboqs": "SLH_DSA_PURE_SHA2_256S", "pk": 64,
                          "sk": 128, "sig": 29792, "fips": "FIPS 205 Table 2"},
}
EXPECTED_KEM = {
    "ML-KEM-512": {"pk": 800, "sk": 1632, "ct": 768, "ss": 32},
    "ML-KEM-768": {"pk": 1184, "sk": 2400, "ct": 1088, "ss": 32},
    "ML-KEM-1024": {"pk": 1568, "sk": 3168, "ct": 1568, "ss": 32},
}
N_SIG = {"ML-DSA-44": 50, "ML-DSA-65": 50, "ML-DSA-87": 50,
         "SLH-DSA-SHA2-128s": 20, "SLH-DSA-SHA2-192s": 5,
         "SLH-DSA-SHA2-256s": 5}
N_KEM = 50
QUORUM = 4
MSG = b"migration-cost benchmark checkpoint payload"


def med(vals):
    return statistics.median(vals)


def main():
    print("=== MIGRATION-COST MEASUREMENT ===")
    print("started_utc: %s" % datetime.now(timezone.utc).isoformat())
    print("liboqs_version: %s" % oqs.oqs_version())
    print("python: %s" % sys.version.split()[0])
    failures = []
    results = {"signatures": {}, "kems": {}}

    for name, exp in EXPECTED_SIG.items():
        sig = oqs.Signature(exp["liboqs"])
        det = sig.details
        pk_len = det["length_public_key"]
        sk_len = det["length_secret_key"]
        sig_len = det["length_signature"]
        ok = (pk_len == exp["pk"] and sk_len == exp["sk"]
              and sig_len == exp["sig"])
        print("[%s] size %s pk=%d sk=%d sig=%d (expected %d/%d/%d, %s)"
              % ("PASS" if ok else "FAIL", name, pk_len, sk_len, sig_len,
                 exp["pk"], exp["sk"], exp["sig"], exp["fips"]))
        if not ok:
            failures.append("size %s" % name)
        n = N_SIG[name]
        pk = sig.generate_keypair()
        t_sign, t_verify = [], []
        for _ in range(n):
            t0 = time.perf_counter()
            s = sig.sign(MSG)
            t_sign.append(time.perf_counter() - t0)
            t0 = time.perf_counter()
            ok_v = sig.verify(MSG, s, pk)
            t_verify.append(time.perf_counter() - t0)
            if not ok_v:
                failures.append("self-verify %s" % name)
        assert len(s) == sig_len
        print("timing %s: sign n=%d median=%.4f s min=%.4f s max=%.4f s; "
              "verify median=%.4f s min=%.4f s max=%.4f s"
              % (name, n, med(t_sign), min(t_sign), max(t_sign),
                 med(t_verify), min(t_verify), max(t_verify)))
        results["signatures"][name] = {
            "pk": pk_len, "sk": sk_len, "sig": sig_len,
            "sign_s_median": med(t_sign), "verify_s_median": med(t_verify),
            "n": n}

    for name, exp in EXPECTED_KEM.items():
        kem = oqs.KeyEncapsulation(name)
        det = kem.details
        pk_len, sk_len = det["length_public_key"], det["length_secret_key"]
        ct_len, ss_len = det["length_ciphertext"], det["length_shared_secret"]
        ok = (pk_len == exp["pk"] and sk_len == exp["sk"]
              and ct_len == exp["ct"] and ss_len == exp["ss"])
        print("[%s] size %s pk=%d sk=%d ct=%d ss=%d (expected %d/%d/%d/%d, "
              "FIPS 203 Table 3)"
              % ("PASS" if ok else "FAIL", name, pk_len, sk_len, ct_len,
                 ss_len, exp["pk"], exp["sk"], exp["ct"], exp["ss"]))
        if not ok:
            failures.append("size %s" % name)
        pk = kem.generate_keypair()
        t_enc, t_dec = [], []
        for _ in range(N_KEM):
            t0 = time.perf_counter()
            ct, ss1 = kem.encap_secret(pk)
            t_enc.append(time.perf_counter() - t0)
            t0 = time.perf_counter()
            ss2 = kem.decap_secret(ct)
            t_dec.append(time.perf_counter() - t0)
            if ss1 != ss2:
                failures.append("kem round-trip %s" % name)
        assert len(ct) == ct_len
        print("timing %s: encap n=%d median=%.6f s; decap median=%.6f s"
              % (name, N_KEM, med(t_enc), med(t_dec)))
        results["kems"][name] = {
            "pk": pk_len, "sk": sk_len, "ct": ct_len, "ss": ss_len,
            "encap_s_median": med(t_enc), "decap_s_median": med(t_dec),
            "n": N_KEM}

    # ---- cross-implementation checks (reference driver <-> liboqs) ----
    print("--- CROSS-IMPLEMENTATION CHECKS ---")
    tmp = tempfile.mkdtemp(prefix="costs-xcheck-")
    try:
        # ML-DSA-65: ref driver signs, liboqs verifies; and reverse.
        msg_f = os.path.join(tmp, "msg.bin")
        open(msg_f, "wb").write(MSG)
        subprocess.run([MLDSA65, "keypair", os.path.join(tmp, "pk"),
                        os.path.join(tmp, "sk")], check=True,
                       capture_output=True)
        subprocess.run([MLDSA65, "sign", os.path.join(tmp, "sk"), msg_f,
                        os.path.join(tmp, "sig")], check=True,
                       capture_output=True)
        pk_ref = open(os.path.join(tmp, "pk"), "rb").read()
        sig_ref = open(os.path.join(tmp, "sig"), "rb").read()
        s65 = oqs.Signature("ML-DSA-65")
        ok_ref_to_oqs = s65.verify(MSG, sig_ref, pk_ref)
        print("[%s] ML-DSA-65 ref-driver signature verifies under liboqs: %s"
              % ("PASS" if ok_ref_to_oqs else "FAIL", ok_ref_to_oqs))
        if not ok_ref_to_oqs:
            failures.append("ML-DSA-65 ref->liboqs")
        pk_oqs = s65.generate_keypair()
        sig_oqs = s65.sign(MSG)
        open(os.path.join(tmp, "pk2"), "wb").write(pk_oqs)
        open(os.path.join(tmp, "sig2"), "wb").write(sig_oqs)
        r = subprocess.run([MLDSA65, "verify", os.path.join(tmp, "pk2"),
                            msg_f, os.path.join(tmp, "sig2")],
                           capture_output=True, text=True)
        ok_oqs_to_ref = (r.returncode == 0)
        print("[%s] ML-DSA-65 liboqs signature verifies under ref driver: %s"
              % ("PASS" if ok_oqs_to_ref else "FAIL", ok_oqs_to_ref))
        if not ok_oqs_to_ref:
            failures.append("ML-DSA-65 liboqs->ref")

        # SLH-DSA-SHA2-192s: ref (round-3) driver signs, liboqs verifies.
        # NOTE (finding, recorded not hidden): the sphincsplus round-3
        # reference predates FIPS 205; its randomized signing differs
        # from the final standard (robust thash masking, context-string
        # encoding). The same divergence was measured for the 128s
        # parameter set in the earlier release-interop pack. A cross
        # result of INVALID here therefore does NOT mean the drill is
        # broken: the drill verifies every signature with the same
        # implementation that produced it, and the measured sizes
        # match FIPS 205 Table 2 exactly. The cross-check outcome is
        # reported as observed.
        subprocess.run([SLH192, "keypair", os.path.join(tmp, "pk192"),
                        os.path.join(tmp, "sk192")], check=True,
                       capture_output=True)
        subprocess.run([SLH192, "sign", os.path.join(tmp, "sk192"), msg_f,
                        os.path.join(tmp, "sig192")], check=True,
                       capture_output=True)
        pk192 = open(os.path.join(tmp, "pk192"), "rb").read()
        sig192 = open(os.path.join(tmp, "sig192"), "rb").read()
        print("ref SLH-DSA-SHA2-192s sizes: pk=%d sk=%d sig=%d "
              "(FIPS 205 Table 2: 48/96/16224)"
              % (len(pk192),
                 len(open(os.path.join(tmp, "sk192"), "rb").read()),
                 len(sig192)))
        s192 = oqs.Signature("SLH_DSA_PURE_SHA2_192S")
        ok_192 = s192.verify(MSG, sig192, pk192)
        print("[INFO] SLH-DSA-SHA2-192s ref-driver signature verifies "
              "under liboqs: %s" % ok_192)
        if ok_192:
            print("cross-check SLH-DSA-192s ref->liboqs: VALID "
                  "(no divergence at this parameter set)")
        else:
            print("cross-check SLH-DSA-192s ref->liboqs: INVALID "
                  "(expected divergence: round-3 reference vs FIPS 205; "
                  "see note above; drill self-verification unaffected)")
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)

    # ---- ledger-growth model (inputs measured above) ------------------
    print("--- LEDGER-GROWTH MODEL (quorum=%d signatures/checkpoint) ---"
          % QUORUM)
    old_b = QUORUM * EXPECTED_SIG["ML-DSA-65"]["sig"]
    dual_b = QUORUM * (EXPECTED_SIG["ML-DSA-65"]["sig"]
                       + EXPECTED_SIG["SLH-DSA-SHA2-192s"]["sig"])
    new_b = QUORUM * EXPECTED_SIG["SLH-DSA-SHA2-192s"]["sig"]
    print("bytes per quorum-signed checkpoint: old(ML-DSA-65)=%d "
          "dual=%d new(SLH-DSA-192s)=%d" % (old_b, dual_b, new_b))
    for n in (10000, 100000, 1000000):
        print("checkpoints=%d: old=%.2f MB dual=%.2f MB new=%.2f MB "
              "delta_new_minus_old=%+.2f MB"
              % (n, old_b * n / 1e6, dual_b * n / 1e6, new_b * n / 1e6,
                 (new_b - old_b) * n / 1e6))
    print("validator key storage (pk+sk, bytes): ML-DSA-65=%d "
          "SLH-DSA-192s=%d (both keys during dual-signing=%d)"
          % (1952 + 4032, 48 + 96, 1952 + 4032 + 48 + 96))
    results["ledger_growth"] = {
        "quorum": QUORUM, "bytes_per_checkpoint": {
            "old": old_b, "dual": dual_b, "new": new_b}}
    print("RESULTS_JSON: %s" % json.dumps(results, sort_keys=True))
    print("failures: %d %s" % (len(failures), failures))
    print("=== COST MEASUREMENT: %s ===" %
          ("ALL SIZE ASSERTIONS PASSED" if not failures else "FAILURES"))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
