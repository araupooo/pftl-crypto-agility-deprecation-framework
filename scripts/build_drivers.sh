#!/bin/bash
# Rebuild the reference-driver binaries used by deprecation_drill.py
# and measure_costs.py, from the pinned commits. Run from the pack
# root. Requires: git, gcc, python3 (liboqs-python only needed for
# measure_costs.py, not for the drill itself).
set -e
PACK="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$PACK/drivers-src"

# --- ML-DSA reference: pq-crystals/dilithium, FIPS 204 ---
if [ ! -d "$SRC/ref-mldsa" ]; then
  git clone https://github.com/pq-crystals/dilithium.git "$SRC/ref-mldsa"
fi
git -C "$SRC/ref-mldsa" checkout d35ba3fe5449bee3e6d43e1f296c3ca818bd36be
gcc -O2 -std=c99 -Wall -DDILITHIUM_MODE=3 -I"$SRC/ref-mldsa/ref" \
  -o "$PACK/bin/ref_mldsa65_driver" \
  "$PACK/drivers/ref_mldsa65_driver.c" \
  "$SRC/ref-mldsa/ref/randombytes.c" "$SRC/ref-mldsa/ref/sign.c" \
  "$SRC/ref-mldsa/ref/packing.c" "$SRC/ref-mldsa/ref/polyvec.c" \
  "$SRC/ref-mldsa/ref/poly.c" "$SRC/ref-mldsa/ref/ntt.c" \
  "$SRC/ref-mldsa/ref/reduce.c" "$SRC/ref-mldsa/ref/rounding.c" \
  "$SRC/ref-mldsa/ref/fips202.c" "$SRC/ref-mldsa/ref/symmetric-shake.c"

# --- SLH-DSA reference: sphincs/sphincsplus, round-3 (pre-FIPS-205) ---
# NOTE: the round-3 reference predates FIPS 205; its signatures do
# not verify under liboqs (see cost-table.md section 4). The drill
# verifies each signature with the implementation that produced it.
if [ ! -d "$SRC/ref-slhdsa" ]; then
  git clone https://github.com/sphincs/sphincsplus.git "$SRC/ref-slhdsa"
fi
git -C "$SRC/ref-slhdsa" checkout 7ec789ace6874d875f4bb84cb61b81155398167e
gcc -O2 -std=c99 -Wall -I"$SRC/ref-slhdsa/ref" -DPARAMS=sphincs-sha2-192s \
  -o "$PACK/bin/ref_slhdsa192_driver" \
  "$PACK/drivers/ref_slhdsa192_driver.c" \
  "$SRC/ref-slhdsa/ref/address.c" "$SRC/ref-slhdsa/ref/randombytes.c" \
  "$SRC/ref-slhdsa/ref/merkle.c" "$SRC/ref-slhdsa/ref/wots.c" \
  "$SRC/ref-slhdsa/ref/wotsx1.c" "$SRC/ref-slhdsa/ref/utils.c" \
  "$SRC/ref-slhdsa/ref/utilsx1.c" "$SRC/ref-slhdsa/ref/fors.c" \
  "$SRC/ref-slhdsa/ref/sign.c" "$SRC/ref-slhdsa/ref/sha2.c" \
  "$SRC/ref-slhdsa/ref/hash_sha2.c" "$SRC/ref-slhdsa/ref/thash_sha2_robust.c"

echo "built: ref_mldsa65_driver ref_slhdsa192_driver"
