# Primary-source citations

Access date for every source below: 2026-11-16. "Verified" means
the cited text was read directly from the source on that date
(PDF text extraction or live page fetch), unless the entry says
otherwise.

## [S1] FIPS 203 — ML-KEM

- NIST FIPS 203, *Module-Lattice-Based Key-Encapsulation
  Mechanism Standard*, published/effective 13 August 2024.
- URL: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
  (also https://csrc.nist.gov/pubs/fips/203/final)
- DOI: https://doi.org/10.6028/NIST.FIPS.203
- Used for: ML-KEM parameter sets; Table 3 sizes (ML-KEM-512
  ek 800 / dk 1,632 / ct 768; ML-KEM-768 1,184 / 2,400 / 1,088;
  ML-KEM-1024 1,568 / 3,168 / 1,568; shared secret 32 B).
- Verification: direct PDF text extraction, 2026-11-16.

## [S2] FIPS 204 — ML-DSA

- NIST FIPS 204, *Module-Lattice-Based Digital Signature
  Standard*, published/effective 13 August 2024.
- URL: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
  (also https://csrc.nist.gov/pubs/fips/204/final)
- DOI: https://doi.org/10.6028/NIST.FIPS.204
- Used for: ML-DSA parameter sets and categories; Table 2 sizes
  (ML-DSA-44 pk 1,312 / sk 2,560 / sig 2,420; ML-DSA-65 1,952 /
  4,032 / 3,309; ML-DSA-87 2,592 / 4,896 / 4,627).
- Verification: direct PDF text extraction, 2026-11-16.

## [S3] FIPS 205 — SLH-DSA

- NIST FIPS 205, *Stateless Hash-Based Digital Signature
  Standard*, published/effective 13 August 2024.
- URL: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
  (also https://csrc.nist.gov/pubs/fips/205/final)
- DOI: https://doi.org/10.6028/NIST.FIPS.205
- Used for: SLH-DSA parameter sets (§11, Table 2): 128s pk 32 /
  sig 7,856; 192s pk 48 / sig 16,224; 256s pk 64 / sig 29,792
  (sk 64 / 96 / 128, measured); 12 parameter sets (3 categories
  × 2 hash families × s/f tunings).
- Verification: direct PDF text extraction, 2026-11-16 (sizes
  cross-checked against the same table as recorded in the
  amendment-activation pack, 2026-11-16).

## [S4] NIST IR 8547 — transition schedule and crypto-agility

- NIST IR 8547, *Transition to Post-Quantum Cryptography
  Standards*, final, October 2026. Authors: D. Moody,
  R. Perlner, A. Regenscheid, A. Robinson, D. Cooper.
  DOI: https://doi.org/10.6028/NIST.IR.8547
- URL: https://nvlpubs.nist.gov/nistpubs/ir/2026/NIST.IR.8547.pdf
  (also https://csrc.nist.gov/pubs/ir/8547/final)
- Used for: deprecation after 2030 / disallowance after 2035 for
  all quantum-vulnerable public-key algorithms (Tables 2 and 4);
  ML-KEM-768 as recommended default parameter set (Table 5
  discussion); post-quantum algorithm inventory (Tables 3 and 5);
  hybrid techniques (§3.2, dual signatures §3.2.2); HQC selected
  as ML-KEM alternative with a FIPS under development (§4.1.2);
  status definitions (acceptable / deprecated / disallowed /
  legacy use, §4.1); EO 14412 and OMB M-26-15 deadlines — key
  establishment by 31 December 2030, signatures by 31 December
  2031, TLS 1.3 by 2 January 2030 (§4); crypto-agility statement
  (§1.1: "building long-term cryptographic agility into
  organizational infrastructure to allow for seamless updates as
  post-quantum standards evolve").
- Verification: direct PDF text extraction from the final PDF,
  2026-11-16 (34 pages; PDF metadata: CreationDate 2026-10-26).
  The PDF itself is dated "October 2026". The exact publication
  day, 27 October 2026, is from the NIST news release of that
  date and concordant secondary reporting; the pack cites the
  month, not the day, for the primary claim.

## [S5] PostFiat whitepaper — deployed signature scheme

- Post Fiat, *A Buy-Side Internet of Value* (whitepaper),
  https://postfiat.org/whitepaper/ , §1.11.
- Used for: "Accounts and validators sign with ML-DSA-65 from
  genesis: 1,952-byte public keys, 3,309-byte signatures."
- Verification: verified 2026-11-16 in the amendment-activation
  research pass; the sizes were re-confirmed against FIPS 204
  Table 2 [S2] on 2026-11-16. The whitepaper text itself was not
  re-fetched in this pack build; the claim rests on the prior
  verification plus the FIPS cross-check.

## [S6] CNSA 2.0 — NSA algorithm suite

- NSA, *Announcing the Commercial National Security Algorithm
  Suite 2.0*, CSA U/OO/194427-22 | PP-22-1338, September 2022.
- Used for: ML-KEM-1024 (key establishment) and ML-DSA-87
  (signatures) required for national security systems; AES-256;
  SHA-384/512; LMS/XMSS for firmware/software signing.
- Verification: the NSA PDF itself returned HTTP 403 from this
  machine on 2026-11-16, so it was NOT read directly. The
  requirement table was verified by concordance across three
  independent secondary sources, all citing the same NSA
  document: fieldguide.lamarrlabs.com/NSA-CNSA-2.0,
  postquantum.com/cnsa-2-0/complete-guide/,
  encryptionconsulting.com (CNSA 2.0 guides). The pack states
  this verification method plainly and does not present the
  CNSA 2.0 claim as direct-PDF-verified.

## [S7] XRPL amendment system (upstream heritage)

- xrpl.org, "Amendments",
  https://xrpl.org/docs/concepts/networks-and-servers/amendments
  (sections "Amendment Process" and "Amendment Voting").
- Used for: >80% support for two weeks passes an amendment;
  flag ledgers every 256th ledger; `EnableAmendment`
  pseudo-transaction; an enabled amendment can only be disabled
  by a new amendment; servers that removed an enabled
  amendment's code become amendment-blocked (veto mechanism).
- Verification: verified against xrpl.org 2026-11-15 in the
  amendment-activation research pass; not re-fetched in this
  pack build.

## [S8] postfiatd (fork) — amendment threshold

- Repository: `postfiatorg/postfiatd`, commit 0085a1ff.
- `include/xrpl/protocol/SystemParameters.h`:
  `preFixAmendmentMajorityCalcThreshold` = 204/256;
  `postFixAmendmentMajorityCalcThreshold` = 67/100;
  `defaultAmendmentMajorityTime` = 2 weeks.
- URL (raw):
  https://raw.githubusercontent.com/postfiatorg/postfiatd/0085a1ff885d6a446369cf73a4430f75af22be55/include/xrpl/protocol/SystemParameters.h
- Used for: 67% post-fix threshold; two-week majority time;
  at 53 validators, passage requires at least 36 supporters.
- Verification: threshold constants re-verified live from the
  raw file on 2026-11-16. The 53-validator count and the
  ≥36 arithmetic are from the amendment-activation research
  pass (2026-11-16).

## Software sources (implementations used)

- pq-crystals/dilithium, reference implementation (FIPS 204),
  commit d35ba3fe5449bee3e6d43e1f296c3ca818bd36be.
  https://github.com/pq-crystals/dilithium
- sphincs/sphincsplus, round-3 reference implementation,
  commit 7ec789ace6874d875f4bb84cb61b81155398167e.
  https://github.com/sphincs/sphincsplus
  NOTE: round-3 reference predates FIPS 205; see framework.md
  §8 and cost-table.md §4 for the measured cross-implementation
  divergence.
- liboqs 0.16.0 via liboqs-python 0.16.0.2.
  https://github.com/open-quantum-safe/liboqs-python
- All three were already present on this machine from prior
  packs; pinned commits are recorded in
  `scripts/build_drivers.sh`, which rebuilds the drivers.
