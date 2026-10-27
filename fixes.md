# Fixes roadmap — RangeSet-MPCitH V3 (academic prototype)

Baseline: `aaa5c18` pre-fix. All fixes are breaking transcript changes
(C1/H1/M1) so they share one protocol bump `v2 -> v4`
(`V3_PROOF_FORMAT_VERSION 2 -> 4` to stay distinct from `V2_PROOF_VERSION 3`,
`V3_TR_DOMAIN_INIT .../v2 -> .../v3`).
Old proofs are rejected at parse, never re-evaluated. No security claim
is made by fixing code alone — independent review + FS/extractor/QROM
work in `docs/` remains open.

Order: highest severity first, minimal diffs, no over-engineering.
Each step must keep `cargo test --offline` green.

## 0. Protocol bump (done once, with C1)
- `src/v3/suite.rs`: `VERSION 2 -> 3`.
- `src/v3/transcript.rs`: `V3_TR_DOMAIN_INIT .../v2 -> .../v3`,
  add `V3_HASH_TAG_DELTA`.
- `src/v3/proof.rs` tests: expect 3, reject 1 and 2.
- Reason: C1/H1/M1 all change challenges; single bump avoids
  cross-version replay.

## C1 Critical — unauthenticated `delta_u1` (linear bypass)
Files: `src/v3/prover.rs:167,250-253,348`, `src/v3/verifier.rs:247-262,332-340`.
Problem: `delta` sent in clear, never absorbed before `gamma'`.
Attacker sees `gamma'` then picks `delta*` to satisfy
`sum(alpha'_secret)==sum(gp·rhs)`. Wrong-root proofs pass while
all `c=a·b` hold.
Fix (minimal):
- Prover: after `h1'`, hash deltas
  `hDelta=hash_fr_vecs(V3_HASH_TAG_DELTA,&[deltas])`, `absorb(hDelta)`
  before any `V3_TR_TAG_BATCH` sampling.
- Verifier: same, from `rep.delta_u1` (length already checked)
  before sampling `gammas/gamma_ps`.
- New order: `h1 -> Gamma -> h1' -> hDelta -> (gamma,gamma') -> hB -> I`.
- Tests: existing tamper tests still pass; add regression:
  flipping `delta_u1` must fail (already covered indirectly by
  `hDelta` binding — add explicit test in `tests/v3_prototype.rs`
  if cheap, else rely on `tampered_broadcast_shares` + new hash check).

## H1 High — missing `Pu` mask (paper deviation, ZK leak)
Files: `src/v3/prover.rs:201-222`, `src/v3/verifier.rs:353-376`.
Problem: `Pxi=Gamma·Q` with masks as `Gamma`-weighted columns.
Paper `Eq.15`: `Pxi=Gamma·Q+Pu`, `Pu` coeff 1. Current leaks
`Gamma·witness-secret` (`eta·(dbeta+1)` points determine poly).
Fix (paper-faithful, minimal):
- Keep leaf layout `[witness, masks(Pu), hints]` so commitments unchanged.
- Split: `Q = witness+hints`, `Pu = eta masks`.
- `Gamma` size `eta*(n_w+rho*n_hints)` (was `eta*(n_w+eta+rho*n_hints)`).
- `Pxi_k(e)=Pu_k(e)+sum_q Gamma·Qtilde_q(e)` both for canonical
  `d_beta+1` interpolation and `Sx` responses. Same both sides.
- Masks already `deg==dbeta` via `share(s,ell)`, no shift.
- Result: Theorem 1 applies directly, no variant lemma.

## M1 Medium — suite binding gap
Files: `src/v3/suite.rs:28-45`, `src/v3/transcript.rs:70-87`.
Problem: doc says all 5 suite ids bound, code absorbs only
`protocol_id+field_id`. Cross-instance replay if Poseidon/framing change.
Fix: in `TranscriptV3::new` also absorb `version`,
`poseidon2_id`, `framing_id`. No new params (constants).

## M2 Low — `validate()` missing `dalpha/d2` feasibility
File: `src/v3/params.rs:99-156`.
Problem: only `dbeta+2<=N` checked. `N=32,s=20,l=3` passes then
`complement_set` fails late in `prove_rep`/`verify_rep`.
Fix: also require `broadcast_degree()+1<=N` and
`(2*s+l-1)<=N` (`==d2+1`). Fail-fast with `InvalidParams`.
Both sides already fail-closed, so availability/incompleteness only.

## L1 Low — `sample_subset` modulo bias + 32b truncation
File: `src/v3/transcript.rs:143`.
Problem: `rng.next_u64() as usize % (n-i)` biased, truncates on 32b.
Fix: `u64` rejection sampling:
`limit=u64::MAX-u64::MAX%range; loop{v=rng.next_u64(); if v<limit{...}}`.
Uniform `I` assumption restored. Negligible quantitative change.

## L2 Low — Merkle odd-duplication not enforced
Files: `src/v3/commit.rs:87-104,108-144`, `src/v3/verifier.rs:204-208`.
Problem: lonely last node duplicates `sib==cur` on commit, verifier
accepts arbitrary `sib` for unopened leaves; missing
`!sibling_is_left && idx%2==1 -> false` check.
Fix: track `width` per level in `verify_path`; if `idx` even and
lonely (`idx+1>=width`) require `sibling==cur`; if sides mismatch
parity return `false`. Honest paths unaffected.

## V2 hardening (Low/Info, no behavior change except guard)
- `src/v2/merkle.rs:220-227`: `depth_for_members(0)` underflows.
  Add `if num_members==0 {return 0;}` (callers already reject 0).
- `src/v2/predicate.rs:287`: `build_witness_raw` `zip` without length
  assert. Add `debug_assert!(siblings.len()==...)` (private/test-only).
- `src/v2/merkle.rs:65-78`: add practical `MAX_V2_MEMBERS = 1<<20`
  cap (`TooManyMembers`) to avoid `depth=32` OOM on untrusted sizes.
  Does not change honest small sets.

## Re-audit
- `cargo test --offline` + `cargo test --offline --release` (fast tests).
- Manual re-check: transcript order identical both sides,
  `Gamma` dims identical, `hDelta` pre-`gamma'`, `Pu` coeff 1,
  version-2 proofs rejected, tamper tests fail, honest `tau=1,2`
  verify + round-trip.
- Thesis wording stays: experimental prototype, no 127-bit claim,
  needs independent review + FS/extractor/QROM before any claim.
