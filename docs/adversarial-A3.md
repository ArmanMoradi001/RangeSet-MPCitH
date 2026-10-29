# V3 Adversarial Campaign — A3 commitment/opening/parser tampering

Plan: `attack.md` §4-A3. No protocol, parameter, proof-format, circuit,
V2, or documentation-logic change. No new dependencies, no fuzzer.
Preset: `V3Params::fast_insecure_test` (`N=32,ℓ=3,s=8,η=2,ρ=1,τ=1`),
four-member set `[10,20,30,40]`, seeded `ChaCha20Rng(0xA3A3_A3A3)`
— except the odd-`N` test, which uses `V3Params::new(33,3,8,2,1,1)`.
Both presets are intentionally insecure; outcomes are
implementation-robustness observations only.

## Tests (`tests/v3_adversarial_a3.rs`, 4 passed, 0 failed)

| Test | Attempt (fresh copy each) | Observed outcome |
|---|---|---|
| `a3_opening_tampering_rejects` | honest control verifies | Verified (control) |
| `a3_opening_tampering_rejects` | `opened[0].party_index + 1` | Rejected |
| `a3_opening_tampering_rejects` | `leaf_randomness[0] ^= 1` | Rejected |
| `a3_opening_tampering_rejects` | `path[0][0] ^= 1` (sibling) | Rejected |
| `a3_opening_tampering_rejects` | flip `path_left[0]` (direction) | Rejected |
| `a3_opening_tampering_rejects` | pop one path step (+ side bit) | Rejected |
| `a3_opening_tampering_rejects` | push one bogus path step | Rejected |
| `a3_opening_tampering_rejects` | pop one share from `opened[0].shares` | Rejected |
| `a3_opening_tampering_rejects` | pop one opened party | Rejected |
| `a3_broadcast_decs_shape_rejects` | honest control verifies | Verified (control) |
| `a3_broadcast_decs_shape_rejects` | pop one `broadcast_alpha[0]` share | Rejected |
| `a3_broadcast_decs_shape_rejects` | pop `broadcast_alpha` batch | Rejected |
| `a3_broadcast_decs_shape_rejects` | pop one `broadcast_alpha_prime[0]` share | Rejected |
| `a3_broadcast_decs_shape_rejects` | pop one `decs_responses[0]` element | Rejected |
| `a3_broadcast_decs_shape_rejects` | pop `decs_responses` row | Rejected |
| `a3_parser_malformed_rejects` | empty input | Rejected (parse) |
| `a3_parser_malformed_rejects` | half-length truncation | Rejected (parse) |
| `a3_parser_malformed_rejects` | reps length prefix `= u32::MAX` (offset 178, self-checked) | Rejected at the length cap, no large allocation |
| `a3_odd_party_count_end_to_end` | honest proof, `N=33`, verify + round-trip | Verified + round-trip ok |

Reused existing coverage (referenced, not duplicated): opened share
and DECS response *values*, commitment root, broadcast hash and
share *values* (`tampered_proof_bytes_reject`,
`tampered_broadcast_shares_reject`); codec magic/version/trailing/
noncanonical/side-bit and 20-byte truncation (`src/v3/proof.rs`
tests); odd-node, wrong leaf/index/side/root, truncated-path unit
cases (`src/v3/commit.rs` tests). The odd-`N` test targets the V3
share-commitment tree (`N=33`), not the 4-member statement tree.

## Limitations

- Every tamper case mutates an honest proof; these are rejection
  checks, not forgery attempts. No malformed input was accepted, and
  no bounded input panicked, hung, or over-allocated during the run.
  This is not a denial-of-service proof and does not cover all
  malformed inputs.
- The oversized-prefix case asserts rejection, not a time bound;
  fail-fast follows by inspection (cap checked before allocation).
- No adversarial proof was accepted in A3.

## Full suite after A3

`cargo test --offline`: `105` lib + `4` a1 + `2` a2 + `4` a3 +
`2` p11 + `9` prototype = `126` passed, `0` failed. Finite tests do
not establish soundness, zero knowledge, proof of knowledge, any
security level, or readiness.
