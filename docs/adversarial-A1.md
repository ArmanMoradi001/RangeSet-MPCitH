# V3 Adversarial Campaign — A1 predicate/witness substitution

Plan: `attack.md` §4-A1. No protocol, parameter, proof-format, circuit,
V2, or documentation-logic change. No new dependencies.
Preset for every test: `V3Params::fast_insecure_test`
(`N=32,ℓ=3,s=8,η=2,ρ=1,τ=1`), four-member set `[10,20,30,40]`,
seeded `ChaCha20Rng(0xA1A1_A1A1)`. This preset is intentionally
insecure; outcomes are implementation-robustness observations only.

## Tests (`tests/v3_adversarial_a1.rs`, 4 passed, 0 failed)

| Test | Class | Attempt | Observed outcome |
|---|---|---|---|
| `a1_boundary_witnesses_verify` | Honest control | value 20 == lo of `[20,40]`, member idx 1: prove, verify, codec round-trip | Verified + round-trip ok |
| `a1_boundary_witnesses_verify` | Honest control | value 20 == hi of `[10,20]`, member idx 1: prove, verify, codec round-trip | Verified + round-trip ok |
| `a1_out_of_range_builder_refusals` | Prover refusal | member 10 vs `[11,40]` (below lo) via public prover API | Refused (`is_err`) |
| `a1_out_of_range_builder_refusals` | Prover refusal | member 40 vs `[10,39]` (above hi) | Refused |
| `a1_out_of_range_builder_refusals` | Prover refusal | member 20 vs `[10,19]` (above hi) | Refused |
| `a1_mismatched_membership_builder_refusals` | Prover refusal | member 30 with member 20's path (idx 1) | Refused |
| `a1_mismatched_membership_builder_refusals` | Prover refusal | hand-edited path (`leaf_index` 1→0, siblings unchanged) | Refused |
| `a1_altered_statement_binding_rejects` | Verifier check | honest `[10,40]` proof vs `[11,40]` | Rejected |
| `a1_altered_statement_binding_rejects` | Verifier check | same proof vs `[10,39]` | Rejected |
| `a1_altered_statement_binding_rejects` | Verifier check | same proof vs widened `[1,1000]` | Rejected |
| `a1_altered_statement_binding_rejects` | Verifier check | same proof vs `(root, 3 members, depth 2)` | Rejected |
| `a1_altered_statement_binding_rejects` | Constructor refusal | `MembershipStatementV2::new(root,4,3)` and `(root,4,1)` | Refused (non-canonical depth; no verifier check reached) |

Reused existing coverage (not duplicated): nonmember 99 with the
index-1 path (`false_statements_cannot_prove`), value 20 vs
`[21,40]` (same test), wrong-root/context/`pok_reps` replay
(`wrong_expected_statement_context_or_params_reject`).

## Not performed

A true malicious-proof experiment — constructing an invalid-witness
proof outside the public prover API and presenting it to the verifier —
was not performed: it would require a second protocol implementation
or a broad production refactor, which is out of scope for this
campaign (`attack.md` §4-A1). Prover-side refusals above therefore say
nothing about verifier soundness beyond the listed statement-binding
checks. No invalid-witness proof was generated and presented to the
verifier in A1, so no such experiment could accept or reject one.

## Full suite after A1

`cargo test --offline`: `105` lib + `4` a1 + `2` p11 + `9` prototype =
`120` passed, `0` failed. Finite tests do not establish soundness,
zero knowledge, proof of knowledge, any security level, or readiness.
