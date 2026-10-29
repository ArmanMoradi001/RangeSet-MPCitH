# V3 Adversarial Campaign — A2 transcript replay and repetition binding

Plan: `attack.md` §4-A2. No protocol, parameter, proof-format, circuit,
V2, or documentation-logic change. No new dependencies.
Preset for the verifier test: `V3Params::new(32, 3, 8, 2, 1, 2)`
(two repetitions), four-member set `[10,20,30,40]`, seeded
`ChaCha20Rng(0xA2A2_A2A2)`. This preset is intentionally insecure;
outcomes are implementation-robustness observations only.

## A1 wording clarification (included in this commit)

`docs/adversarial-A1.md` previously said “No false statement was
accepted by any API”. That phrasing is imprecise: A1 never generated
an invalid-witness proof, so no API was presented with one. It now
reads “no invalid-witness proof was generated and presented to the
verifier”. The limitation — a true malicious-proof experiment was not
performed — is unchanged.

## Tests (`tests/v3_adversarial_a2.rs`, 2 passed, 0 failed)

| Test | Class | Attempt | Observed outcome |
|---|---|---|---|
| `a2_repetition_slot_swap_rejects` | Verifier result (honest control first) | genuine τ=2 proof verifies | Verified (control) |
| `a2_repetition_slot_swap_rejects` | Verifier result (attack attempt) | same proof with `reps[0]`/`reps[1]` swapped | Rejected |
| `a2_transcript_binding_changes_challenge` | Binding observation (control) | identical inputs derive the challenge twice | Identical |
| `a2_transcript_binding_changes_challenge` | Binding observation | repetition index 0 → 1, all else fixed | Changed |
| `a2_transcript_binding_changes_challenge` | Binding observation | context byte change, all else fixed | Changed |

Reused existing coverage (referenced, not duplicated):
`wrong_expected_statement_context_or_params_reject` (wrong context,
wrong `pok_reps`), `cloned_repetition_slot_is_rejected` (duplicated
payload; the swap here is the distinct ordering case),
`tampered_delta_u1_rejects` (correction mutation). Range-only replay
is covered by A1's altered-range binding checks
(`a1_altered_statement_binding_rejects`).

## Limitations

- The swap test mutates an honest proof; it is tampering, not a
  general forgery attempt. The binding test checks two fields
  (repetition index, context) on the existing transcript
  implementation; it performs no challenge search and says nothing
  about grinding cost or query security.
- No adversarial proof was accepted in A2.

## Full suite after A2

`cargo test --offline`: `105` lib + `4` a1 + `2` a2 + `2` p11 +
`9` prototype = `122` passed, `0` failed. Finite tests do not
establish soundness, zero knowledge, proof of knowledge, any security
level, or readiness.
