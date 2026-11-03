# V3 Adversarial Campaign — A4 algebraic manipulation

Plan: `attack.md` §4-A4. No protocol, parameter, proof-format, circuit,
V2, or documentation-logic change. No new dependencies, no second
prover, no edited challenge values, no historical-order model.
Deterministic inputs only (no RNG); the transcript shape mirrors the
small insecure test point (`N=32,ℓ=3,s=8`).

## Tests (`tests/v3_adversarial_a4.rs`, 1 passed, 0 failed)

| Test | Class | Attempt | Observed outcome |
|---|---|---|---|
| `a4_correction_bound_before_batching` | Order regression (control) | identical committed `delta_u1`, full drive twice | Identical `(Gamma, batch0, batch1)` |
| `a4_correction_bound_before_batching` | Order regression | committed `delta_u1` `1 -> 2` only | `Gamma` unchanged, `(batch0, batch1)` changed |

The drive follows the implemented schedule on the existing transcript
implementation: prefix, `h1`, `Gamma`, `h1'`, `hDelta`, then batching
challenges. This confirms the correction is committed before batching
is derived. It performs no challenge search, so it says nothing about
grinding cost, and it does not model an adaptive algebraic forgery.

## Reused existing coverage (referenced, not duplicated)

- `delta_u1` value mutation: `tampered_delta_u1_rejects`.
- Broadcast share mutation, both repetitions:
  `tampered_broadcast_shares_reject`.
- DECS response and broadcast-hash mutation:
  `tampered_proof_bytes_reject`.
- All broadcast/DECS/opening shape mutations: A3
  (`a3_broadcast_decs_shape_rejects`, `a3_opening_tampering_rejects`).

No additional structured field mutation was added: every
verifier-visible algebraic value (`delta_u1`, `broadcast_alpha`,
`broadcast_alpha_prime`, DECS responses) already has a value-mutation
regression, and inventing further arbitrary mutations would not
demonstrate rejection of invalid relations. No isolated
historical-order model was built; the regression above covers the
ordering property directly on current code.

## Limitations

- The new test exercises the transcript object, not the prover; it
  shows the schedule binds the correction first, not that an adaptive
  attacker cannot succeed.
- No adversarial proof was accepted in A4.

## Full suite after A4

`cargo test --offline`: `105` lib + `4` a1 + `2` a2 + `4` a3 +
`1` a4 + `2` p11 + `9` prototype = `127` passed, `0` failed.
Finite tests do not establish soundness, zero knowledge, proof of
knowledge, any security level, or readiness.
