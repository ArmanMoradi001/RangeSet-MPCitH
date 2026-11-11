# RangeSet-MPCitH

An experimental **MPC-in-the-head** proof prototype: one non-interactive
proof that a single private 32-bit integer satisfies a public range check
**and** belongs to a public Merkle set, simultaneously.

> **Research status — read before citing.** This is an experimental
> implementation with open proof obligations (no extractor, no simulator,
> no QROM lift, no tight Fiat–Shamir bound) and no independent security
> review. Do not describe it as formally secure, as 127-bit secure, or as
> production/deployment ready. See [`docs/audit-status.md`](docs/audit-status.md)
> and [`docs/external-review-packet.md`](docs/external-review-packet.md).

## What it proves

- **Public statement:** range bounds `[lo, hi]`, Merkle set root plus
  `(num_members, depth)`, and a 32-byte application context.
- **Private witness:** one `u32` value shared by both predicates, plus its
  native Merkle membership path.
- **Guarantee (implemented, not proven):** the combined circuit allocates a
  single input wire for both checks, so one proof covers both predicates
  for the same value by construction. The verifier rebuilds the relation
  from its own expected statement and rejects anything else.

Construction: TCitH-MT over a ΠLigero-style LPPC compilation of the V2
arithmetic circuit (BN254 `Fr`, BLAKE3 transcript/commitments, Poseidon2
membership hashing), Fiat–Shamir serialized as `V3Proof` (format v4).
Protocol details: [`docs/protocol.md`](docs/protocol.md).

## Quick start

```sh
cargo test --offline                              # full suite: 127 pass
cargo run --offline --release --example v3_benchmark   # set-size benchmark
cargo run --offline --release --example v3_profile     # prover cost profile
```

## Performance snapshot

Post-P13 release figures (i7-13620H, `N=8192, ℓ=30, s=120, η=6, ρ=1, τ=2`):

| Set size | Prove | Verify (in-memory) | Proof bytes |
|---:|---|---|---:|
| 4 | ~0.81–0.82 s | ~0.24 s | 180,474 |
| 8 | ~0.86–0.88 s | ~0.26 s | 191,994 |
| 16 | ~0.92–0.96 s | ~0.27 s | 203,514 |
| 32 | ~1.01–1.02 s | ~0.29–0.30 s | 215,034 |

These are single-machine prototype timings (no warm-up analysis; verify
excludes byte parsing, ledger, and network). Full tables, history, and
methodology: [`benchmark.md`](benchmark.md).

## Testing

- `tests/v3_prototype.rs` — honest proofs, determinism, negative paths,
  parser/commitment/broadcast/`delta_u1` tamper rejection.
- `tests/v3_adversarial_a{1,2,3,4}.rs` — documented robustness campaign
  (predicate substitution, replay/binding, opening/parser tampering,
  transcript ordering). Finite rejection tests only; they establish no
  soundness, zero-knowledge, or proof-of-knowledge claim.
- `tests/v3_p11_perf.rs` — parallel-vs-sequential equivalence checks.
- `cargo test --offline` runs everything: **105 lib + 35 integration = 140 pass.**

## Project layout

- `src/v3/` — parameters, packed sharing, hint generation, commitments,
  transcript/challenges, proof codec, prover, verifier.
- `src/v2/` — reused relation layer only: circuit builder, field encoding,
  Poseidon2 + Merkle membership, statement compiler, suite ids. The old V2
  proof protocol is **not** part of this crate (the `v2` module name is a
  source-path legacy).
- `examples/` — `v3_benchmark` (set-size sweep), `v3_profile` (prover
  cost breakdown).
- `docs/` — protocol spec, Fiat–Shamir/interactive-soundness analyses,
  parameter feasibility, audit status, external review packet, and the
  per-scenario adversarial reports (`adversarial-A*.md`).
- `attack.md` — adversarial campaign roadmap (completed; results in
  `benchmark.md` and `docs/adversarial-A*.md`).
- `fixes.md` — repaired-audit-findings log (C1/H1/M1/M2/L1/L2, all fixed
  in-tree with regressions).

## Scope and limitations

Correct thesis-level description: *"an experimental implementation of a
combined range-and-membership MPC-in-the-head proof artifact, with
demonstrated honest-path behavior and listed tamper rejection, whose
cryptographic analysis remains open."* There is no Hyperledger Fabric
integration in this repository, and none of the figures above describe
on-ledger performance.
