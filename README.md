# RangeSet-MPCitH

A clean research prototype for one MPC-in-the-head proof that a private input
satisfies a public range check and belongs to a public Merkle set.

> **Research status:** experimental implementation only. The V3 construction
> has open proof obligations and has not received independent security review.
> Do not describe it as formally secure or as a 127-bit-secure system.

## Quick start

```sh
cargo test --offline
cargo run --offline --release --example v3_benchmark
```

The benchmark varies the set size across 4, 8, 16, and 32 members while
keeping the range and V3 proof parameters fixed. See [benchmark.md](benchmark.md)
for the recorded timings and exact scenario details.

## Project layout

- `src/v3/` — V3 protocol parameters, sharing, commitments, transcript,
  proof encoding, prover, and verifier.
- `src/v2/` — only the V2-derived circuit, field, Poseidon2 Merkle membership,
  statement compiler, and suite support that V3 currently reuses. The V2
  proof protocol and its prover/verifier are not copied into this project.
- `tests/v3_prototype.rs` — end-to-end positive, negative, and tampering tests.
- `examples/v3_benchmark.rs` — reproducible membership-size benchmark.
- `docs/` — protocol description and current security analyses/status.

The `v2` module name remains in the Rust paths because the V3 implementation
currently uses those source-level types. It does not mean this crate includes
the old V2 proof protocol.
