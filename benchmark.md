# V3 prototype benchmark

This benchmark measures the experimental V3 combined proof: one proof checks
that the same input is in the public range and belongs to a Merkle set. It
focuses on how proof cost changes as the membership set grows. These are
prototype measurements, not production guarantees or a cryptographic security
claim.

## Protocol settings and meaning of “rounds”

All four cases use the same V3 parameters:

| Parameter | Value | Meaning |
|---|---:|---|
| `N` | 8,192 | Simulated MPC parties in the proof protocol; these are not Fabric peers or physical nodes. |
| `ℓ` | 30 | Privacy threshold parameter. |
| `s` | 120 | Packed witness width. |
| `η` | 6 | DECS repetition parameter. |
| `ρ` | 1 | MPC-in-the-head repetition parameter. |
| `τ` | 2 | Independent proof repetitions (`pok_reps`). |

The interactive protocol template has **7 message steps per repetition**:
commitment, challenge, second commitment, batching challenge, broadcast,
opening challenge, and opening response. Thus this parameter set has two
logical repetitions of that template. V3 applies Fiat–Shamir, so the deployed
proof is non-interactive: the challenges are derived from the transcript and
there are no seven online network exchanges per repetition. The serialized
proof contains both repetitions.

## Scenarios and measured results

The set contains `100 + 10·i` for `i = 0..set_size-1`. Each case proves the
same value (`120`) at member index `2`, with range `[1, 1000]`. Only set size
and the resulting Merkle depth change. Each scenario generates one proof and
verifies it twice in sequence.

| Set members | Merkle depth | Prove run 1 (ms) | Verify run 1 (ms, 2 checks) | Prove run 2 (ms) | Verify run 2 (ms, 2 checks) | Proof bytes | Codec round-trip |
|---:|---:|---:|---:|---:|---:|---:|---|
| 4 | 2 | 3,934.9 | 238.2, 236.0 | 3,796.9 | 236.3, 236.7 | 180,474 | Pass |
| 8 | 3 | 4,320.7 | 254.8, 259.1 | 4,362.6 | 284.1, 264.6 | 191,994 | Pass |
| 16 | 4 | 4,840.4 | 276.8, 273.6 | 4,951.1 | 282.9, 327.3 | 203,514 | Pass |
| 32 | 5 | 5,348.7 | 291.6, 291.3 | 5,399.0 | 291.9, 290.9 | 215,034 | Pass |

Each scenario was run twice; each generated proof was then verified twice.
Increasing the set from 4 to 32 members adds three Merkle levels and 34,560
proof bytes. Across the two runs, proving took 3.80–3.93 seconds for 4
members and 5.35–5.40 seconds for 32; verification took about 0.24 seconds
and 0.29 seconds respectively. Some intermediate verification samples vary
more, consistent with a shared development machine and this small sample.
The benchmark verifies an in-memory `V3Proof`; verification timings do not
include proof-byte parsing, Fabric endorsement, ledger commit, or network
communication.

## How to reproduce

From the repository root, run:

```sh
cargo run --offline --release --example v3_benchmark
```

The committed harness is [`examples/v3_benchmark.rs`](examples/v3_benchmark.rs).
It prints the parameter set and one CSV row per scenario. The prover RNG is
seeded deterministically per set size. Timings are single samples with no
warm-up or statistical variance analysis; rerun the command to assess local
variation.

## Environment for the recorded run

- CPU: 13th Gen Intel Core i7-13620H, 10 cores / 16 threads.
- RAM: 14 GiB total; approximately 9 GiB available before the run.
- OS: Linux 7.0.0-38-generic, Ubuntu, x86_64.
- Toolchain: `rustc 1.98.1`, `cargo 1.98.1`.
- Build: Cargo release profile (`opt-level = 3`, LTO enabled,
  `codegen-units = 1`).
- Command completed twice on 2026-10-27; all eight generated proofs
  verified and passed a serialization round-trip.

## Prior optimization comparison

The earlier 32-member P10 benchmark used a different witness value and
single-case harness. Its recorded baseline verification was about 203–217 s;
the optimized verifier was about 0.30 s at 215,034 bytes. The current 32-member
scenario measures about 0.29 s. Those historical before/after figures are
included only as context; the table above is the current set-size experiment.

All figures describe this experimental prototype and this machine. They do
not establish formal soundness, zero-knowledge security, or deployment
performance on Hyperledger Fabric.
