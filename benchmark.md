# V3 prototype benchmark (post-fix, proof v4)

This benchmark measures the experimental V3 combined proof: one proof checks
that the same input is in the public range and belongs to a Merkle set. It
focuses on how proof cost changes as the membership set grows. These are
prototype measurements, not production guarantees or a cryptographic security
claim.

Recorded after the `fixes.md` security repairs (C1 `hDelta` binding, H1
paper-faithful `Pu`, M1 full suite binding, proof `v2 -> v4`,
transcript `v2 -> v3`). Proof bytes are unchanged by the fixes
(`Gamma` resize and `hDelta` are transcript-only; `delta_u1` was already
stored).

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

The interactive template now has **8 message steps per repetition**:
commitment (`h1`), challenge (`Gamma`), second commitment (`h1'`),
delta commitment (`hDelta`, C1 fix), batching challenge (`gamma,gamma'`),
broadcast (`hB`), opening challenge (`I`), and opening response.
Thus this parameter set has two logical repetitions of that template.
V3 applies Fiat–Shamir, so the deployed proof is non-interactive: the
challenges are derived from the transcript and there are no online network
exchanges per repetition. The serialized proof contains both repetitions.

## Scenarios and measured results

The set contains `100 + 10·i` for `i = 0..set_size-1`. Each case proves the
same value (`120`) at member index `2`, with range `[1, 1000]`. Only set size
and the resulting Merkle depth change. Each scenario generates one proof and
verifies it twice in sequence (fresh run, single sample per case).

| Set members | Merkle depth | Prove (ms) | Verify 1 (ms) | Verify 2 (ms) | Proof bytes | Codec round-trip |
|---:|---:|---:|---:|---:|---:|---|
| 4 | 2 | 4,388.6 | 256.9 | 284.1 | 180,474 | Pass |
| 8 | 3 | 5,099.6 | 259.1 | 256.8 | 191,994 | Pass |
| 16 | 4 | 5,022.8 | 289.7 | 274.5 | 203,514 | Pass |
| 32 | 5 | 5,484.0 | 351.4 | 315.1 | 215,034 | Pass |

Increasing the set from 4 to 32 members adds three Merkle levels and 34,560
proof bytes (identical to pre-fix: `180,474 -> 215,034`). Proving took
~4.39 s for 4 members and ~5.48 s for 32; verification took ~0.26–0.28 s
and ~0.32–0.35 s respectively. The 8-member prove sample (`5.10 s`)
exceeds the 16-member sample (`5.02 s`) here, consistent with a shared
development machine and single samples with no warm-up. The benchmark
verifies an in-memory `V3Proof`; verification timings do not include
proof-byte parsing, Fabric endorsement, ledger commit, or network
communication.

Previous pre-fix run (2026-10-27, proof v2, same machine) for reference:
4-member prove `3.80–3.93 s` / verify `~0.24 s`; 32-member prove
`5.35–5.40 s` / verify `~0.29 s` at identical byte sizes. Differences are
within machine-variation plus the extra `hDelta` hash and `Pu` path;
no size regression.

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
- RAM: 14 GiB total; approximately 5 GiB available before the run.
- OS: Linux 7.0.0-38-generic, Ubuntu, x86_64.
- Toolchain: `rustc 1.98.1`, `cargo 1.98.1`.
- Build: Cargo release profile (`opt-level = 3`, LTO enabled,
  `codegen-units = 1`).
- Command completed on 2026-10-27 (single sweep, post-fix v4);
  all four generated proofs verified twice and passed a serialization
  round-trip. Raw output:
  `4,2,4388.6,180474,256.9,284.1,ok`,
  `8,3,5099.6,191994,259.1,256.8,ok`,
  `16,4,5022.8,203514,289.7,274.5,ok`,
  `32,5,5484.0,215034,351.4,315.1,ok`.

## Prior optimization comparison

The earlier 32-member P10 benchmark used a different witness value and
single-case harness. Its recorded baseline verification was about 203–217 s;
the optimized verifier was about 0.30 s at 215,034 bytes. The current 32-member
scenario measures about 0.32–0.35 s at the same 215,034 bytes. Those historical
before/after figures are included only as context; the table above is the
current post-fix set-size experiment.

All figures describe this experimental prototype and this machine. They do
not establish formal soundness, zero-knowledge security, or deployment
performance on Hyperledger Fabric.
