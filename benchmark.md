# V3 prototype benchmark (post-fix v4, post-P11)

This benchmark measures the experimental V3 combined proof: one proof checks
that the same input is in the public range and belongs to a Merkle set. It
focuses on how proof cost changes as the membership set grows. These are
prototype measurements, not production guarantees or a cryptographic security
claim.

Recorded after the `fixes.md` security repairs (C1 `hDelta` binding, H1
paper-faithful `Pu`, M1 full suite binding, proof `v2 -> v4`,
transcript `v2 -> v3`) and the P11 performance phase (P11.2 hoisted
lane setup; P11.4 parallel share generation; P11.5 parallel F4
sparse-linear broadcast; P11.6 parallel hint-polynomial evaluation —
all with `std::thread::scope`, no parameter/protocol change).
Proof bytes are unchanged by every fix and optimization.

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

The interactive template has **8 message steps per repetition**:
commitment (`h1`), challenge (`Gamma`), second commitment (`h1'`),
delta commitment (`hDelta`), batching challenge (`gamma,gamma'`),
broadcast (`hB`), opening challenge (`I`), and opening response.
Thus this parameter set has two logical repetitions of that template.
V3 applies Fiat–Shamir, so the deployed proof is non-interactive: the
challenges are derived from the transcript and there are no online network
exchanges per repetition. The serialized proof contains both repetitions.

The prover uses `std::thread::scope` with up to 16 workers
(`available_parallelism` on the machine below); the verifier is
single-threaded. No `τ`/parameter, circuit, or protocol change was
made for performance.

## Scenarios and measured results

The set contains `100 + 10·i` for `i = 0..set_size-1`. Each case proves the
same value (`120`) at member index `2`, with range `[1, 1000]`. Only set size
and the resulting Merkle depth change. Each scenario generates one proof and
verifies it twice in sequence. Three sweeps on the same machine; each cell
is a single sample (no warm-up), so read the ranges, not a single number.

| Set members | Merkle depth | Prove sweep 1 (ms) | Prove sweep 2 (ms) | Prove sweep 3 (ms) | Verify range (ms, 2 checks x 3 sweeps) | Proof bytes | Codec round-trip |
|---:|---:|---:|---:|---:|---|---|---|
| 4 | 2 | 1,347.4 | 1,373.1 | 1,318.7 | 240–275 | 180,474 | Pass |
| 8 | 3 | 1,395.2 | 1,382.5 | 1,322.9 | 255–291 | 191,994 | Pass |
| 16 | 4 | 1,420.1 | 1,410.8 | 1,414.1 | 273–292 | 203,514 | Pass |
| 32 | 5 | 1,501.5 | 1,512.7 | 1,510.6 | 297–318 | 215,034 | Pass |

Honest summary: proving takes **~1.3–1.4 s** for 4–16 members and
**~1.5 s** for 32 members on this machine; verification takes
**~0.24–0.32 s**. Increasing the set from 4 to 32 members adds three
Merkle levels and 34,560 proof bytes
(`180,474 -> 215,034`, identical in every run). The benchmark verifies
an in-memory `V3Proof`; verification timings do not include
proof-byte parsing, Fabric endorsement, ledger commit, or network
communication.

History on the same machine/profile (same 32-member scenario):
pre-fix v2 `~5.35–5.40 s` prove / `~0.29 s` verify;
post-fix v4 `~5.4–5.5 s` / `~0.30 s` (fixes cost nothing measurable);
post-P11 `~1.5 s` / `~0.30 s` at identical byte sizes. The P11 gain
(`~3.7x` on 32-member) comes from parallelizing share generation,
sparse-linear broadcast, and hint evaluation — proof bytes and the
verified relation are unchanged.

## How to reproduce

From the repository root, run:

```sh
cargo run --offline --release --example v3_benchmark
```

The committed harness is [`examples/v3_benchmark.rs`](examples/v3_benchmark.rs).
It prints the parameter set and one CSV row per scenario. The prover RNG is
seeded deterministically per set size. Timings are single samples with no
warm-up or statistical variance analysis; rerun the command to assess local
variation. Full test suite at this commit: `105 lib + 2 p11 + 9 prototype
= 116` pass.

## Environment for the recorded run

- CPU: 13th Gen Intel Core i7-13620H, 10 cores / 16 threads (`nproc=16`).
- RAM: 14 GiB total; approximately 5 GiB available before the run.
- OS: Linux 7.0.0-38-generic, Ubuntu, x86_64.
- Toolchain: `rustc 1.98.1`, `cargo 1.98.1`.
- Build: Cargo release profile (`opt-level = 3`, LTO enabled,
  `codegen-units = 1`).
- Command completed three times on 2026-10-27 (post-P11.6); all twelve
  generated proofs verified twice and passed a serialization round-trip.
  Raw rows:
  `4,2,1347.4,180474,268.3,259.6,ok`,
  `8,3,1395.2,191994,291.1,264.3,ok`,
  `16,4,1420.1,203514,287.9,279.2,ok`,
  `32,5,1501.5,215034,304.3,300.0,ok` /
  `4,2,1373.1,180474,274.6,264.8,ok`,
  `8,3,1382.5,191994,268.6,260.9,ok`,
  `16,4,1410.8,203514,288.8,276.0,ok`,
  `32,5,1512.7,215034,306.7,312.6,ok` /
  `4,2,1318.7,180474,255.0,258.6,ok`,
  `8,3,1322.9,191994,270.9,264.2,ok`,
  `16,4,1414.1,203514,282.4,283.4,ok`,
  `32,5,1510.6,215034,317.7,311.8,ok`.

## Prior optimization comparison

The earlier 32-member P10 benchmark used a different witness value and
single-case harness. Its recorded baseline verification was about 203–217 s;
the optimized verifier was about 0.30 s at 215,034 bytes. The current 32-member
scenario measures about 0.30–0.32 s at the same 215,034 bytes. Those historical
before/after figures are included only as context; the table above is the
current post-fix, post-P11 set-size experiment.

All figures describe this experimental prototype and this machine. They do
not establish formal soundness, zero-knowledge security, or deployment
performance on Hyperledger Fabric.
