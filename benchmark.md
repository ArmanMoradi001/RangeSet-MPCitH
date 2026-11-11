# V3 prototype benchmark (post-fix v4, post-P13)

This benchmark measures the experimental V3 combined proof: one proof checks
that the same input is in the public range and belongs to a Merkle set. It
focuses on how proof cost changes as the membership set grows. These are
prototype measurements, not production guarantees or a cryptographic security
claim.

Recorded after the `fixes.md` security repairs (C1 `hDelta` binding, H1
paper-faithful `Pu`, M1 full suite binding, proof `v2 -> v4`,
transcript `v2 -> v3`), the P11 performance phase (P11.2 hoisted
lane setup; P11.4 parallel share generation; P11.5 parallel F4
sparse-linear broadcast; P11.6 parallel hint-polynomial evaluation),
P12 (parallel `τ=2` repetitions with domain-separated per-rep RNG;
batched correction-basis evaluation with a single inversion), and P13
(parallel leaf commits and opening assembly; per-rep point/basis caches)
— all with `std::thread::scope`, no parameter/protocol change.
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

Since P12 the prover runs the `τ=2` repetitions concurrently in a
`std::thread::scope` (per-rep seeds drawn sequentially from the caller RNG,
inner stage workers capped at a fair share); the verifier is
single-threaded. No `τ`/parameter, circuit, or protocol change was
made for performance.

## Scenarios and measured results (current: post-P13)

The set contains `100 + 10·i` for `i = 0..set_size-1`. Each case proves the
same value (`120`) at member index `2`, with range `[1, 1000]`. Only set size
and the resulting Merkle depth change. Each scenario generates one proof and
verifies it twice in sequence. Three sweeps on the same machine; each cell
is a single sample (no warm-up), so read the ranges, not a single number.

| Set members | Merkle depth | Prove sweep 1 (ms) | Prove sweep 2 (ms) | Prove sweep 3 (ms) | Verify range (ms, 2 checks x 3 sweeps) | Proof bytes | Codec round-trip |
|---:|---:|---:|---:|---:|---|---|---|
| 4 | 2 | 819.7 | 818.7 | 809.8 | 236–240 | 180,474 | Pass |
| 8 | 3 | 869.0 | 876.5 | 859.6 | 255–263 | 191,994 | Pass |
| 16 | 4 | 960.2 | 924.1 | 946.5 | 272–276 | 203,514 | Pass |
| 32 | 5 | 1,013.1 | 1,008.6 | 1,020.3 | 292–297 | 215,034 | Pass |

Honest summary: proving takes **~0.81–0.82 s** for 4 members,
**~0.86–0.88 s** for 8 members, **~0.92–0.96 s** for 16 members, and
**~1.01–1.02 s** for 32 members on this machine; verification takes
**~0.24–0.30 s**. Increasing the set from 4 to 32 members adds three
Merkle levels and 34,560 proof bytes
(`180,474 -> 215,034`, identical in every run). The benchmark verifies
an in-memory `V3Proof`; verification timings do not include
proof-byte parsing, Fabric endorsement, ledger commit, or network
communication.

The sub-1000 ms goal is met for the 4-, 8-, and 16-member scenarios on
all three sweeps; the 32-member scenario remains marginally above
(`~1.01–1.02 s`, best sweep `1008.6 ms`).

## History (same machine/profile, older rows retained)

Pre-P13 rows used the identical scenarios, seeds, and harness; only the
prover implementation differs. Proof bytes are identical in every row
ever recorded here.

Post-P12 (2026-11-10): `τ=2` reps concurrent + batched correction basis.
Proving `~0.84–0.93 s` (4–8 members), `~0.98–1.04 s` (16),
`~1.06–1.10 s` (32); verification `~0.24–0.31 s`.
Honesty note: `τ=2` proof *values* differ from pre-P12 runs (re-seeded
per-rep streams) while proof *sizes* are identical and every proof
verifies plus round-trips.

| Set members | Prove sweep 1 (ms) | Prove sweep 2 (ms) | Prove sweep 3 (ms) | Verify range (ms) | Proof bytes |
|---:|---:|---:|---:|---|---|
| 4 | 880.2 | 839.3 | 872.5 | 237–247 | 180,474 |
| 8 | 920.0 | 891.6 | 933.8 | 255–280 | 191,994 |
| 16 | 1,037.7 | 1,026.7 | 983.2 | 272–277 | 203,514 |
| 32 | 1,101.0 | 1,060.2 | 1,083.9 | 293–309 | 215,034 |

Post-P11 (2026-10-27): parallel share generation, sparse-linear
broadcast, and hint evaluation. Proving `~1.3–1.5 s` (4–16 members),
`~1.5 s` (32); verification `~0.24–0.32 s`.

| Set members | Prove sweep 1 (ms) | Prove sweep 2 (ms) | Prove sweep 3 (ms) | Verify range (ms) | Proof bytes |
|---:|---:|---:|---:|---|---|
| 4 | 1,420.0 | 1,339.3 | 1,277.1 | 241–283 | 180,474 |
| 8 | 1,416.4 | 1,362.3 | 1,304.8 | 258–284 | 191,994 |
| 16 | 1,484.9 | 1,374.5 | 1,367.0 | 280–289 | 203,514 |
| 32 | 1,528.1 | 1,537.2 | 1,501.7 | 300–318 | 215,034 |

Earlier 32-member history (same scenario): pre-fix v2 `~5.35–5.40 s`
prove / `~0.29 s` verify; post-fix v4 `~5.4–5.5 s` / `~0.30 s` (fixes
cost nothing measurable). Cumulative gain pre-fix → post-P13 is `~5.3x`
on 32-member proving at identical byte sizes, from parallelizing share
generation, sparse-linear broadcast, hint evaluation, repetitions, leaf
commits, and openings — the verified relation is unchanged throughout.

## How to reproduce

From the repository root, run:

```sh
cargo run --offline --release --example v3_benchmark
```

The committed harness is [`examples/v3_benchmark.rs`](examples/v3_benchmark.rs).
It prints the parameter set and one CSV row per scenario. The prover RNG is
seeded deterministically per set size. Timings are single samples with no
warm-up or statistical variance analysis; rerun the command to assess local
variation. Full test suite at this commit: `105 lib + 4 A1 + 2 A2 + 4 A3
+ 1 A4 + 2 p11 + 9 prototype = 127` pass.

## Environment for the recorded runs

- CPU: 13th Gen Intel Core i7-13620H, 10 cores / 16 threads (`nproc=16`).
- RAM: 14 GiB total; approximately 5 GiB available before the run.
- OS: Linux Ubuntu x86_64 (post-P11 rows: `7.0.0-38-generic`;
  post-P12/post-P13 rows: `7.0.0-42-generic`).
- Toolchain: `rustc 1.98.1`, `cargo 1.98.1`.
- Build: Cargo release profile (`opt-level = 3`, LTO enabled,
  `codegen-units = 1`).
- Post-P11 command completed three times on 2026-10-27; post-P12 and
  post-P13 commands three times each on 2026-11-10. All generated proofs
  verified twice and passed a serialization round-trip. Raw rows,
  post-P13:
  `4,2,819.7,180474,240.4,237.3,ok`,
  `8,3,869.0,191994,263.4,254.9,ok`,
  `16,4,960.2,203514,271.5,271.9,ok`,
  `32,5,1013.1,215034,297.0,293.3,ok` /
  `4,2,818.7,180474,238.2,239.2,ok`,
  `8,3,876.5,191994,257.3,256.2,ok`,
  `16,4,924.1,203514,275.8,273.6,ok`,
  `32,5,1008.6,215034,291.5,292.2,ok` /
  `4,2,809.8,180474,239.6,236.0,ok`,
  `8,3,859.6,191994,258.3,255.9,ok`,
  `16,4,946.5,203514,273.4,273.4,ok`,
  `32,5,1020.3,215034,293.2,293.2,ok`.
  Post-P12 raw rows:
  `4,2,880.2,180474,246.9,242.4,ok`,
  `8,3,920.0,191994,279.8,261.1,ok`,
  `16,4,1037.7,203514,277.0,273.6,ok`,
  `32,5,1101.0,215034,296.1,295.0,ok` /
  `4,2,839.3,180474,241.6,239.1,ok`,
  `8,3,891.6,191994,260.2,255.4,ok`,
  `16,4,1026.7,203514,273.6,272.2,ok`,
  `32,5,1060.2,215034,293.3,294.2,ok` /
  `4,2,872.5,180474,241.1,237.4,ok`,
  `8,3,933.8,191994,258.6,256.1,ok`,
  `16,4,983.2,203514,273.3,271.9,ok`,
  `32,5,1083.9,215034,309.4,294.6,ok`.
  Post-P11 raw rows:
  `4,2,1420.0,180474,276.8,282.5,ok`,
  `8,3,1416.4,191994,266.4,283.6,ok`,
  `16,4,1484.9,203514,281.4,289.4,ok`,
  `32,5,1528.1,215034,317.6,301.9,ok` /
  `4,2,1339.3,180474,262.1,260.9,ok`,
  `8,3,1362.3,191994,266.5,259.9,ok`,
  `16,4,1374.5,203514,286.4,280.0,ok`,
  `32,5,1537.2,215034,299.5,300.7,ok` /
  `4,2,1277.1,180474,257.7,241.4,ok`,
  `8,3,1304.8,191994,263.7,257.5,ok`,
  `16,4,1367.0,203514,281.3,279.8,ok`,
  `32,5,1501.7,215034,311.1,305.1,ok`.

## Prior optimization comparison

The earlier 32-member P10 benchmark used a different witness value and
single-case harness. Its recorded baseline verification was about 203–217 s;
the optimized verifier was about 0.30 s at 215,034 bytes. The current 32-member
scenario measures about 0.29–0.30 s at the same 215,034 bytes. Those historical
before/after figures are included only as context; the tables above are the
current post-fix, post-P13 set-size experiment.

All figures describe this experimental prototype and this machine. They do
not establish formal soundness, zero-knowledge security, or deployment
performance on Hyperledger Fabric.

## Adversarial test campaign (not a security proof)

Small, deterministic robustness campaign per `attack.md`. Preset everywhere:
`V3Params::fast_insecure_test` (`N=32,ℓ=3,s=8,η=2,ρ=1,τ=1`), four-member set
`[10,20,30,40]`, seeded RNGs — except the A2 swap test (`τ=2`) and the A3
odd-`N` test (`N=33`). These presets are intentionally insecure. Final suite at
campaign end: `105` lib + `4` A1 + `2` A2 + `4` A3 + `1` A4 +
`2` p11 + `9` prototype = `127` passed, `0` failed.

Honest controls (A0): valid 4/8/16/32-member proofs verified twice
with codec round-trip `ok`; proof sizes `180,474`, `191,994`,
`203,514`, `215,034` bytes — identical to every run in this document.
The A0 machine was loaded, so its timings ran roughly 1.5–1.9x above the
rows above depending on case (about 1.9x on the 32-member proving time),
including on the untouched verifier; that is shared-machine
variance, not a regression, and those timings are not presented as a
performance result.

| Scenario | Attempt | Honest control | Observed outcome | Test(s) | Limitation |
|---|---|---|---|---|---|
| A1 boundary | value == `lo`/`hi` of the range, real member | same proof verifies + round-trips | Verified + round-trip ok | `tests/v3_adversarial_a1.rs::a1_boundary_witnesses_verify` | Controls only; small preset |
| A1 out-of-range | member below `lo` / above `hi` via public prover API | — (builder refused) | Refused at witness build | `a1_out_of_range_builder_refusals` | Prover-API refusal, not a verifier result |
| A1 mismatched membership | cross-member proof swap; hand-edited index/path | — (builder refused) | Refused at witness build | `a1_mismatched_membership_builder_refusals` | Private inputs; not a verifier result |
| A1 statement binding | one honest proof vs altered `lo`/`hi`/widened range/member count | honest statement verifies | Rejected | `a1_altered_statement_binding_rejects` | Non-canonical depth unconstructible (constructor refusal) |
| A2 replay | τ=2 proof with `reps[0]`/`reps[1]` swapped | unswapped proof verifies | Rejected | `tests/v3_adversarial_a2.rs::a2_repetition_slot_swap_rejects` | Tampered honest proof, not a forgery |
| A2 binding | change rep index / context, re-derive challenge | identical inputs re-derive identically | Challenge changed for each changed field | `tests/v3_adversarial_a2.rs::a2_transcript_binding_changes_challenge` | Binding observation only; no grinding search |
| A3 openings | alter index/leaf-randomness/sibling/direction/path length/share count/opened count (fresh copy each) | unmutated proof verifies | Rejected, no panic/hang/overallocation | `tests/v3_adversarial_a3.rs::a3_opening_tampering_rejects` | Selected mutations only |
| A3 broadcast/DECS shapes | short `broadcast_alpha[_prime]`, missing batch, short/missing DECS row | unmutated proof verifies | Rejected | `a3_broadcast_decs_shape_rejects` | Shape checks, not value forgeries |
| A3 parser | empty input; half truncation; `reps` prefix `= u32::MAX` | valid bytes parse | Rejected (cap before allocation) | `a3_parser_malformed_rejects` | No time bound asserted; not a DoS proof |
| A3 odd N | honest proof, share-commitment `N=33` (lonely leaf) | verifies + round-trips | Verified + round-trip ok | `a3_odd_party_count_end_to_end` | One odd size only |
| A4 ordering | drive transcript twice identically; then change only committed `delta_u1` | identical drive reproduces | `Gamma` unchanged, batching challenges changed | `tests/v3_adversarial_a4.rs::a4_correction_bound_before_batching` | Order check on transcript object, not an adaptive attack |
| A4 tamper (reused) | flip `delta_u1` in an honest proof | unmutated proof verifies | Rejected | `tests/v3_prototype.rs::tampered_delta_u1_rejects` | Value mutation, not an adaptive forgery |

Not performed: no adaptive malicious prover and no false-statement
proof was constructed or submitted to the verifier in any scenario
(A1 would have required a second protocol implementation; A4
performs no challenge search). Prover/witness-builder refusals (A1
out-of-range and mismatched-membership rows) say nothing about
verifier soundness beyond the listed binding/rejection checks.

These finite tests do not establish soundness, zero knowledge, proof
of knowledge, 127-bit security, resistance to untested attacks, or
production readiness. Full per-scenario reports:
`docs/adversarial-A0-baseline.md`, `docs/adversarial-A1.md`,
`docs/adversarial-A2.md`, `docs/adversarial-A3.md`,
`docs/adversarial-A4.md`.
