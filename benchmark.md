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
| 4 | 2 | 1,420.0 | 1,339.3 | 1,277.1 | 241–283 | 180,474 | Pass |
| 8 | 3 | 1,416.4 | 1,362.3 | 1,304.8 | 258–284 | 191,994 | Pass |
| 16 | 4 | 1,484.9 | 1,374.5 | 1,367.0 | 280–289 | 203,514 | Pass |
| 32 | 5 | 1,528.1 | 1,537.2 | 1,501.7 | 300–318 | 215,034 | Pass |

Honest summary: proving takes **~1.3–1.5 s** for 4–16 members and
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

## Post-P12 measurement (new; old table retained above)

Recorded 2026-11-10 after two prover-only changes (no parameter, circuit,
protocol, transcript, proof-format, or verifier change):

- **P12a — parallel repetitions:** the `τ=2` reps run concurrently in a
  `std::thread::scope`. Per-rep 32-byte seeds are drawn sequentially from
  the caller RNG in rep order, so the same caller seed still gives the same
  proof; inner stage parallelism is capped at a fair share of machine
  threads (`src/v3/prover.rs`). The `τ=1` path is untouched and
  byte-identical to before.
- **P12b — batched correction basis:** `correction_basis_evals_for_parties`
  (`src/v3/hints.rs`) inverts the `s`-only denominator once instead of per
  party (`N-1` fewer inversions); field values are identical to the
  per-party loop it replaces.

Honesty notes: `τ=2` proof *values* differ from pre-P12 runs (re-seeded
per-rep streams) while proof *sizes* are identical (`180,474 / 191,994 /
203,514 / 215,034`) and every proof verifies plus round-trips. Three
sweeps, same scenarios/seeds as the old table, no warm-up — read ranges,
not single numbers. Same machine as the old table (i7-13620H, `nproc=16`,
14 GiB, `rustc/cargo 1.98.1`, release `opt-level=3` + LTO +
`codegen-units=1`); kernel `7.0.0-42-generic` (old rows: `-38`).

| Set members | Merkle depth | Prove sweep 1 (ms) | Prove sweep 2 (ms) | Prove sweep 3 (ms) | Verify range (ms, 2 checks x 3 sweeps) | Proof bytes | Codec round-trip |
|---:|---:|---:|---:|---:|---|---|---|
| 4 | 2 | 880.2 | 839.3 | 872.5 | 237–247 | 180,474 | Pass |
| 8 | 3 | 920.0 | 891.6 | 933.8 | 255–280 | 191,994 | Pass |
| 16 | 4 | 1,037.7 | 1,026.7 | 983.2 | 272–277 | 203,514 | Pass |
| 32 | 5 | 1,101.0 | 1,060.2 | 1,083.9 | 293–309 | 215,034 | Pass |

Raw rows:
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

Honest summary: proving now takes **~0.84–0.93 s** (4–8 members),
**~0.98–1.04 s** (16 members), **~1.06–1.10 s** (32 members);
verification is unchanged (**~0.24–0.31 s**, verifier untouched).
Versus the retained post-P11 rows above, that is roughly **1.5x faster**
on 4–8 members and **~1.4x** on 16–32 members. The sub-1000 ms goal is
met for the 4- and 8-member scenarios on all three sweeps; the
16-member scenario straddles it (one sweep under, two just over) and the
32-member scenario stays just above (`~1.06–1.10 s`). Full debug suite at
this commit: `105 lib + 4 A1 + 2 A2 + 4 A3 + 1 A4 + 2 p11 + 9 prototype
= 127` pass. As before: in-memory verify only; no parse, Fabric,
ledger, or network timing; no security claim.

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
scenario measures about 0.30–0.32 s at the same 215,034 bytes. Those historical
before/after figures are included only as context; the table above is the
current post-fix, post-P11 set-size experiment.

All figures describe this experimental prototype and this machine. They do
not establish formal soundness, zero-knowledge security, or deployment
performance on Hyperledger Fabric.

## Adversarial test campaign (not a security proof)

Small, deterministic robustness campaign per `attack.md` (plan only;
untracked in this repo). Preset everywhere: `V3Params::fast_insecure_test`
(`N=32,ℓ=3,s=8,η=2,ρ=1,τ=1`), four-member set `[10,20,30,40]`, seeded
RNGs — except the A2 swap test (`τ=2`) and the A3 odd-`N` test
(`N=33`). These presets are intentionally insecure. Final suite at
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
| A2 binding | change rep index / context, re-derive challenge | identical inputs re-derive identically | Challenge changed for each changed field | `a2_transcript_binding_changes_challenge` | Binding observation only; no grinding search |
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
