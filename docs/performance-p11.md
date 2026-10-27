# P11 prover performance phase — baseline (no code change)

Scope: narrowly scoped prover speedup only. Protocol, proof format
(`v4`), circuit, parameters (`N=8192,ℓ=30,s=120,η=6,ρ=1,τ=2`),
and V2 are unchanged. No security claim.

## Baseline (existing benchmark scenario, same machine/build)

Command: `cargo run --offline --release --example v3_benchmark`
Date (UTC): 2026-10-27. Machine: i7-13620H (10c/16t), 14 GiB RAM
(~5 GiB avail during run), Linux 7.0.0-38-generic x86_64.
Toolchain: `rustc 1.98.1`, `cargo 1.98.1`.
Build: release `opt-level=3`, LTO, `codegen-units=1`.

| Set | Depth | Prove (ms) | Verify1 (ms) | Verify2 (ms) | Bytes | Roundtrip |
|---:|---:|---:|---:|---:|---:|---|
| 4 | 2 | 3903.0 | 249.8 | 244.0 | 180474 | ok |
| 8 | 3 | 4465.9 | 267.4 | 261.2 | 191994 | ok |
| 16 | 4 | 4960.1 | 278.2 | 284.0 | 203514 | ok |
| 32 | 5 | 5447.4 | 299.4 | 301.8 | 215034 | ok |

Raw:
`params=N:8192,ell:30,s:120,eta:6,rho:1,tau:2`,
`range=[1,1000] value=120 member_index=2`.

Thread count: benchmark is single-threaded (no `rayon`/threads in
`Cargo.toml`; `std::thread` not used in prover path).

## Next (P11.1)

Profile actual dominant prover costs with targeted release timings
before any optimization. No operation-count assumptions.

## P11.1 profile (release, 32-member worst case, same machine/build)

Harness: `cargo run --offline --release --example v3_profile`
(committed as `examples/v3_profile.rs`; deterministic seed `0xC10C`).

| Section | What | ms |
|---|---|---:|
| A | relation compile + witness | 20.6 |
| B | packed shares, witness+`eta` masks (`52 x N=8192`) | 1586.3 |
| C | hints sample+eval+correct+derive (`4` cols) | 235.3 |
| D | leaf commits (`N x 56` cols) | 29.2 |
| D2 | Merkle root | 1.3 |
| E | Merkle paths (`ell=30`) | 38.4 |
| F1 | lane interpolator build | 72.6 |
| F2 | quadratic broadcast (`299 x m1=15`) | 0.3 |
| F3 | lane bases (`d2+1=269`) | 107.9 |
| F4 | sparse linear (`269 x m2=3642`) | 540.3 |
| G | Pxi interp (`eta=6 x 150`) | 16.0 |
| G2 | broadcast interp (`299`) | 8.6 |
| H | full `prove_combined_v3` (`tau=2`) | 5490.4, `215034 B` |

Reading: per-rep cost is `B (~60%) + F4 (~20%) + C (~9%) + F3/F1`.
`B/F4/C` depend on witness/randomness/challenges (need care);
`F1+F3 (~180ms)` depend only on program/params (safe to hoist).
Leaf hashing/Merkle/interp are negligible. One rep ≈ `2.6s`,
`xτ=2` ≈ `5.3s` + relation/packaging matches `H`.

## P11.2 change (first category: reuse only, no parallelism)

Hoisted invariant setup out of the per-rep loop in
`src/v3/prover.rs`: `lane_interpolator()` + canonical `ap_bases`
computed once in `prove_combined_v3`, passed as `&[Vec<Fr>]` into
`prove_rep`. No RNG consumption changed (hoisted values are pure
functions of program/params), so determinism and proof bytes are
preserved by construction. No new dependency, no threads.

Tests: new `tests/v3_p11_perf.rs` —
`precomputed_lane_bases_match_inline_recomputation` (hoisted ==
inline) and `hoisted_prove_still_verifies_and_stays_deterministic`
(same seed -> same bytes + verifies). Existing suite covers the rest.

## P11.2 measurements (same scenario/machine/build, release)

| Set | Prove before | Prove after | Δ | Verify | Bytes | Roundtrip |
|---:|---:|---:|---:|---|---|---|
| 4 | 3903.0 | 3769.4 | -133.6 (-3.4%) | ~245/241 | 180474 | ok |
| 8 | 4465.9 | 4244.8 | -221.1 (-5.0%) | ~269/263 | 191994 | ok |
| 16 | 4960.1 | 4853.2 | -106.9 (-2.2%) | ~276/282 | 203514 | ok |
| 32 | 5447.4 | 5296.9 | -150.5 (-2.8%) | ~301/301 | 215034 | ok |

Full suite: `98 lib + 2 p11 + 9 prototype = 109` pass.
Build: same release profile; still single-threaded.

## Review / limitations / stop condition

Gain is small (`~100-220ms`, `2-5%`), matching the predicted
`F1+F3 ≈ 180ms` saving for the second rep — reuse alone cannot move
the needle because the dominant `B/F4/C` scale with `N` and circuit
size. Proof bytes and verification are unchanged (no regression).

Per the phase rule, stopping here before any second category.
The remaining headroom (`B` share evals, `F4` sparse-linear, `C`
hint evals, `D` leaf hashing) is independent per pack/party and
parallelizable with `std::thread::scope`, but that changes RNG
consumption ordering and needs domain-separated per-task randomness
to keep `deterministic_under_seeded_rng` byte-identical — a bigger,
more invasive change requiring your review first. No `τ`/parameter,
circuit, `V2`, GGM/Limbo/NTT/GPU, or security-claim change was made.

## P11.4 baseline (P11.3 state, no code change yet)

HEAD: `97a78f1` (P11.3 record). Tree clean.
Post-P11.2 release benchmark, same machine/build (`i7-13620H`,
`rustc 1.98.1`, release `LTO`), single-threaded:

| Set | Prove (ms) | Verify1/2 (ms) | Bytes | Roundtrip |
|---:|---:|---|---|---|
| 4 | 3769.4 | 245.1 / 241.2 | 180474 | ok |
| 8 | 4244.8 | 268.8 / 263.1 | 191994 | ok |
| 16 | 4853.2 | 276.0 / 281.6 | 203514 | ok |
| 32 | 5296.9 | 301.1 / 300.6 | 215034 | ok |

Full suite: `98 lib + 2 p11 + 9 prototype = 109` pass.
Thread count: 1 (no threads in prover path).

## P11.4 design (recorded before implementing)

Target: `B` share generation only (`1586ms`, `~60%`/rep at 32-member).
One hot path; `F4/C/D` untouched until this is measured.

Method: sequential pre-generation, parallel pure math.
`prove_rep` first samples all share randomness sequentially from the
caller RNG in the exact pre-existing order (witness `r`, then mask
secrets + `r`), then evaluates `share()` for all jobs with
`std::thread::scope`, collecting outputs by job index. Workers never
touch the RNG.

Randomness / domain separation: each job `i` owns the samples drawn
for it in order — i.e. separation by stable job index over the
pre-existing stream, fresh per `prove_rep` call (hence per
repetition). No stream is shared concurrently or reused across tasks
or reps. Assumption: `share()` is a pure function of
`(secret, randomness)`; scheduling therefore cannot affect outputs.
Expected result: byte-identical proofs for the same input and seed.

stdlib vs dependency: `std::thread::scope` (stable, no new
dependency) with manual chunking is ~20 lines and sufficient for one
hot path. `rayon` would give `par_iter` ergonomics but adds a
dependency and version lock to an offline thesis build for no
measured need yet. Revisit only if manual chunking proves
error-prone or a second hot path needs join-heavy scheduling.

Acceptance: unit sequential-vs-parallel equality over thread counts
`1,2,3,4,7,16` and two back-to-back runs; existing determinism +
verify + tamper tests; benchmark byte sizes unchanged
(`180474/191994/203514/215034`).

## P11.4 results (share-generation parallelism only)

Implementation (`src/v3/prover.rs`): `P11.4.1` pre-generates share
randomness sequentially (identical order/values), then evaluates
`share()` for witness+mask jobs with `std::thread::scope`
(`share_worker_count` = `available_parallelism`, capped by jobs).
No other stage parallelized; `F4/C/D` untouched.

Release benchmark, same machine/build/threads (`nproc=16`,
workers ≤ 16):

| Set | Prove before | Prove after | Speedup | Verify1/2 | Bytes | Roundtrip |
|---:|---:|---:|---:|---|---|---|
| 4 | 3769.4 | 1957.2 | 1.93x | 244.0 / 238.0 | 180474 | ok |
| 8 | 4244.8 | 2137.6 | 1.99x | 257.2 / 256.2 | 191994 | ok |
| 16 | 4853.2 | 2400.8 | 2.02x | 280.9 / 281.4 | 203514 | ok |
| 32 | 5296.9 | 2618.4 | 2.02x | 297.2 / 302.7 | 215034 | ok |

Full suite: `101 lib (incl. 3 new parallel-equivalence) + 2 p11 +
9 prototype = 112` pass, incl. `deterministic_under_seeded_rng`,
`tampered_delta_u1_rejects`, all tamper/negative tests.
Proof bytes identical to baseline at every set size; verification
times unchanged (verifier untouched).

Review: `~2x` prove speedup from one hot path, no byte/behavior
change. `F4` sparse-linear (`540ms`/rep) is the next measured
candidate but is left for a separate step per the one-path rule —
it touches challenge-dependent values and needs its own equivalence
analysis. No `τ`/parameter, circuit, `V2`, GGM/Limbo/NTT/GPU, or
security-claim change.

## P11.5 baseline (P11.4 state, re-profiled, no code change yet)

HEAD: `418a3f6` (P11.4.2 record). Tree clean.
Same release benchmark, same machine/build (`i7-13620H`,
`rustc 1.98.1`, release `LTO`), rerun 2026-10-27:

| Set | Prove (ms) | Verify1/2 (ms) | Bytes | Roundtrip |
|---:|---:|---|---|---|
| 4 | 2228.5 | 310.9 / 322.3 | 180474 | ok |
| 8 | 2587.2 | 362.1 / 347.1 | 191994 | ok |
| 16 | 2406.7 | 276.2 / 273.0 | 203514 | ok |
| 32 | 2645.2 | 318.0 / 300.1 | 215034 | ok |

Note: shared dev machine — this rerun is uniformly slower than the
P11.4.2 sweep (`1957/2138/2401/2618`) including on verify-only times,
so compare P11.5 changes against this rerun, back-to-back where
possible. Bytes identical; suite `112` pass assumed (rerun in P11.5.2).

Re-profile (`v3_profile`, 32-member; `B` is the sequential reference
cost, already parallel in the prover since P11.4):

| Section | ms |
|---|---:|
| B share reference (sequential) | 1576.3 |
| C hints | 240.2 |
| D leaf commit / D2 root / E paths | 30.7 / 1.4 / 38.1 |
| F1 interp / F3 bases (hoisted since P11.2) | 72.3 / 87.8 |
| F2 quad | 0.3 |
| F4 sparse linear (`269 x m2=3642`) | 544.8 |
| G/G2 interp | 16.5 / 9.1 |
| H full prove `tau=2` | 2660.6, `215034 B` |

## P11.5 results (F4 parallelism only)

Implementation (`src/v3/prover.rs`, `P11.5.1`): new
`broadcast_alpha_prime_all` evaluates the per-canonical-party
`eval_linear_jb_sparse` + `gp` accumulation with
`std::thread::scope`, ordered join, `Result` propagation in index
order. `gp` challenges and `jvp` masks are sampled/derived
sequentially beforehand; workers touch neither RNG nor transcript.
`share_worker_count` generalized to `worker_count` (shared by both
parallel stages). No other stage parallelized.

Tests: 2 new unit tests (`alpha_prime_parallel_matches_sequential`
over thread counts `1,2,3,5,16` x two back-to-back runs against a
directly-written sequential reference, plus empty). Verifier-visible
path (`alpha_p` feeds `hB`) covered by existing round-trip,
`tampered_broadcast_shares_reject`, determinism, and tamper tests.

Release benchmark, same machine/build, `nproc=16` (two sweeps;
shared-machine variance visible on verify-only times, verifier
untouched):

| Set | P11.5 baseline | P11.5 sweep 1 | P11.5 sweep 2 | Bytes | Roundtrip |
|---:|---:|---:|---:|---|---|
| 4 | 2228.5 | 1634.0 (1.36x) | 1699.9 (1.31x) | 180474 | ok |
| 8 | 2587.2 | 1691.2 (1.53x) | 1601.4 (1.62x) | 191994 | ok |
| 16 | 2406.7 | 1937.0 (1.24x) | 1607.6 (1.50x) | 203514 | ok |
| 32 | 2645.2 | 1837.0 (1.44x) | 1902.4 (1.39x) | 215034 | ok |

Speedups vs P11.5 baseline rerun; cumulative vs pre-P11.4
(`3903/4466/4960/5447`): `~2.3x/2.8x/3.1x/2.9x` (32-member
`5447 -> ~1900ms`). Proof bytes identical at every size; verify
times within machine variance; roundtrip `ok`.

Full suite: `103 lib (incl. 2 new F4-equivalence) + 2 p11 +
9 prototype = 114` pass.

Review: `~1.3-1.6x` further prove speedup from the second hot path,
no byte/behavior change. Remaining sequential prover work is `C`
hint evals (`~240ms`/rep) plus hashing/openings — left for a future
single-path step, not attempted here. No `τ`/parameter, circuit,
`V2`, GGM/Limbo/NTT/GPU, or security-claim change.
