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
