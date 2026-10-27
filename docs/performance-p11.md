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
