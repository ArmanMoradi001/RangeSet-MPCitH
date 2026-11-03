# V3 Adversarial Campaign — A0 baseline (no code change)

Plan: `attack.md` (untracked, preserved as-is). No attack tests exist yet;
nothing in `src/`, `tests/`, `examples/`, `benchmark.md`, or docs was modified
for A0.

## Worktree and commit

- HEAD: `b156f47` (“bench: re-run three fresh sweeps and update benchmark.md table”).
- `git status`: clean except untracked `attack.md` and `thesis_chapter/`
  (`thesis_chapter/protocol_design.txt`, 50338 bytes) — both preserved,
  neither committed nor modified.
- Do not push (per campaign rules).

## Commands run

1. `cargo test --offline`
2. `cargo run --offline --release --example v3_benchmark` (twice)

## Existing test inventory (all passing, no new tests in A0)

- `cargo test --offline`: `105` lib unit + `2` (`tests/v3_p11_perf.rs`,
  determinism/precompute only) + `9` (`tests/v3_prototype.rs`) = `116`
  passed, `0` failed.
- `tests/v3_prototype.rs` (9): `honest_combined_proof_verifies_and_round_trips`,
  `deterministic_under_seeded_rng`,
  `honest_two_repetition_proof_verifies_and_round_trips`,
  `cloned_repetition_slot_is_rejected`, `false_statements_cannot_prove`,
  `wrong_expected_statement_context_or_params_reject`,
  `tampered_proof_bytes_reject`, `tampered_broadcast_shares_reject`,
  `tampered_delta_u1_rejects`.
- Relevant existing attack-adjacent coverage (per `attack.md` §2, not
  duplicated here): commit/path tests in `src/v3/commit.rs`, codec tests
  in `src/v3/proof.rs`, predicate/Merkle unit failure tests in `src/v2/`.

## Honest release benchmark (A0 reference)

Same scenario as `benchmark.md`: `N=8192,ℓ=30,s=120,η=6,ρ=1,τ=2`,
`range=[1,1000] value=120 member_index=2`, seeded RNG, in-memory
`V3Proof` verified twice. Machine: i7-13620H (`nproc=16`), 14 GiB RAM
(~6 GiB available during run), Linux 7.0.0-38-generic, `rustc 1.98.1`,
release `opt-level=3` + LTO.

| Set | Depth | Prove s1 (ms) | Prove s2 (ms) | Verify s1 (ms x2) | Verify s2 (ms x2) | Bytes | Roundtrip |
|---:|---:|---:|---:|---|---|---|---|
| 4 | 2 | 2300.8 | 2155.0 | 436.9 / 436.1 | 487.8 / 375.6 | 180474 | ok |
| 8 | 3 | 2345.1 | 2273.6 | 465.9 / 492.2 | 413.1 / 400.6 | 191994 | ok |
| 16 | 4 | 2669.5 | 2328.9 | 516.1 / 501.9 | 450.0 / 438.1 | 203514 | ok |
| 32 | 5 | 2788.7 | 2878.5 | 559.7 / 553.4 | 578.1 / 509.2 | 215034 | ok |

Note: this machine was loaded during A0 (all timings, including the
untouched single-threaded verifier, run roughly 1.5–1.9x above the
`benchmark.md` post-P11 rows depending on case — about 1.9x on the
32-member proving time — versus prove `~1.3–1.5 s`, verify
`~0.24–0.32 s`). Proof sizes are identical to every prior run, and
all eight generated proofs verified twice with codec round-trip `ok`.
The slowdown is shared-machine variance, not a code regression:
verifier code is unchanged since long before P11 yet verify times
rose proportionally. `benchmark.md` is left intact per campaign scope.

## Proposed A1 (for review; not started)

Per `attack.md` §4-A1, add only missing deterministic predicate/witness
substitution tests with insecure small params, labeling prover-API
refusal separately from verifier rejection of an altered expected
statement: (a) honest lower/upper boundary witnesses (`value=lo`,
`value=hi`) as controls; (b) below-range / above-range values via the
public prover API (expect builder refusal); (c) nonmember value with a
mismatched-but-valid path (expect builder refusal); (d) one valid proof
verified against altered expected statements (range edge shift,
wrong member index path, inconsistent range+membership inputs —
expect verifier rejection). If a true malicious-proof construction
needs a second protocol implementation, record it as not performed
instead of building it. No security claim will be made.
