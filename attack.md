# V3 Adversarial Test Campaign Roadmap

**Status: plan complete — results recorded.** The A0–A4 campaign described
below has been executed and committed: see `benchmark.md` §"Adversarial
test campaign (not a security proof)" and `docs/adversarial-A0-baseline.md`
through `docs/adversarial-A4.md` (`105` lib + `4` A1 + `2` A2 + `4` A3 +
`1` A4 + `2` p11 + `9` prototype = `127` passed, `0` failed). This file
remains the roadmap/plan; it contains no attack results itself and makes
no security claim.

## 1. Goal and reporting standard

Run a small, reproducible adversarial robustness campaign against the current V3 prototype. The objective is to document how the implementation responds to four specific classes of attempted forgery, replay, commitment tampering, and algebraic manipulation. These experiments complement ordinary correctness tests; they do not establish soundness, zero knowledge, proof of knowledge, a security level, or deployment readiness.

Report only what each experiment actually tested. In particular, an honest prover refusing an invalid witness tests the witness-building API; it does **not** show that the verifier rejects every malicious proof for a false statement. A mutated honest proof is a tampering test; it is not a general forgery attempt. Do not describe passing tests as “the protocol is secure” or “the protocol withstands attacks.”

Use deterministic seeds and small, explicitly insecure test parameters for attack tests. Keep the existing release benchmark as the performance and honest-operation reference. Never infer a negligible probability from a finite number of failed attempts.

## 2. Current implementation and coverage to preserve

The target is the current V3 implementation: TCitH-MT over the ΠLigero-style constraint program, with BN254 `Fr`, BLAKE3 commitments/transcript, Poseidon2-based membership constraints, and proof-format version 4. The verifier derives challenges from the statement-bound transcript. The `delta_u1` vector is hashed into `hDelta` before batching challenges. The V3 prover and verifier are under `src/v3/`; V2-derived circuit, field, Poseidon2, predicate, and set-Merkle support is under `src/v2/`.

Existing coverage already includes:

- `tests/v3_prototype.rs`: honest proof verification and codec round-trip, deterministic seeded proving, two repetitions, cloned-repetition rejection, prover rejection of out-of-range/nonmember inputs, wrong root/context/parameters, sampled byte mutations, opened-share/DECS/root/broadcast tampering, broadcast-share tampering, and `delta_u1` tampering.
- `src/v3/commit.rs` tests: Merkle paths for even and odd leaf counts, wrong leaf/index/side/root, truncated paths, and odd-node duplicate-sibling validation.
- `src/v3/proof.rs` tests: wrong magic/version, prior proof-version rejection, trailing bytes, noncanonical field elements, and malformed side bits.
- `src/v2/predicate.rs` and `src/v2/merkle.rs` tests: circuit-level range and membership failures, invalid paths, roots, counts, depths, and indices.

Before adding tests, inspect the current test names and run the existing suite. Add only meaningful gaps; do not duplicate these cases under new names to inflate the attack count. Keep `benchmark.md`'s existing honest performance results intact.

## 3. Scope limits

- Do not change the protocol, transcript, proof format, parameters, circuit, V2 code, or security documentation as a side effect of the campaign.
- Do not add dependencies, a general fuzzing framework, a custom cryptographic model, a network service, or a benchmark framework. Use focused deterministic Rust tests and existing helpers.
- Do not add production attack hooks or weaken verifier checks. A narrowly scoped `#[cfg(test)]` helper is acceptable only when necessary and when it does not duplicate the prover/verifier implementation.
- Do not tune parameters or label any preset secure. Attack tests must state which parameters they use; the small test preset is intentionally insecure.
- If a test appears to demonstrate acceptance of a false statement, stop at that phase gate. Preserve the smallest reproducible failing case, commit it, record it honestly, and report the finding. Do not silently patch it or report the campaign as passed; any repair should be a separately reviewed step.

## 4. Attack scenarios

### A1 — Predicate and witness substitution

Attempt to prove/use a value below or above the public range, a nonmember value, a mismatched Merkle path for another value, and a statement whose range and membership data refer to inconsistent inputs. Include valid lower- and upper-bound witnesses as honest controls.

Use the public prover API and verifier API where possible. Check both (a) whether the checked witness builder rejects invalid inputs and (b) whether an existing valid proof is rejected when verified against a false or altered expected statement. Keep these outcomes separately labeled.

If a verifier-side false-witness experiment requires constructing a malicious proof outside the public prover API, first assess whether a minimal test-only path can reuse existing internals without copying the prover. If it would require a broad refactor or a second implementation of the protocol, do not build it in this campaign. State that the experiment was not performed; do not present prover-side refusal as a verifier soundness result.

**Expected observation:** invalid witness construction fails, altered expected statements reject, and valid boundary witnesses verify. Any valid-looking proof for a false relation is a stop-and-report finding.

### A2 — Transcript replay and context substitution

Attempt to reuse a valid proof under a changed context, range, membership root/count/depth, parameter set, suite/format version, or repetition position. Include a cloned or swapped repetition payload and a changed `delta_u1` value. Reuse existing tests where they already cover the exact case; add only missing cases such as range-only statement alteration or rep-slot swapping if not covered.

For transcript inputs that can be exercised directly, check that changing one bound field changes the derived challenge. This is a deterministic binding regression, not evidence that grinding is infeasible. Do not conduct an unbounded search for a favorable challenge or claim a query-security estimate from a small search.

**Expected observation:** cross-context/statement/parameter replay and altered repetition payloads reject; transcript-binding checks show the selected changed field affects the challenge. Record any case already covered instead of duplicating it.

### A3 — Commitment, opening, and parser tampering

Starting from one honest proof, attempt targeted changes to an opened party index, share value, leaf randomness, Merkle sibling, sibling direction, path length, broadcast share, and DECS response. Include an odd-sized Merkle tree case so the lonely duplicated-node rule is exercised end-to-end where practical. Exercise truncated and trailing proof bytes, unsupported format version, noncanonical field encoding, invalid side-bit encoding, and oversized length prefixes using small inputs that fail quickly.

Use the existing parser and Merkle helpers. The objective is clean rejection without panic, hang, or excessive allocation for the selected malformed inputs. Do not turn this into a generic parser fuzzer or claim resistance to all denial-of-service attacks.

**Expected observation:** tampered commitments/openings fail verification; malformed encodings fail parsing or verification cleanly. Any panic, hang, excessive allocation, or accepted inconsistent opening is a finding and stops the campaign.

### A4 — Algebraic transcript and correction manipulation

Target the verifier-visible algebraic values: `delta_u1`, `broadcast_alpha`, `broadcast_alpha_prime`, and DECS responses. First preserve the existing `delta_u1` mutation regression. Add a focused check of the actual schedule: the correction vector is committed as `hDelta` before the batching challenge is derived, so changing the correction changes the transcript-derived challenge and the old response must not verify.

Also test a small set of structured mutations that attempt to make an invalid linear outcome, multiplication broadcast, or DECS response pass. Do not describe arbitrary field-element mutation as an adaptive algebraic forgery. A true adaptive-forgery experiment would need an adversary that respects the commitment/challenge order; do not fake this by directly editing challenge values or bypassing the verifier.

If reproducing the historical post-challenge `delta_u1` exploit is useful, keep the vulnerable ordering in a tiny isolated test model solely to demonstrate why the regression matters. It must not be reachable from production code and must be labeled as a model of the old schedule, not an attack on the current implementation.

**Expected observation:** the documented targeted mutations reject; the transcript-order regression confirms the correction is bound before batching. Any accepted false relation or bypass is a stop-and-report finding. Passing these cases does not prove the algebraic soundness theorem.

## 5. Agent workflow and commit gates

Implement one step at a time. At each step, inspect the latest commit and worktree first, preserve unrelated/untracked files (including `thesis_chapter/`), and do not push. Make one phase-numbered commit after each completed step; never make a gate commit that claims a failed or unperformed attack passed.

1. **A0 — inventory and honest baseline.** Re-run the existing tests and the documented release benchmark. Record current commit, command, parameters, environment, honest prove/verify results, proof bytes, round-trip status, and existing attack-test coverage. Commit the baseline/results update.
2. **A1 — predicate/witness substitution.** Add only missing deterministic tests; record which checks exercise the prover API versus the verifier. Run focused and full tests. Commit tests and accurate results.
3. **A2 — transcript replay/binding.** Add only missing replay, repetition, or challenge-binding tests. Run focused and full tests. Commit tests and results.
4. **A3 — commitment/opening/parser tampering.** Add only missing targeted malformed-input and end-to-end opening tests. Keep each input bounded. Run focused and full tests. Commit tests and results.
5. **A4 — algebraic manipulation.** Add the transcript-order regression and a small number of structured algebraic tampering tests, without changing protocol logic. Run focused and full tests. Commit tests and results.
6. **A5 — consolidated report.** Update `benchmark.md` with an explicitly separate section titled **“Adversarial test campaign (not a security proof)”**. Preserve the existing honest performance table and append: (i) fresh honest control outcomes from A0, (ii) one row per attack scenario with the attempted change, test location, observed outcome, and limitation, (iii) total passing/failing tests, and (iv) any attack that succeeded or scenario not implemented. Commit this report separately.

Use commit subjects such as `V3 A1: test predicate substitution attempts` and `V3 A5: record adversarial campaign results`. After each commit, summarize the changed files, tests run, observed outcomes, and next step. If interrupted, continue from the latest committed step; do not repeat or overwrite completed work.

## 6. Result table format for `benchmark.md`

| Scenario | Attempt | Honest control | Observed outcome | Test(s) | Limitation |
|---|---|---|---|---|---|
| A1 … | … | … | Rejected / Accepted / Not run | `path::test_name` | … |

Use **Accepted** to mean the verifier accepted the adversarial proof or malformed input. An accepted false proof is a failure, not a passing test. Use **Rejected** only when the stated verifier/parser actually rejected the specific attempt. Use **Not run** where implementation or tooling made the scenario infeasible within scope.

Report honest controls separately from attack outcomes: state the number of valid proofs generated, the parameter preset, verification and codec-round-trip outcomes, and performance only if measured. Keep attack-test results out of the existing proof-size/proving-time summary, except for a clear cross-reference to the new subsection.

## 7. Required final wording

The final report may say that the implementation rejected the listed, reproducible attempts under the specified test parameters. It must also state that finite tests do not establish cryptographic soundness, zero knowledge, proof of knowledge, 127-bit security, resistance to untested attacks, or production readiness. Preserve any vulnerability, failed test, or unperformed scenario plainly in the report.
