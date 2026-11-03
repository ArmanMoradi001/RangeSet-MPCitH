//! A4 — correction transcript ordering (adversarial campaign).
//!
//! Scope notes (see `attack.md`):
//! - Reused existing coverage is referenced, not duplicated:
//!   `delta_u1` mutation (`tampered_delta_u1_rejects`), broadcast share
//!   mutation both repetitions (`tampered_broadcast_shares_reject`), DECS
//!   response and broadcast-hash mutation (`tampered_proof_bytes_reject`).
//!   Those already mutate every verifier-visible algebraic value, so no
//!   additional field-mutation test is added here.
//! - This file adds exactly one test: a transcript-order regression on the
//!   existing transcript implementation showing the committed correction
//!   is bound before the batching challenges are derived. This checks the
//!   implemented order only; it is not a grinding experiment and proves
//!   nothing about adaptive algebraic attacks.
//! - Small insecure-shape inputs, fully deterministic (no RNG).

use ark_bn254::Fr;
use range_set_mpcith::v3::transcript::{
    hash_fr_vecs, TranscriptV3, V3_HASH_TAG_DELTA, V3_HASH_TAG_PXI,
    V3_TR_TAG_BATCH, V3_TR_TAG_GAMMA,
};

/// Drive the transcript through h1 -> Gamma -> h1' -> hDelta ->
/// batching, returning (Gamma, batch0, batch1) challenges.
fn drive(delta: Fr) -> (Vec<Fr>, Vec<Fr>, Vec<Fr>) {
    let mut tr = TranscriptV3::new(
        32, 3, 8, 2, 1, 1, 10, 40, &[7u8; 32], 4, 2, &[7u8; 32],
        &[11u8; 32], &[13u8; 32], 0,
    );
    tr.absorb_hash(b"h1", &[42u8; 32]);
    let gamma = tr.sample_frs(V3_TR_TAG_GAMMA, 0, 8);
    tr.absorb_hash(b"h1p", &hash_fr_vecs(V3_HASH_TAG_PXI, &[vec![Fr::from(1u64)]]));
    // hDelta commits the correction vector, exactly as the prover and
    // verifier do before any batching challenge is sampled.
    let h_delta = hash_fr_vecs(V3_HASH_TAG_DELTA, &[vec![delta]]);
    tr.absorb_hash(b"hdelta", &h_delta);
    let batch0 = tr.sample_frs(V3_TR_TAG_BATCH, 0, 4);
    let batch1 = tr.sample_frs(V3_TR_TAG_BATCH, 1, 4);
    (gamma, batch0, batch1)
}

#[test]
fn a4_correction_bound_before_batching() {
    // Identical committed correction -> identical challenges (control).
    let base = drive(Fr::from(1u64));
    assert_eq!(base, drive(Fr::from(1u64)));

    // Changed correction only: Gamma (derived before hDelta) is unchanged,
    // while the batching challenges (derived after hDelta) change.
    let altered = drive(Fr::from(2u64));
    assert_eq!(
        base.0, altered.0,
        "Gamma must not depend on the later-committed correction"
    );
    assert_ne!(
        (base.1.clone(), base.2.clone()),
        (altered.1.clone(), altered.2.clone()),
        "batching challenges must depend on the committed correction"
    );
}
