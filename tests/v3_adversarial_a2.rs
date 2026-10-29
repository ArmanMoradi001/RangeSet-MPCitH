//! A2 — transcript replay and repetition binding (adversarial campaign).
//!
//! Scope notes (see `attack.md`):
//! - Reused existing coverage is referenced, not duplicated:
//!   wrong context/parameters (`wrong_expected_statement_context_or_params_reject`),
//!   cloned repetition (`cloned_repetition_slot_is_rejected`), `delta_u1`
//!   tampering (`tampered_delta_u1_rejects`).
//! - This file adds only (1) a repetition-slot *swap* (distinct from the
//!   existing clone-slot case) and (2) a direct transcript-binding check.
//! - Verifier rejection is a verifier result; a changed challenge is a
//!   transcript-binding observation. Neither establishes security, and no
//!   grinding/search claim is made.
//! - Small insecure preset only, deterministic inputs.

use range_set_mpcith::v2::merkle::MerkleTreeV2;
use range_set_mpcith::v2::predicate::{
    MembershipStatementV2, RangeStatementV2, StatementV2,
};
use range_set_mpcith::v3::params::V3Params;
use range_set_mpcith::v3::prover::prove_combined_v3;
use range_set_mpcith::v3::transcript::{TranscriptV3, V3_TR_TAG_GAMMA};
use range_set_mpcith::v3::verifier::verify_combined_v3;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(0xA2A2_A2A2)
}

fn small_tree() -> MerkleTreeV2 {
    MerkleTreeV2::build(&[10u32, 20, 30, 40]).unwrap()
}

fn tau2_small_params() -> V3Params {
    V3Params::new(32, 3, 8, 2, 1, 2)
}

#[test]
fn a2_repetition_slot_swap_rejects() {
    // Honest control: a genuine two-repetition proof verifies.
    // Attack attempt: the two repetition payloads are swapped, so each
    // repetition is checked against the other repetition's transcript
    // position (`rep_index` is bound in the transcript prefix).
    let tree = small_tree();
    let params = tau2_small_params();
    let proof_tx = tree.prove_membership(1).unwrap();
    let context = [7u8; 32];
    let proof = prove_combined_v3(
        10, 40, tree.root(), tree.num_members(), tree.depth(), 20, &proof_tx,
        context, &params, &mut rng(),
    )
    .unwrap();
    assert_eq!(proof.reps.len(), 2);
    let statement = StatementV2::Combined {
        range: RangeStatementV2::new(10, 40).unwrap(),
        membership: MembershipStatementV2::new(
            tree.root(),
            tree.num_members(),
            tree.depth(),
        )
        .unwrap(),
    };
    verify_combined_v3(&proof, &statement, context, &params)
        .expect("honest tau=2 proof must verify");

    let mut swapped = proof.clone();
    swapped.reps.swap(0, 1);
    assert!(
        verify_combined_v3(&swapped, &statement, context, &params).is_err(),
        "swapped repetition payloads must be rejected"
    );
}

#[test]
fn a2_transcript_binding_changes_challenge() {
    // Direct binding observation on the existing transcript
    // implementation: changing one bound input changes the derived
    // challenge. This is a determinism/binding regression, not evidence
    // about grinding feasibility (no search is performed).
    let mk = |rep: u32, context: [u8; 32]| {
        let mut tr = TranscriptV3::new(
            32, 3, 8, 2, 1, 1, 10, 40, &[7u8; 32], 4, 2, &context,
            &[11u8; 32], &[13u8; 32], rep,
        );
        tr.absorb_hash(b"h1", &[42u8; 32]);
        tr.sample_frs(V3_TR_TAG_GAMMA, 0, 8)
    };

    // Same inputs -> same challenge (control).
    assert_eq!(mk(0, [7u8; 32]), mk(0, [7u8; 32]));

    // Changed repetition index -> changed challenge.
    assert_ne!(
        mk(0, [7u8; 32]),
        mk(1, [7u8; 32]),
        "repetition index must affect the derived challenge"
    );

    // Changed context -> changed challenge.
    assert_ne!(
        mk(0, [7u8; 32]),
        mk(0, [8u8; 32]),
        "context must affect the derived challenge"
    );
}
