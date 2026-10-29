//! A1 — predicate and witness substitution attempts (adversarial campaign).
//!
//! Scope notes (see `attack.md` and `docs/adversarial-A0-baseline.md`):
//! - Small insecure preset only (`V3Params::fast_insecure_test`), seeded RNG.
//! - Prover/witness-builder refusals are labeled as such; they are NOT
//!   verifier soundness results.
//! - Statement-binding checks use one honest proof against altered public
//!   statements and ARE verifier checks.
//! - No second prover implementation exists here; a true malicious-proof
//!   construction outside the public API was not performed (see report).

use range_set_mpcith::v2::merkle::MerkleTreeV2;
use range_set_mpcith::v2::predicate::{
    MembershipStatementV2, RangeStatementV2, StatementV2,
};
use range_set_mpcith::v3::params::V3Params;
use range_set_mpcith::v3::proof::V3Proof;
use range_set_mpcith::v3::prover::prove_combined_v3;
use range_set_mpcith::v3::verifier::verify_combined_v3;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(0xA1A1_A1A1)
}

fn small_tree() -> MerkleTreeV2 {
    MerkleTreeV2::build(&[10u32, 20, 30, 40]).unwrap()
}

fn combined_statement(lo: u32, hi: u32, tree: &MerkleTreeV2) -> StatementV2 {
    StatementV2::Combined {
        range: RangeStatementV2::new(lo, hi).unwrap(),
        membership: MembershipStatementV2::new(
            tree.root(),
            tree.num_members(),
            tree.depth(),
        )
        .unwrap(),
    }
}

#[test]
fn a1_boundary_witnesses_verify() {
    // Honest controls: the private value sits exactly on a public bound
    // and is a real set member in both cases (value 20, index 1).
    let tree = small_tree();
    let params = V3Params::fast_insecure_test();
    let proof_tx = tree.prove_membership(1).unwrap();
    let context = [7u8; 32];

    // Lower bound: range [20, 40], value == lo.
    let lo_proof = prove_combined_v3(
        20, 40, tree.root(), tree.num_members(), tree.depth(), 20, &proof_tx,
        context, &params, &mut rng(),
    )
    .expect("lo-boundary honest proof must construct");
    let lo_stmt = combined_statement(20, 40, &tree);
    verify_combined_v3(&lo_proof, &lo_stmt, context, &params)
        .expect("lo-boundary honest proof must verify");
    assert_eq!(
        V3Proof::from_bytes(&lo_proof.to_bytes().unwrap()).unwrap(),
        lo_proof
    );

    // Upper bound: range [10, 20], value == hi.
    let hi_proof = prove_combined_v3(
        10, 20, tree.root(), tree.num_members(), tree.depth(), 20, &proof_tx,
        context, &params, &mut rng(),
    )
    .expect("hi-boundary honest proof must construct");
    let hi_stmt = combined_statement(10, 20, &tree);
    verify_combined_v3(&hi_proof, &hi_stmt, context, &params)
        .expect("hi-boundary honest proof must verify");
    assert_eq!(
        V3Proof::from_bytes(&hi_proof.to_bytes().unwrap()).unwrap(),
        hi_proof
    );
}

#[test]
fn a1_out_of_range_builder_refusals() {
    // Prover/witness-builder refusals (NOT verifier results): in-range
    // set members moved outside the public range. The existing suite
    // covers value 20 against [21, 40]; these are distinct combos.
    let tree = small_tree();
    let params = V3Params::fast_insecure_test();
    let context = [7u8; 32];

    // Member 10 below lo.
    let proof_idx0 = tree.prove_membership(0).unwrap();
    assert!(
        prove_combined_v3(
            11, 40, tree.root(), tree.num_members(), tree.depth(), 10,
            &proof_idx0, context, &params, &mut rng(),
        )
        .is_err(),
        "below-range member must be refused by the witness builder"
    );

    // Member 40 above hi.
    let proof_idx3 = tree.prove_membership(3).unwrap();
    assert!(
        prove_combined_v3(
            10, 39, tree.root(), tree.num_members(), tree.depth(), 40,
            &proof_idx3, context, &params, &mut rng(),
        )
        .is_err(),
        "above-range member must be refused by the witness builder"
    );

    // Member 20 above a lowered hi.
    let proof_idx1 = tree.prove_membership(1).unwrap();
    assert!(
        prove_combined_v3(
            10, 19, tree.root(), tree.num_members(), tree.depth(), 20,
            &proof_idx1, context, &params, &mut rng(),
        )
        .is_err(),
        "above-range member must be refused by the witness builder"
    );
}

#[test]
fn a1_mismatched_membership_builder_refusals() {
    // Prover/witness-builder refusals for private witness mismatches.
    // (The existing suite covers nonmember 99 with the index-1 path;
    // that case is referenced, not duplicated. The membership index is
    // a private witness input, so none of these are verifier tests.)
    let tree = small_tree();
    let params = V3Params::fast_insecure_test();
    let context = [7u8; 32];

    // Member value 30 presented with member 20's proof (index 1).
    let proof_idx1 = tree.prove_membership(1).unwrap();
    assert!(
        prove_combined_v3(
            10, 40, tree.root(), tree.num_members(), tree.depth(), 30,
            &proof_idx1, context, &params, &mut rng(),
        )
        .is_err(),
        "cross-member proof swap must be refused by the witness builder"
    );

    // Hand-edited path: valid index-1 proof with leaf_index rewritten to 0,
    // so the index no longer matches the sibling path.
    let mut bad_path = tree.prove_membership(1).unwrap();
    bad_path.leaf_index = 0;
    assert!(
        prove_combined_v3(
            10, 40, tree.root(), tree.num_members(), tree.depth(), 20,
            &bad_path, context, &params, &mut rng(),
        )
        .is_err(),
        "index/path inconsistency must be refused by the witness builder"
    );
}

#[test]
fn a1_altered_statement_binding_rejects() {
    // Statement-binding checks (verifier-side): one honest proof,
    // verified against altered PUBLIC statements. The membership index
    // is not a public statement field, so no altered-index claim is made.
    // (Wrong-root replay is existing coverage; referenced, not duplicated.)
    let tree = small_tree();
    let params = V3Params::fast_insecure_test();
    let proof_tx = tree.prove_membership(1).unwrap();
    let context = [7u8; 32];
    let proof = prove_combined_v3(
        10, 40, tree.root(), tree.num_members(), tree.depth(), 20, &proof_tx,
        context, &params, &mut rng(),
    )
    .unwrap();
    let honest = combined_statement(10, 40, &tree);
    verify_combined_v3(&proof, &honest, context, &params).unwrap();

    // Altered range bounds.
    assert!(
        verify_combined_v3(
            &proof, &combined_statement(11, 40, &tree), context, &params
        )
        .is_err(),
        "tightened lo must reject"
    );
    assert!(
        verify_combined_v3(
            &proof, &combined_statement(10, 39, &tree), context, &params
        )
        .is_err(),
        "tightened hi must reject"
    );
    assert!(
        verify_combined_v3(
            &proof, &combined_statement(1, 1000, &tree), context, &params
        )
        .is_err(),
        "widened range must reject (circuit hash binds the statement)"
    );

    // Altered member count (constructible: depth 2 is canonical for 3).
    let altered_count = StatementV2::Combined {
        range: RangeStatementV2::new(10, 40).unwrap(),
        membership: MembershipStatementV2::new(tree.root(), 3, 2).unwrap(),
    };
    assert!(
        verify_combined_v3(&proof, &altered_count, context, &params).is_err(),
        "altered member count must reject"
    );

    // Altered depth is not constructible: the statement constructor
    // rejects non-canonical depth, so no verifier check is reached.
    // Recorded as a constructor refusal, not a verifier rejection.
    assert!(MembershipStatementV2::new(tree.root(), 4, 3).is_err());
    assert!(MembershipStatementV2::new(tree.root(), 4, 1).is_err());
}
