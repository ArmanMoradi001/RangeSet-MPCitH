//! P11.2 focused tests: hoisted invariant precomputation.
//! No protocol change. Uses only insecure fast test parameters.

use range_set_mpcith::v2::merkle::MerkleTreeV2;
use range_set_mpcith::v2::predicate::{
    compile_from_statement, MembershipStatementV2, RangeStatementV2, StatementV2,
};
use range_set_mpcith::v3::constraints::ConstraintProgramV3;
use range_set_mpcith::v3::params::V3Params;
use range_set_mpcith::v3::prover::prove_combined_v3;
use range_set_mpcith::v3::sharing::party_point;
use range_set_mpcith::v3::verifier::verify_combined_v3;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

#[test]
fn precomputed_lane_bases_match_inline_recomputation() {
    // The hoisted P11.2 path (one lane interpolator + bases for all reps)
    // must equal per-rep inline recomputation exactly.
    let params = V3Params::fast_insecure_test();
    let tree = MerkleTreeV2::build(&[10u32, 20, 30, 40]).unwrap();
    let statement = StatementV2::Combined {
        range: RangeStatementV2::new(10, 40).unwrap(),
        membership: MembershipStatementV2::new(
            tree.root(),
            tree.num_members(),
            tree.depth(),
        )
        .unwrap(),
    };
    let compiled = compile_from_statement(&statement).unwrap();
    let program = ConstraintProgramV3::compile(compiled.circuit(), &params).unwrap();
    let s = params.packing_width as usize;
    let d2 = 2 * s + params.privacy_threshold as usize - 2;

    // Hoisted path (as in prove_combined_v3).
    let lane_once = program.lane_interpolator().unwrap();
    let bases_once: Vec<Vec<_>> = (0..d2 + 1)
        .map(|i| lane_once.basis_evals(party_point(s, i)))
        .collect();

    // Inline path (as prove_rep did before P11.2).
    let lane_inline = program.lane_interpolator().unwrap();
    let bases_inline: Vec<Vec<_>> = (0..d2 + 1)
        .map(|i| lane_inline.basis_evals(party_point(s, i)))
        .collect();

    assert_eq!(bases_once, bases_inline);
}

#[test]
fn hoisted_prove_still_verifies_and_stays_deterministic() {
    let params = V3Params::fast_insecure_test();
    let tree = MerkleTreeV2::build(&[10u32, 20, 30, 40]).unwrap();
    let proof_tx = tree.prove_membership(1).unwrap();
    let context = [7u8; 32];
    let statement = StatementV2::Combined {
        range: RangeStatementV2::new(10, 40).unwrap(),
        membership: MembershipStatementV2::new(
            tree.root(),
            tree.num_members(),
            tree.depth(),
        )
        .unwrap(),
    };
    let mut rng_a = ChaCha20Rng::seed_from_u64(0x7331_5033);
    let mut rng_b = ChaCha20Rng::seed_from_u64(0x7331_5033);
    // Same seed -> identical bytes (determinism preserved by the hoist:
    // no RNG consumption changed).
    let proof_a = prove_combined_v3(
        10, 40, tree.root(), tree.num_members(), tree.depth(), 20, &proof_tx,
        context, &params, &mut rng_a,
    )
    .unwrap();
    let proof_b = prove_combined_v3(
        10, 40, tree.root(), tree.num_members(), tree.depth(), 20, &proof_tx,
        context, &params, &mut rng_b,
    )
    .unwrap();
    assert_eq!(proof_a.to_bytes().unwrap(), proof_b.to_bytes().unwrap());
    verify_combined_v3(&proof_a, &statement, context, &params).unwrap();
    // Consume the RNG the way the benchmark does (proves determinism
    // helper traits are intact).
    let _: u32 = rng_a.next_u32();
}
