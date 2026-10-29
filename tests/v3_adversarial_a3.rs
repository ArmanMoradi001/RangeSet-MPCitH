//! A3 — commitment, opening, and parser tampering (adversarial campaign).
//!
//! Scope notes (see `attack.md`):
//! - Reused existing coverage is referenced, not duplicated: opened share
//!   *values*, DECS response *values*, commitment root, broadcast hash, and
//!   broadcast share *values* (`tampered_proof_bytes_reject`,
//!   `tampered_broadcast_shares_reject`); codec magic/version/trailing/
//!   noncanonical/side-bit cases (`src/v3/proof.rs` tests); odd-node and
//!   path-shape unit cases (`src/v3/commit.rs` tests).
//! - This file adds only structural/shape mutations, parser edge cases,
//!   and one odd-`N` end-to-end proof. Each mutation uses a fresh proof
//!   copy and expects clean verifier/parser rejection (no panic, no
//!   unbounded work). No fuzzer, dependencies, or protocol changes.
//! - Small insecure preset only, deterministic seeds.

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
    ChaCha20Rng::seed_from_u64(0xA3A3_A3A3)
}

fn small_tree() -> MerkleTreeV2 {
    MerkleTreeV2::build(&[10u32, 20, 30, 40]).unwrap()
}

fn honest_proof() -> (V3Proof, StatementV2, [u8; 32], V3Params) {
    let tree = small_tree();
    let params = V3Params::fast_insecure_test();
    let proof_tx = tree.prove_membership(1).unwrap();
    let context = [7u8; 32];
    let proof = prove_combined_v3(
        10, 40, tree.root(), tree.num_members(), tree.depth(), 20, &proof_tx,
        context, &params, &mut rng(),
    )
    .unwrap();
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
        .expect("honest control must verify");
    (proof, statement, context, params)
}

#[test]
fn a3_opening_tampering_rejects() {
    // Each subcase mutates one opening field of a fresh copy.
    // (Share *values* are existing coverage; shapes/identities are new.)
    let (proof, statement, context, params) = honest_proof();

    // Opened party index no longer matches the challenged opening set.
    let mut bad = proof.clone();
    let idx = bad.reps[0].opened[0].party_index;
    bad.reps[0].opened[0].party_index = idx.wrapping_add(1);
    assert!(
        verify_combined_v3(&bad, &statement, context, &params).is_err(),
        "altered party index must reject"
    );

    // Leaf randomness no longer recomputes the committed leaf.
    let mut bad = proof.clone();
    bad.reps[0].opened[0].leaf_randomness[0] ^= 1;
    assert!(
        verify_combined_v3(&bad, &statement, context, &params).is_err(),
        "altered leaf randomness must reject"
    );

    // Authentication-path sibling no longer folds to the root.
    let mut bad = proof.clone();
    bad.reps[0].opened[0].path[0][0] ^= 1;
    assert!(
        verify_combined_v3(&bad, &statement, context, &params).is_err(),
        "altered path sibling must reject"
    );

    // Flipped sibling direction fails the side-parity check.
    let mut bad = proof.clone();
    bad.reps[0].opened[0].path_left[0] = !bad.reps[0].opened[0].path_left[0];
    assert!(
        verify_combined_v3(&bad, &statement, context, &params).is_err(),
        "flipped path direction must reject"
    );

    // Truncated path fails the height check.
    let mut bad = proof.clone();
    bad.reps[0].opened[0].path.pop();
    bad.reps[0].opened[0].path_left.pop();
    assert!(
        verify_combined_v3(&bad, &statement, context, &params).is_err(),
        "truncated path must reject"
    );

    // Extended path fails the height check.
    let mut bad = proof.clone();
    bad.reps[0].opened[0].path.push([9u8; 32]);
    bad.reps[0].opened[0].path_left.push(false);
    assert!(
        verify_combined_v3(&bad, &statement, context, &params).is_err(),
        "extended path must reject"
    );

    // Wrong share count in one opened party.
    let mut bad = proof.clone();
    bad.reps[0].opened[0].shares.pop();
    assert!(
        verify_combined_v3(&bad, &statement, context, &params).is_err(),
        "short share vector must reject"
    );

    // Wrong opened-party count.
    let mut bad = proof.clone();
    bad.reps[0].opened.pop();
    assert!(
        verify_combined_v3(&bad, &statement, context, &params).is_err(),
        "short opened set must reject"
    );
}

#[test]
fn a3_broadcast_decs_shape_rejects() {
    // Shape (not value) mutations of the per-batch vectors.
    // (Share *values* are existing coverage.)
    let (proof, statement, context, params) = honest_proof();

    // Fewer broadcast shares than |S|.
    let mut bad = proof.clone();
    bad.reps[0].broadcast_alpha[0].pop();
    assert!(
        verify_combined_v3(&bad, &statement, context, &params).is_err(),
        "short broadcast_alpha must reject"
    );

    // Wrong batch count.
    let mut bad = proof.clone();
    bad.reps[0].broadcast_alpha.pop();
    assert!(
        verify_combined_v3(&bad, &statement, context, &params).is_err(),
        "missing broadcast batch must reject"
    );

    // Fewer prime broadcast shares than |S'|.
    let mut bad = proof.clone();
    bad.reps[0].broadcast_alpha_prime[0].pop();
    assert!(
        verify_combined_v3(&bad, &statement, context, &params).is_err(),
        "short broadcast_alpha_prime must reject"
    );

    // Fewer DECS responses than |Sx| in one row.
    let mut bad = proof.clone();
    bad.reps[0].decs_responses[0].pop();
    assert!(
        verify_combined_v3(&bad, &statement, context, &params).is_err(),
        "short decs response row must reject"
    );

    // Missing DECS row.
    let mut bad = proof.clone();
    bad.reps[0].decs_responses.pop();
    assert!(
        verify_combined_v3(&bad, &statement, context, &params).is_err(),
        "missing decs row must reject"
    );
}

#[test]
fn a3_parser_malformed_rejects() {
    // Only cases NOT already covered in `src/v3/proof.rs` tests (which
    // handle wrong magic/version, trailing bytes, noncanonical field
    // elements, bad side bits, and a 20-byte truncation).
    let (proof, _, _, _) = honest_proof();
    let bytes = proof.to_bytes().unwrap();

    // Empty input fails at the magic prefix check.
    assert!(V3Proof::from_bytes(&[]).is_err());

    // Mid-structure truncation (half the proof) fails cleanly.
    assert!(V3Proof::from_bytes(&bytes[..bytes.len() / 2]).is_err());

    // Oversized repetition-count prefix must fail at the length cap,
    // before any large allocation. The reps count sits after
    // magic(8) + version(2) + params(6x4) + lo(4) + hi(4) + root(32) +
    // num_members(4) + depth(4) + context(32) + circuit_hash(32) + salt(32).
    let reps_at: usize = 8 + 2 + 6 * 4 + 4 + 4 + 32 + 4 + 4 + 32 + 32 + 32;
    assert_eq!(reps_at, 178);
    let count =
        u32::from_be_bytes(bytes[reps_at..reps_at + 4].try_into().unwrap());
    assert_eq!(count, 1, "fast preset has one repetition");
    let mut bad = bytes.clone();
    bad[reps_at..reps_at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(
        V3Proof::from_bytes(&bad).is_err(),
        "oversized length prefix must reject at the cap"
    );
}

#[test]
fn a3_odd_party_count_end_to_end() {
    // End-to-end V3 proof with odd N=33 in the *share-commitment* tree
    // (not the 4-member statement tree), exercising the lonely duplicated
    // leaf through prove/verify/round-trip. N=33 keeps the fast-test
    // shape (s=8, ell=3, eta=2, rho=1, tau=1); degree checks:
    // d_beta+2=12, d_alpha+1=21, d2+1=18, all <= 33.
    let tree = small_tree();
    let params = V3Params::new(33, 3, 8, 2, 1, 1);
    params.validate().expect("N=33 test params must validate");
    let proof_tx = tree.prove_membership(1).unwrap();
    let context = [7u8; 32];
    let proof = prove_combined_v3(
        10, 40, tree.root(), tree.num_members(), tree.depth(), 20, &proof_tx,
        context, &params, &mut rng(),
    )
    .expect("odd-N honest proof must construct");
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
        .expect("odd-N honest proof must verify");
    assert_eq!(
        V3Proof::from_bytes(&proof.to_bytes().unwrap()).unwrap(),
        proof
    );
}
