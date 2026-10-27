//! Reproducible, single-sample V3 benchmark across membership-set sizes.
//!
//! Run with: cargo run --offline --release --example v3_benchmark

use std::time::Instant;

use range_set_mpcith::v2::merkle::MerkleTreeV2;
use range_set_mpcith::v2::predicate::{MembershipStatementV2, RangeStatementV2, StatementV2};
use range_set_mpcith::v3::params::V3Params;
use range_set_mpcith::v3::proof::V3Proof;
use range_set_mpcith::v3::prover::prove_combined_v3;
use range_set_mpcith::v3::verifier::verify_combined_v3;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn main() {
    let params = V3Params::prototype_tau2();
    let context = [7u8; 32];
    let range_lo = 1;
    let range_hi = 1000;
    let value = 120;
    let member_index = 2;

    println!("benchmark=v3_combined_membership_sweep");
    println!(
        "params=N:{},ell:{},s:{},eta:{},rho:{},tau:{}",
        params.num_parties,
        params.privacy_threshold,
        params.packing_width,
        params.decs_reps,
        params.mpc_reps,
        params.pok_reps
    );
    println!("range=[{range_lo},{range_hi}] value={value} member_index={member_index}");
    println!(
        "columns=set_size,merkle_depth,prove_ms,proof_bytes,verify_ms_1,verify_ms_2,roundtrip"
    );

    for set_size in [4usize, 8, 16, 32] {
        let members: Vec<u32> = (0..set_size).map(|i| 100 + 10 * i as u32).collect();
        let tree = MerkleTreeV2::build(&members).expect("build membership tree");
        let membership_proof = tree
            .prove_membership(member_index)
            .expect("prove membership");
        let mut rng = ChaCha20Rng::seed_from_u64(0x7331_5033 + set_size as u64);

        let start = Instant::now();
        let proof = prove_combined_v3(
            range_lo,
            range_hi,
            tree.root(),
            tree.num_members(),
            tree.depth(),
            value,
            &membership_proof,
            context,
            &params,
            &mut rng,
        )
        .expect("generate combined proof");
        let prove_ms = start.elapsed().as_secs_f64() * 1000.0;
        let bytes = proof.to_bytes().expect("serialize proof");

        let statement = StatementV2::Combined {
            range: RangeStatementV2::new(range_lo, range_hi).expect("valid range"),
            membership: MembershipStatementV2::new(tree.root(), tree.num_members(), tree.depth())
                .expect("valid membership statement"),
        };

        let mut verify_ms = [0.0; 2];
        for (index, elapsed) in verify_ms.iter_mut().enumerate() {
            let start = Instant::now();
            verify_combined_v3(&proof, &statement, context, &params)
                .expect("verify combined proof");
            *elapsed = start.elapsed().as_secs_f64() * 1000.0;
            assert_eq!(proof.reps.len(), params.pok_reps as usize);
            if index == 0 {
                // Ensure serialization and parsing preserve the measured proof.
                assert_eq!(V3Proof::from_bytes(&bytes).expect("parse proof"), proof);
            }
        }

        println!(
            "{set_size},{},{prove_ms:.1},{},{:.1},{:.1},ok",
            tree.depth(),
            bytes.len(),
            verify_ms[0],
            verify_ms[1]
        );
    }
}
