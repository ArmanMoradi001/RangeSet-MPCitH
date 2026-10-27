//! Targeted prover profiler (P11.1). Release-only timings at the prototype
//! point; no protocol change. Run:
//! `cargo run --offline --release --example v3_profile`

use std::time::Instant;

use ark_bn254::Fr;
use ark_ff::UniformRand;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use range_set_mpcith::v2::merkle::MerkleTreeV2;
use range_set_mpcith::v3::commit::{leaf_commit, merkle_path, merkle_root};
use range_set_mpcith::v3::constraints::ConstraintProgramV3;
use range_set_mpcith::v3::hints::{
    correction_basis_eval, eval_hint_polys, sample_hint_polys, sigma_correction,
    zero_mask_eval, PiDollarV3,
};
use range_set_mpcith::v3::params::V3Params;
use range_set_mpcith::v3::prover::prove_combined_v3;
use range_set_mpcith::v3::sharing::{
    interpolate_coeffs_fast, party_point, share,
};

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.0
}

fn main() {
    let params = V3Params::prototype_tau2();
    let s = params.packing_width as usize;
    let ell = params.privacy_threshold as usize;
    let n = params.num_parties as usize;
    let eta = params.decs_reps as usize;
    let rho = params.mpc_reps as usize;
    let d_beta = params.hint_degree() as usize;
    let d_alpha = params.broadcast_degree() as usize;
    let d2 = 2 * s + ell - 2;

    // Worst-case 32-member statement (slowest in benchmark sweep).
    let members: Vec<u32> = (0..32).map(|i| 100 + 10 * i as u32).collect();
    let tree = MerkleTreeV2::build(&members).unwrap();
    let mproof = tree.prove_membership(2).unwrap();
    let statement =
        range_set_mpcith::v2::predicate::compile_from_statement(
            &range_set_mpcith::v2::predicate::StatementV2::Combined {
                range: range_set_mpcith::v2::predicate::RangeStatementV2::new(1, 1000)
                    .unwrap(),
                membership:
                    range_set_mpcith::v2::predicate::MembershipStatementV2::new(
                        tree.root(),
                        tree.num_members(),
                        tree.depth(),
                    )
                    .unwrap(),
            },
        )
        .unwrap();
    let t0 = Instant::now();
    let program = ConstraintProgramV3::compile(statement.circuit(), &params).unwrap();
    let inputs = statement.witness_for(120, Some(&mproof)).unwrap();
    let matrix = program.witness_matrix(statement.circuit(), &inputs).unwrap();
    println!("A_relation_compile+witness {:.1}ms", ms(t0));
    let n_w = matrix.len();
    println!("n_w={n_w} m1={} m2={} d_beta={d_beta} d_alpha={d_alpha} d2={d2}", program.m1(), program.m2());

    let mut rng = ChaCha20Rng::seed_from_u64(0xC10C);
    let pi_v = PiDollarV3::for_target(s, ell, d_beta, d_alpha - s).unwrap();
    let pi_vp = PiDollarV3::for_target(s, ell, d_beta, d2).unwrap();

    // B: packed share generation (witness + eta masks), exactly like prove_rep.
    let t = Instant::now();
    let mut q_shares: Vec<Vec<Fr>> = Vec::with_capacity(n_w + eta + rho * (pi_v.num_hints + pi_vp.num_hints));
    for pack in &matrix {
        let r: Vec<Fr> = (0..ell).map(|_| Fr::rand(&mut rng)).collect();
        q_shares.push(share(s, ell, n, pack, &r).unwrap());
    }
    for _ in 0..eta {
        let secret: Vec<Fr> = (0..s).map(|_| Fr::rand(&mut rng)).collect();
        let r: Vec<Fr> = (0..ell).map(|_| Fr::rand(&mut rng)).collect();
        q_shares.push(share(s, ell, n, &secret, &r).unwrap());
    }
    println!("B_share_witness_masks({} shares x N={n}) {:.1}ms", q_shares.len(), ms(t));

    // C: hint polys sample + eval + sigma_correction + derive (per batch).
    let t = Instant::now();
    let mut hint_cols: Vec<Vec<Fr>> = Vec::new();
    let mut jv_full: Vec<Fr> = Vec::new();
    for _ in 0..rho {
        let v_polys = sample_hint_polys(&pi_v.hint_degrees(d_beta), &mut rng);
        let vp_polys = sample_hint_polys(&pi_vp.hint_degrees(d_beta), &mut rng);
        let delta = sigma_correction(s, pi_vp.delta, &vp_polys);
        let v_hints = eval_hint_polys(&v_polys, s, n);
        let mut vp_hints = eval_hint_polys(&vp_polys, s, n);
        for i in 0..n {
            vp_hints[0][i] += delta * correction_basis_eval(s, party_point(s, i));
        }
        let jt = pi_v.derive(s, &v_hints).unwrap();
        let jv: Vec<Fr> = jt.iter().enumerate().map(|(i, v)| *v * zero_mask_eval(s, i)).collect();
        let _jvp = pi_vp.derive(s, &vp_hints).unwrap();
        jv_full = jv;
        for h in v_hints.into_iter().chain(vp_hints.into_iter()) {
            hint_cols.push(h);
        }
    }
    std::hint::black_box(&jv_full);
    println!("C_hints(sample+eval+correct+derive, {} cols) {:.1}ms", hint_cols.len(), ms(t));

    // D: leaf commits + Merkle root.
    let all_cols: Vec<&Vec<Fr>> = q_shares.iter().chain(hint_cols.iter()).collect();
    let mut leaf_rand = vec![[0u8; 32]; n];
    for r in leaf_rand.iter_mut() {
        rng.fill_bytes(r);
    }
    let t = Instant::now();
    let leaves: Vec<[u8; 32]> = (0..n)
        .map(|i| {
            let values: Vec<Fr> = all_cols.iter().map(|v| v[i]).collect();
            leaf_commit(i as u32, &values, &leaf_rand[i])
        })
        .collect();
    println!("D_leaf_commit(N={n} x {} cols) {:.1}ms", all_cols.len(), ms(t));
    let t = Instant::now();
    let root = merkle_root(&leaves).unwrap();
    println!("D2_merkle_root {:.1}ms", ms(t));
    std::hint::black_box(&root);

    // E: Merkle paths for ell openings.
    let t = Instant::now();
    for i in 0..ell {
        let p = merkle_path(&leaves, i).unwrap();
        std::hint::black_box(p);
    }
    println!("E_merkle_path(ell={ell}) {:.1}ms", ms(t));

    // F: broadcast work: lane interpolator, quadratic loop, sparse linear loop.
    let t = Instant::now();
    let lane_interp = program.lane_interpolator().unwrap();
    println!("F1_lane_interpolator {:.1}ms", ms(t));
    let g: Vec<Fr> = (0..program.m1()).map(|_| Fr::rand(&mut rng)).collect();
    let gp: Vec<Fr> = (0..program.m2()).map(|_| Fr::rand(&mut rng)).collect();
    let t = Instant::now();
    let mut acc_quad = Fr::from(0u64);
    for i in 0..(d_alpha + 1) {
        for (gi, grp) in program.parallel_groups().iter().enumerate() {
            let a = q_shares[grp.a_row][i];
            let b = q_shares[grp.b_row][i];
            let c = q_shares[grp.c_row][i];
            acc_quad += g[gi] * (c - a * b);
        }
    }
    std::hint::black_box(acc_quad);
    println!("F2_quad_broadcast(d_alpha+1={} x m1={}) {:.1}ms", d_alpha + 1, program.m1(), ms(t));
    let t = Instant::now();
    let ap_bases: Vec<Vec<Fr>> = (0..d2 + 1)
        .map(|i| lane_interp.basis_evals(party_point(s, i)))
        .collect();
    println!("F3_lane_bases(d2+1={}) {:.1}ms", d2 + 1, ms(t));
    let t = Instant::now();
    let mut acc_lin = Fr::from(0u64);
    for k in 0..(d2 + 1) {
        let pack_values: Vec<Fr> = q_shares[..n_w].iter().map(|col| col[k]).collect();
        let jb = program.eval_linear_jb_sparse(&ap_bases[k], &pack_values).unwrap();
        for (jb_j, gp_j) in jb.iter().zip(gp.iter()) {
            acc_lin += *gp_j * *jb_j;
        }
    }
    std::hint::black_box(acc_lin);
    println!("F4_sparse_linear(d2+1={} x m2={}) {:.1}ms", d2 + 1, program.m2(), ms(t));

    // G: interpolation sizes used by prover (Pxi d_beta+1, broadcast d_alpha+1).
    let t = Instant::now();
    for _ in 0..eta {
        let pts: Vec<Fr> = (0..d_beta + 1).map(|i| party_point(s, i)).collect();
        let vals: Vec<Fr> = (0..d_beta + 1).map(|_| Fr::rand(&mut rng)).collect();
        let coeffs = interpolate_coeffs_fast(&pts, &vals).unwrap();
        std::hint::black_box(coeffs);
    }
    println!("G_pxi_interp(eta={eta} x {}) {:.1}ms", d_beta + 1, ms(t));
    let t = Instant::now();
    {
        let pts: Vec<Fr> = (0..d_alpha + 1).map(|i| party_point(s, i)).collect();
        let vals: Vec<Fr> = (0..d_alpha + 1).map(|_| Fr::rand(&mut rng)).collect();
        let coeffs = interpolate_coeffs_fast(&pts, &vals).unwrap();
        std::hint::black_box(coeffs);
    }
    println!("G2_broadcast_interp({}) {:.1}ms", d_alpha + 1, ms(t));

    // H: full prover reference (tau=2, as shipped).
    let context = [7u8; 32];
    let t = Instant::now();
    let proof = prove_combined_v3(1, 1000, tree.root(), tree.num_members(), tree.depth(), 120, &mproof, context, &params, &mut rng).unwrap();
    println!("H_full_prove_tau2 {:.1}ms bytes={}", ms(t), proof.to_bytes().unwrap().len());
}
