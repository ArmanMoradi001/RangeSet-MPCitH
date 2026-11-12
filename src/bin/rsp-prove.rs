//! `rsp-prove`: build a Merkle set, prove range+membership, write a
//! versioned proof envelope file for later Fabric submission.
//!
//! Usage:
//! ```sh
//! rsp-prove --value 20 --lo 10 --hi 40 --members 10,20,30,40 \
//!   --member-index 1 --context <64 hex> --params fast-insecure-test \
//!   --seed 1234 --out proof.env
//! ```
//! Prints a one-line JSON summary to stdout. Exit 0 on success,
//! 1 on prover error, 2 on usage error. Deterministic for a fixed seed.

use std::process::ExitCode;

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use range_set_mpcith::v2::merkle::MerkleTreeV2;
use range_set_mpcith::v3::envelope::{named_params, ProofEnvelopeV1};
use range_set_mpcith::v3::params::V3Params;
use range_set_mpcith::v3::prover::prove_combined_v3;

fn usage() -> ! {
    eprintln!(
        "usage: rsp-prove --value V --lo LO --hi HI --members A,B,... --member-index I \
--context HEX64 --params PRESET --seed N --out FILE"
    );
    std::process::exit(2);
}

fn arg(args: &[String], name: &str) -> String {
    args.windows(2)
        .find(|w| w[0] == name)
        .map(|w| w[1].clone())
        .unwrap_or_else(|| {
            eprintln!("missing {name}");
            usage();
        })
}

fn parse_hex32(s: &str, what: &str) -> [u8; 32] {
    let bytes = hex::decode(s).unwrap_or_else(|_| {
        eprintln!("{what} is not hex");
        usage();
    });
    if bytes.len() != 32 {
        eprintln!("{what} must be 64 hex chars");
        usage();
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let value: u32 = arg(&args, "--value").parse().unwrap_or_else(|_| usage());
    let lo: u32 = arg(&args, "--lo").parse().unwrap_or_else(|_| usage());
    let hi: u32 = arg(&args, "--hi").parse().unwrap_or_else(|_| usage());
    let members: Vec<u32> = arg(&args, "--members")
        .split(',')
        .map(|s| {
            s.trim().parse().unwrap_or_else(|_| {
                eprintln!("bad member {s:?}");
                usage();
            })
        })
        .collect();
    let member_index: usize = arg(&args, "--member-index").parse().unwrap_or_else(|_| usage());
    let context = parse_hex32(&arg(&args, "--context"), "--context");
    let params: V3Params = named_params(&arg(&args, "--params")).unwrap_or_else(|| {
        eprintln!("unknown --params preset (see named_params)");
        usage();
    });
    let seed: u64 = arg(&args, "--seed").parse().unwrap_or_else(|_| usage());
    let out = arg(&args, "--out");

    if let Err(e) = params.validate() {
        eprintln!("params invalid: {e}");
        return ExitCode::from(1);
    }
    let tree = match MerkleTreeV2::build(&members) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("set build failed: {e}");
            return ExitCode::from(1);
        }
    };
    if member_index >= members.len() {
        eprintln!("member-index out of range");
        return ExitCode::from(2);
    }
    let mproof = match tree.prove_membership(member_index as u32) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("membership proof failed: {e}");
            return ExitCode::from(1);
        }
    };
    // Domain-separate the caller seed from rep seeds: the prover draws its
    // own stream from this RNG, deterministically.
    let mut rng_seed = [0u8; 32];
    ChaCha20Rng::seed_from_u64(seed).fill_bytes(&mut rng_seed);
    let mut rng = ChaCha20Rng::from_seed(rng_seed);
    let proof = match prove_combined_v3(
        lo,
        hi,
        tree.root(),
        tree.num_members(),
        tree.depth(),
        value,
        &mproof,
        context,
        &params,
        &mut rng,
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("prove failed: {e}");
            return ExitCode::from(1);
        }
    };
    let proof_bytes = match proof.to_bytes() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("proof encode failed: {e}");
            return ExitCode::from(1);
        }
    };
    let env = ProofEnvelopeV1 {
        params,
        range_lo: lo,
        range_hi: hi,
        set_root: proof.set_root,
        num_members: proof.num_members,
        depth: proof.depth,
        context,
        proof_bytes,
    };
    let env_bytes = match env.to_bytes() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("envelope encode failed: {e}");
            return ExitCode::from(1);
        }
    };
    if let Err(e) = std::fs::write(&out, &env_bytes) {
        eprintln!("write {out} failed: {e}");
        return ExitCode::from(1);
    }
    let hash = env.envelope_hash_hex().unwrap_or_default();
    println!(
        "{{\"envelope_file\":\"{out}\",\"envelope_hash\":\"{hash}\",\"proof_bytes\":{},\"envelope_bytes\":{}}}",
        env.proof_bytes.len(),
        env_bytes.len(),
    );
    ExitCode::SUCCESS
}
