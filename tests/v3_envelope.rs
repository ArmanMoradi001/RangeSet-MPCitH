//! Envelope integration tests: honest verify, every rejection reason,
//! codec strictness, hash stability. Fast insecure preset only; no
//! security claim.

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use range_set_mpcith::v2::merkle::MerkleTreeV2;
use range_set_mpcith::v3::envelope::{
    named_params, verify_envelope, EnvelopeReject, ExpectedStatement, ProofEnvelopeV1,
    ENVELOPE_FORMAT_VERSION, ENVELOPE_MAGIC, MAX_ENVELOPE_PROOF_BYTES,
};
use range_set_mpcith::v3::params::V3Params;
use range_set_mpcith::v3::prover::prove_combined_v3;

fn test_setup() -> (MerkleTreeV2, [u8; 32]) {
    (MerkleTreeV2::build(&[10u32, 20, 30, 40]).unwrap(), [7u8; 32])
}

fn honest_envelope(params: V3Params) -> (ProofEnvelopeV1, ExpectedStatement) {
    let (tree, context) = test_setup();
    let mproof = tree.prove_membership(1).unwrap();
    let mut rng = ChaCha20Rng::seed_from_u64(0xE11E10);
    let proof = prove_combined_v3(
        10, 40, tree.root(), tree.num_members(), tree.depth(), 20, &mproof, context, &params,
        &mut rng,
    )
    .unwrap();
    let proof_bytes = proof.to_bytes().unwrap();
    let expected = ExpectedStatement {
        range_lo: 10,
        range_hi: 40,
        set_root: proof.set_root,
        num_members: tree.num_members(),
        depth: tree.depth(),
        context,
    };
    let env = ProofEnvelopeV1 {
        params,
        range_lo: expected.range_lo,
        range_hi: expected.range_hi,
        set_root: expected.set_root,
        num_members: expected.num_members,
        depth: expected.depth,
        context: expected.context,
        proof_bytes,
    };
    (env, expected)
}

fn allowed(params: V3Params) -> Vec<V3Params> {
    vec![params]
}

#[test]
fn honest_envelope_verifies_tau1() {
    let params = V3Params::fast_insecure_test();
    let (env, expected) = honest_envelope(params);
    verify_envelope(&env, &expected, &allowed(params)).unwrap();
}

#[test]
fn honest_envelope_verifies_tau2() {
    let params = V3Params::new(32, 3, 8, 2, 1, 2);
    let (env, expected) = honest_envelope(params);
    verify_envelope(&env, &expected, &allowed(params)).unwrap();
}

#[test]
fn wrong_expected_root_is_statement_mismatch() {
    let params = V3Params::fast_insecure_test();
    let (env, mut expected) = honest_envelope(params);
    expected.set_root[0] ^= 1;
    assert_eq!(
        verify_envelope(&env, &expected, &allowed(params)),
        Err(EnvelopeReject::StatementMismatch { field: "set_root" })
    );
}

#[test]
fn wrong_expected_context_is_statement_mismatch() {
    let params = V3Params::fast_insecure_test();
    let (env, mut expected) = honest_envelope(params);
    expected.context = [9u8; 32];
    assert_eq!(
        verify_envelope(&env, &expected, &allowed(params)),
        Err(EnvelopeReject::StatementMismatch { field: "context" })
    );
}

#[test]
fn disallowed_params_rejected_before_parsing() {
    let params = V3Params::fast_insecure_test();
    let (env, expected) = honest_envelope(params);
    assert_eq!(
        verify_envelope(&env, &expected, &[V3Params::prototype_tau2()]),
        Err(EnvelopeReject::ParamsNotAllowed)
    );
}

#[test]
fn structurally_invalid_params_rejected() {
    let params = V3Params::fast_insecure_test();
    let (mut env, expected) = honest_envelope(params);
    env.params = V3Params::new(16, 8, 16, 2, 1, 1); // d_beta + 2 > N
    let allow = vec![env.params];
    assert!(matches!(
        verify_envelope(&env, &expected, &allow),
        Err(EnvelopeReject::ParamsInvalid(_))
    ));
}

#[test]
fn tampered_magic_proof_is_parse_error() {
    let params = V3Params::fast_insecure_test();
    let (mut env, expected) = honest_envelope(params);
    env.proof_bytes[0] ^= 0xFF;
    assert!(matches!(
        verify_envelope(&env, &expected, &allowed(params)),
        Err(EnvelopeReject::ProofParse(_))
    ));
}

#[test]
fn tampered_proof_value_fails_verification() {
    let params = V3Params::fast_insecure_test();
    let (mut env, expected) = honest_envelope(params);
    let last = env.proof_bytes.len() - 1;
    env.proof_bytes[last] ^= 1;
    assert!(matches!(
        verify_envelope(&env, &expected, &allowed(params)),
        Err(EnvelopeReject::VerificationFailed(_)) | Err(EnvelopeReject::ProofParse(_))
    ));
}

#[test]
fn proof_header_vs_envelope_mismatch_reported() {
    // Envelope and expectation agree on a widened range, but the embedded
    // proof was built for [10,40]: header check must name `range_hi`.
    let params = V3Params::fast_insecure_test();
    let (mut env, mut expected) = honest_envelope(params);
    env.range_hi = 41;
    expected.range_hi = 41;
    assert_eq!(
        verify_envelope(&env, &expected, &allowed(params)),
        Err(EnvelopeReject::HeaderMismatch { field: "range_hi" })
    );
}

#[test]
fn oversize_proof_rejected_without_parsing() {
    let params = V3Params::fast_insecure_test();
    let (mut env, expected) = honest_envelope(params);
    env.proof_bytes = vec![0u8; MAX_ENVELOPE_PROOF_BYTES + 1];
    assert_eq!(
        verify_envelope(&env, &expected, &allowed(params)),
        Err(EnvelopeReject::ProofTooLarge {
            len: MAX_ENVELOPE_PROOF_BYTES + 1
        })
    );
}

#[test]
fn envelope_codec_round_trip_and_strictness() {
    let params = V3Params::fast_insecure_test();
    let (env, _) = honest_envelope(params);
    let bytes = env.to_bytes().unwrap();
    assert_eq!(ProofEnvelopeV1::from_bytes(&bytes).unwrap(), env);
    // Trailing byte.
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(matches!(
        ProofEnvelopeV1::from_bytes(&trailing),
        Err(EnvelopeReject::Codec(_))
    ));
    // Bad magic.
    let mut bad_magic = bytes.clone();
    bad_magic[0] ^= 0xFF;
    assert!(matches!(
        ProofEnvelopeV1::from_bytes(&bad_magic),
        Err(EnvelopeReject::Codec(_))
    ));
    // Bad version.
    let mut bad_version = bytes.clone();
    bad_version[8] ^= 0xFF;
    assert!(matches!(
        ProofEnvelopeV1::from_bytes(&bad_version),
        Err(EnvelopeReject::Codec(_))
    ));
    // Truncation.
    assert!(matches!(
        ProofEnvelopeV1::from_bytes(&bytes[..bytes.len() / 2]),
        Err(EnvelopeReject::Codec(_))
    ));
    // Declared length beyond cap rejected before allocation.
    let mut huge_len = bytes.clone();
    let off = bytes.len() - env.proof_bytes.len() - 4;
    huge_len[off..off + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        ProofEnvelopeV1::from_bytes(&huge_len),
        Err(EnvelopeReject::ProofTooLarge { len: u32::MAX as usize })
    );
}

#[test]
fn envelope_hash_stable_and_content_bound() {
    let params = V3Params::fast_insecure_test();
    let (env, _) = honest_envelope(params);
    let h1 = env.envelope_hash().unwrap();
    let h2 = ProofEnvelopeV1::from_bytes(&env.to_bytes().unwrap())
        .unwrap()
        .envelope_hash()
        .unwrap();
    assert_eq!(h1, h2);
    assert_eq!(h1.len(), 32);
    assert_eq!(env.envelope_hash_hex().unwrap().len(), 64);
    let mut mutated = env.clone();
    mutated.range_hi ^= 1;
    assert_ne!(mutated.envelope_hash().unwrap(), h1);
}

#[test]
fn named_params_registry_resolves_presets() {
    assert_eq!(
        named_params("prototype-tau2"),
        Some(V3Params::prototype_tau2())
    );
    assert_eq!(
        named_params("reference-tau1"),
        Some(V3Params::published_reference_tau1())
    );
    assert_eq!(
        named_params("fast-insecure-test"),
        Some(V3Params::fast_insecure_test())
    );
    assert_eq!(named_params("no-such-preset"), None);
    for id in ["prototype-tau2", "reference-tau1", "fast-insecure-test"] {
        named_params(id).unwrap().validate().unwrap();
    }
    assert_eq!(ENVELOPE_MAGIC.len(), 8);
    assert_eq!(ENVELOPE_FORMAT_VERSION, 1);
}
