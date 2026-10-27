//! V2 identifiers retained because the experimental V3 suite declares its
//! field, Poseidon2 instance, and membership-tree framing relative to them.
//! This module intentionally omits V2 proof parameter and verifier code.

/// Historical V2 proof format version, used only to assert format separation.
pub const V2_PROOF_VERSION: u16 = 3;
/// V2 protocol family identifier.
pub const V2_PROTOCOL_ID: &[u8] = b"NovaMPC-v2/proof/v1";
/// BN254 scalar field identifier.
pub const V2_FIELD_ID: &[u8] = b"BN254-Fr";
/// Pinned Horizen Labs Poseidon2 BN254 instance identifier.
pub const V2_POSEIDON2_ID: &[u8] =
    b"HorizenLabs-poseidon2-bn254-t3-d5-rf8-rp56@055bde3f4782731ba5f5ce5888a440a94327eaf3";
/// Tagged-compression framing used by the V2 membership tree.
pub const V2_FRAMING_ID: &[u8] = b"NovaMPC-v2/tagged-compress/v1";
