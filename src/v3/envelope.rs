//! Ledger-facing proof envelope (integration layer, not protocol).
//!
//! The envelope binds one serialized [`V3Proof`] to the statement the
//! ledger expects, so an off-chain attester (and later a Fabric chaincode
//! event flow) can carry everything needed for verification in one object.
//! Nothing here changes the proof protocol: encoding follows the same
//! manual canonical style as [`crate::v3::proof`], and the final check is
//! the unmodified [`verify_combined_v3`].
//!
//! Trust flow: the caller (attester) supplies `expected` from ledger state
//! and an `allowed_params` list from local configuration. Envelope fields
//! are compared against those — never trusted on their own — before the
//! proof is parsed and verified. All rejections are machine-readable via
//! [`EnvelopeReject`]. No security claim attaches to this format.

use thiserror::Error;

use crate::v2::predicate::{MembershipStatementV2, RangeStatementV2, StatementV2};
use crate::v3::params::V3Params;
use crate::v3::proof::V3Proof;
use crate::v3::verifier::verify_combined_v3;

/// Envelope magic. Distinct from every proof magic value.
pub const ENVELOPE_MAGIC: &[u8; 8] = b"NMPCENV\0";

/// Only envelope format version accepted by [`ProofEnvelopeV1::from_bytes`].
pub const ENVELOPE_FORMAT_VERSION: u16 = 1;

/// Fail-closed cap on carried proof bytes (attester/ledger DoS bound).
/// Current 32-member proofs are ~215 KiB; anything near this cap is
/// rejected before parsing.
pub const MAX_ENVELOPE_PROOF_BYTES: usize = 1 << 20;

/// Named parameter presets the ledger may reference by id. The envelope
/// always carries full [`V3Params`]; the attester allowlist decides which
/// of these (if any) it accepts.
pub fn named_params(id: &str) -> Option<V3Params> {
    match id {
        "prototype-tau2" => Some(V3Params::prototype_tau2()),
        "reference-tau1" => Some(V3Params::published_reference_tau1()),
        "fast-insecure-test" => Some(V3Params::fast_insecure_test()),
        _ => None,
    }
}

/// One envelope: the statement the ledger expects plus the opaque proof
/// bytes that must prove it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofEnvelopeV1 {
    /// Full V3 parameter set. Must appear in the attester allowlist.
    pub params: V3Params,
    /// Expected public range lower bound (inclusive).
    pub range_lo: u32,
    /// Expected public range upper bound (inclusive).
    pub range_hi: u32,
    /// Expected Merkle set root (canonical field encoding).
    pub set_root: [u8; 32],
    /// Expected number of real set members.
    pub num_members: u32,
    /// Expected canonical tree depth.
    pub depth: u32,
    /// Expected 32-byte application context.
    pub context: [u8; 32],
    /// Serialized [`V3Proof`] bytes (opaque until parsed).
    pub proof_bytes: Vec<u8>,
}

/// The statement as the ledger believes it to be. Compared field-by-field
/// against the envelope before any proof parsing happens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedStatement {
    pub range_lo: u32,
    pub range_hi: u32,
    pub set_root: [u8; 32],
    pub num_members: u32,
    pub depth: u32,
    pub context: [u8; 32],
}

/// Machine-readable envelope rejection reasons, in check order.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EnvelopeReject {
    /// `V3Params::validate` failed on the envelope params.
    #[error("envelope params structurally invalid: {0}")]
    ParamsInvalid(String),
    /// Envelope params are not in the attester allowlist.
    #[error("envelope params not in attester allowlist")]
    ParamsNotAllowed,
    /// Envelope statement differs from the ledger expectation.
    #[error("envelope statement mismatch vs ledger expectation: {field}")]
    StatementMismatch {
        /// One of `range_lo`, `range_hi`, `set_root`, `num_members`,
        /// `depth`, `context`.
        field: &'static str,
    },
    /// Carried proof exceeds [`MAX_ENVELOPE_PROOF_BYTES`].
    #[error("envelope proof too large: {len} bytes")]
    ProofTooLarge {
        /// Declared/carried length in bytes.
        len: usize,
    },
    /// `V3Proof::from_bytes` failed on the carried proof.
    #[error("envelope proof failed to parse: {0}")]
    ProofParse(String),
    /// Parsed proof header differs from the envelope statement.
    #[error("proof header mismatch vs envelope statement: {field}")]
    HeaderMismatch {
        /// One of `params`, `range_lo`, `range_hi`, `set_root`,
        /// `num_members`, `depth`, `context`.
        field: &'static str,
    },
    /// Envelope statement itself fails statement validation.
    #[error("envelope statement invalid: {0}")]
    StatementInvalid(String),
    /// The embedded proof did not verify against the expected statement.
    #[error("proof verification failed: {0}")]
    VerificationFailed(String),
    /// Envelope-level codec error (magic/version/truncation/trailing).
    #[error("envelope encoding error: {0}")]
    Codec(String),
}

fn write_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn read_u32(bytes: &[u8], pos: &mut usize) -> Result<u32, EnvelopeReject> {
    if *pos + 4 > bytes.len() {
        return Err(EnvelopeReject::Codec("envelope truncated at u32".into()));
    }
    let v = u32::from_be_bytes(bytes[*pos..*pos + 4].try_into().unwrap());
    *pos += 4;
    Ok(v)
}

fn read_bytes32(bytes: &[u8], pos: &mut usize) -> Result<[u8; 32], EnvelopeReject> {
    if *pos + 32 > bytes.len() {
        return Err(EnvelopeReject::Codec("envelope truncated at bytes32".into()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[*pos..*pos + 32]);
    *pos += 32;
    Ok(out)
}

impl ProofEnvelopeV1 {
    /// Canonical serialization. Rejects oversized proofs before encoding.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EnvelopeReject> {
        if self.proof_bytes.len() > MAX_ENVELOPE_PROOF_BYTES {
            return Err(EnvelopeReject::ProofTooLarge {
                len: self.proof_bytes.len(),
            });
        }
        let mut out = Vec::with_capacity(128 + self.proof_bytes.len());
        out.extend_from_slice(ENVELOPE_MAGIC);
        out.extend_from_slice(&ENVELOPE_FORMAT_VERSION.to_be_bytes());
        write_u32(&mut out, self.params.num_parties);
        write_u32(&mut out, self.params.privacy_threshold);
        write_u32(&mut out, self.params.packing_width);
        write_u32(&mut out, self.params.decs_reps);
        write_u32(&mut out, self.params.mpc_reps);
        write_u32(&mut out, self.params.pok_reps);
        write_u32(&mut out, self.range_lo);
        write_u32(&mut out, self.range_hi);
        out.extend_from_slice(&self.set_root);
        write_u32(&mut out, self.num_members);
        write_u32(&mut out, self.depth);
        out.extend_from_slice(&self.context);
        write_u32(&mut out, self.proof_bytes.len() as u32);
        out.extend_from_slice(&self.proof_bytes);
        Ok(out)
    }

    /// Strict parse: magic, version, length cap, no trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EnvelopeReject> {
        let mut pos = 0usize;
        if pos + 8 > bytes.len() {
            return Err(EnvelopeReject::Codec("envelope truncated at magic".into()));
        }
        if bytes[pos..pos + 8] != *ENVELOPE_MAGIC {
            return Err(EnvelopeReject::Codec(
                "envelope has wrong magic (not a proof envelope)".into(),
            ));
        }
        pos += 8;
        if pos + 2 > bytes.len() {
            return Err(EnvelopeReject::Codec("envelope truncated at version".into()));
        }
        let version = u16::from_be_bytes(bytes[pos..pos + 2].try_into().unwrap());
        pos += 2;
        if version != ENVELOPE_FORMAT_VERSION {
            return Err(EnvelopeReject::Codec(format!(
                "envelope has unsupported version {version}"
            )));
        }
        let params = V3Params::new(
            read_u32(bytes, &mut pos)?,
            read_u32(bytes, &mut pos)?,
            read_u32(bytes, &mut pos)?,
            read_u32(bytes, &mut pos)?,
            read_u32(bytes, &mut pos)?,
            read_u32(bytes, &mut pos)?,
        );
        let range_lo = read_u32(bytes, &mut pos)?;
        let range_hi = read_u32(bytes, &mut pos)?;
        let set_root = read_bytes32(bytes, &mut pos)?;
        let num_members = read_u32(bytes, &mut pos)?;
        let depth = read_u32(bytes, &mut pos)?;
        let context = read_bytes32(bytes, &mut pos)?;
        let proof_len = read_u32(bytes, &mut pos)? as usize;
        if proof_len > MAX_ENVELOPE_PROOF_BYTES {
            return Err(EnvelopeReject::ProofTooLarge { len: proof_len });
        }
        if pos + proof_len > bytes.len() {
            return Err(EnvelopeReject::Codec("envelope truncated at proof bytes".into()));
        }
        let proof_bytes = bytes[pos..pos + proof_len].to_vec();
        pos += proof_len;
        if pos != bytes.len() {
            return Err(EnvelopeReject::Codec("envelope has trailing bytes".into()));
        }
        Ok(Self {
            params,
            range_lo,
            range_hi,
            set_root,
            num_members,
            depth,
            context,
            proof_bytes,
        })
    }

    /// Ledger anchor digest: BLAKE3 over the domain tag plus the canonical
    /// encoding. Deterministic per envelope content.
    pub fn envelope_hash(&self) -> Result<[u8; 32], EnvelopeReject> {
        let bytes = self.to_bytes()?;
        let mut h = blake3::Hasher::new();
        h.update(b"NMPC-envelope/v1");
        h.update(&bytes);
        Ok(*h.finalize().as_bytes())
    }

    /// Hex rendering of [`Self::envelope_hash`] for ledger APIs.
    pub fn envelope_hash_hex(&self) -> Result<String, EnvelopeReject> {
        Ok(hex::encode(self.envelope_hash()?))
    }
}

/// Verify an envelope against ledger-held expectations.
///
/// Check order (first failure wins): params structural validity →
/// params allowlist → statement-vs-expected (field by field) → proof size
/// cap → proof parse → proof-header-vs-envelope → statement validity →
/// [`verify_combined_v3`]. The proof carries no authority at any step.
pub fn verify_envelope(
    env: &ProofEnvelopeV1,
    expected: &ExpectedStatement,
    allowed_params: &[V3Params],
) -> Result<(), EnvelopeReject> {
    env.params
        .validate()
        .map_err(|e| EnvelopeReject::ParamsInvalid(e.to_string()))?;
    if !allowed_params.contains(&env.params) {
        return Err(EnvelopeReject::ParamsNotAllowed);
    }
    if env.range_lo != expected.range_lo {
        return Err(EnvelopeReject::StatementMismatch { field: "range_lo" });
    }
    if env.range_hi != expected.range_hi {
        return Err(EnvelopeReject::StatementMismatch { field: "range_hi" });
    }
    if env.set_root != expected.set_root {
        return Err(EnvelopeReject::StatementMismatch { field: "set_root" });
    }
    if env.num_members != expected.num_members {
        return Err(EnvelopeReject::StatementMismatch {
            field: "num_members",
        });
    }
    if env.depth != expected.depth {
        return Err(EnvelopeReject::StatementMismatch { field: "depth" });
    }
    if env.context != expected.context {
        return Err(EnvelopeReject::StatementMismatch { field: "context" });
    }
    if env.proof_bytes.len() > MAX_ENVELOPE_PROOF_BYTES {
        return Err(EnvelopeReject::ProofTooLarge {
            len: env.proof_bytes.len(),
        });
    }
    let proof =
        V3Proof::from_bytes(&env.proof_bytes).map_err(|e| EnvelopeReject::ProofParse(e.to_string()))?;
    if proof.params != env.params {
        return Err(EnvelopeReject::HeaderMismatch { field: "params" });
    }
    if proof.range_lo != env.range_lo {
        return Err(EnvelopeReject::HeaderMismatch { field: "range_lo" });
    }
    if proof.range_hi != env.range_hi {
        return Err(EnvelopeReject::HeaderMismatch { field: "range_hi" });
    }
    if proof.set_root != env.set_root {
        return Err(EnvelopeReject::HeaderMismatch { field: "set_root" });
    }
    if proof.num_members != env.num_members {
        return Err(EnvelopeReject::HeaderMismatch {
            field: "num_members",
        });
    }
    if proof.depth != env.depth {
        return Err(EnvelopeReject::HeaderMismatch { field: "depth" });
    }
    if proof.context != env.context {
        return Err(EnvelopeReject::HeaderMismatch { field: "context" });
    }
    let statement = StatementV2::Combined {
        range: RangeStatementV2::new(expected.range_lo, expected.range_hi)
            .map_err(|e| EnvelopeReject::StatementInvalid(e.to_string()))?,
        membership: MembershipStatementV2::new(
            crate::v2::field::decode_fr(&expected.set_root)
                .map_err(|e| EnvelopeReject::StatementInvalid(e.to_string()))?,
            expected.num_members,
            expected.depth,
        )
        .map_err(|e| EnvelopeReject::StatementInvalid(e.to_string()))?,
    };
    verify_combined_v3(&proof, &statement, expected.context, &env.params)
        .map_err(|e| EnvelopeReject::VerificationFailed(e.to_string()))?;
    Ok(())
}
