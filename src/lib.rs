//! Experimental MPC-in-the-head proof prototype for a combined range and
//! Merkle-set membership statement. This crate is not security reviewed.

pub mod error;
pub mod v2;
pub mod v3;

pub use error::MpcithError;
pub type Result<T> = std::result::Result<T, MpcithError>;
