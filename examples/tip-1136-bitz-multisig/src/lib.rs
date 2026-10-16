//! TIP-1136 `PrivateAuthorizationV1`, private weighted multisig profile, proved
//! with BitZ: integer rank-1 constraints over bit-decomposed witnesses,
//! committed in GF(2^128) and opened with Ligerito (binary-field WHIR-style
//! proximity testing) through Flock.
//!
//! Research prototype. Unaudited, not zero-knowledge (see the README), and
//! must not secure funds.

pub mod ecdsa;
pub mod policy;
pub mod relation;

pub use bitz_cli::end_to_end::{CircuitProofSystem, Error, Proof};
pub use pcs::SecurityLevel;

use policy::{Statement, Witness};
use relation::{PrivateAuthorization, witness_bits};

/// Builds the constraint system for one public statement.
///
/// Public values enter the constraints as constants, so the verifier runs the
/// same setup from the reconstructed statement.
pub fn setup(statement: Statement) -> Result<CircuitProofSystem<PrivateAuthorization>, Error> {
    ecdsa::prepare();
    CircuitProofSystem::new(PrivateAuthorization { statement }, SecurityLevel::Bits100)
}

/// Proves that `witness` satisfies the relation for the system's statement.
pub fn prove(
    system: &CircuitProofSystem<PrivateAuthorization>,
    witness: &Witness,
) -> Result<Proof, Error> {
    let witness = system.witness(&witness_bits(witness))?;
    let commitment = system.commit(&witness)?;
    system.prove(witness, commitment)
}
