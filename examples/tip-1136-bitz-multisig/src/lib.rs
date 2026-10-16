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

/// The proof system for this circuit profile.
pub type System = CircuitProofSystem<PrivateAuthorization>;

/// Builds the profile's constraint system.
///
/// Public values are input bits checked by a PCS opening, so one system serves
/// every statement: provers and verifiers run this once, not per proof.
pub fn setup() -> Result<System, Error> {
    ecdsa::prepare();
    CircuitProofSystem::new(
        PrivateAuthorization {
            statement: Statement::default(),
        },
        SecurityLevel::Bits100,
    )
}

/// Proves that `witness` authorizes `statement`.
pub fn prove(system: &mut System, statement: Statement, witness: &Witness) -> Result<Proof, Error> {
    system.set_statement(PrivateAuthorization { statement });
    let witness = system.witness(&witness_bits(&statement, witness))?;
    let commitment = system.commit(&witness)?;
    system.prove(witness, commitment)
}

/// Verifies a proof for `statement`.
pub fn verify(system: &mut System, statement: Statement, proof: &Proof) -> Result<(), Error> {
    system.set_statement(PrivateAuthorization { statement });
    system.verify(proof)
}
