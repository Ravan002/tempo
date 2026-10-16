use tempo_consensus::VerificationMode;
pub use tempo_e2e::*;

const VERIFICATION_MODE: VerificationMode = VerificationMode::Deferred;

/// Drops tests whose outcome doesn't depend on the verification mode; the
/// `inline` binary runs them.
macro_rules! mode_agnostic {
    ($($item:item)*) => {};
}

#[path = "suite/mod.rs"]
mod tests;
