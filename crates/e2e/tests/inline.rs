use tempo_consensus::VerificationMode;
pub use tempo_e2e::*;

const VERIFICATION_MODE: VerificationMode = VerificationMode::Immediate;

/// Keeps tests whose outcome doesn't depend on the verification mode, so they
/// run in this binary only.
macro_rules! mode_agnostic {
    ($($item:item)*) => { $($item)* };
}

#[path = "suite/mod.rs"]
mod tests;
