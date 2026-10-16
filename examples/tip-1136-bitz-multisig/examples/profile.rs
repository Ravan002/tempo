//! Prints a per-span timing tree for one proof (stderr).

#[path = "../tests/common/mod.rs"]
mod fixtures;

use std::time::Instant;

use fixtures::*;
use tip_1136_bitz::{policy::Witness, prove, setup, verify};
use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new("info"))
        .with_span_events(FmtSpan::CLOSE)
        .with_target(false)
        .init();
    let approvals: Vec<_> = [ALICE, CAROL, EVE].map(|i| approve(i, &digest())).into();
    let witness = Witness::new(&policy(), &approvals, &digest())?;
    let mut system = setup()?;
    let t = Instant::now();
    let proof = prove(&mut system, statement(), &witness)?;
    eprintln!("PROVE {:?}", t.elapsed());
    let t = Instant::now();
    verify(&mut system, statement(), &proof)?;
    eprintln!("VERIFY {:?}", t.elapsed());
    Ok(())
}
