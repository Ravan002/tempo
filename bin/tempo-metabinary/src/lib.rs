//! Era routing and process supervision for frozen historical Tempo executors.
//!
//! The live node executes the last era; earlier eras run in frozen `rpc-only` workers over the same
//! storage. This crate has no Tempo or Reth dependencies; the `tempo` binary implements
//! [`routing::Backend`].

pub mod catalog;
pub mod decorate;
pub mod handshake;
pub mod manifest;
pub mod process;
pub mod routing;
pub mod workers;
