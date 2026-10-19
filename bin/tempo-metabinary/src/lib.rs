//! Execution of frozen Tempo eras by their historical binaries.
//!
//! A release can drop the execution rules of every hardfork older than
//! `TempoHardfork::MINIMUM_SUPPORTED` and still serve full history: blocks of a frozen era are
//! executed by a separately built era binary that shares the node's on-disk storage. This crate
//! is execution-independent; the `tempo` binary supplies the chain-specific adapter.
//!
//! - [`catalog`]: release metadata listing the frozen eras of each built-in chain.
//! - [`routing`]: classifies RPC methods and picks the era that executes each request.
//! - [`decorate`]: replaces execution callbacks of the native RPC transports in place.
//! - [`workers`]: lazily started read-only RPC workers, one per frozen era.
//! - [`handshake`]: the private worker discovery protocol.
//! - [`process`]: bounded child-process lifecycle helpers.
//!
//! See the crate README for the routing rules and operational behavior.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

pub mod catalog;
pub mod decorate;
pub mod handshake;
pub mod process;
pub mod routing;
pub mod workers;
