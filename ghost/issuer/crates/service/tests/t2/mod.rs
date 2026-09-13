//! The T2 unlinkability world (Phase 8 design §13.4, §19.16): the full Rust system (real issuer
//! handlers, real relay redeem path, real client-core crypto) driven by reference clients whose
//! schedule is the reference policy of [`policy`].
#![allow(dead_code)]

pub mod chain;
pub mod client;
pub mod config;
pub mod es;
pub mod gate;
pub mod policy;
pub mod population;
pub mod rng;
pub mod transport;
pub mod views;
pub mod world;
