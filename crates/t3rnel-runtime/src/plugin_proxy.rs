//! Credential-brokering proxy for plugins (`05-security-and-trust.md` §14).
//!
//! The engine lives in the `t3rnel-egress` crate (`sdk/rust/t3rnel-egress`) so that the core, plugin
//! SDKs and development hosts all run the same code. This module re-exports it under its original
//! path.

pub use t3rnel_egress::*;
