//! T3rnel App Bridge.
//!
//! One permission-controlled doorway from agents to applications (`docs/sections/04-app-bridge-and-connectors.md`,
//! `05-security-and-trust.md`). The daemon alone holds policy; this crate is that policy.
//!
//! * [`capability`] — capability names and the reference risk table no manifest may undercut.
//! * [`manifest`] — the v1 plugin manifest and its validation.
//! * [`policy`] — grants, standing rules and the allow / approve / deny decision.
//! * [`ratchet`] — which manifest changes force a fresh approval.
//! * [`audit`] — the hash-chained record of every call.
//! * [`category`] — prohibited / restricted / unrestricted classification of requests and connectors.

pub mod audit;
pub mod capability;
pub mod category;
pub mod manifest;
pub mod policy;
pub mod ratchet;
