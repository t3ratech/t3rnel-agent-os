//! Core kernel for the T3rnel Agent Operating System.
//!
//! The kernel manages agent lifecycles, memory, permissions, scheduling,
//! and inter-agent communication.

pub mod approval;
pub mod approval_gate;
pub mod auth;
pub mod auto_reply;
pub mod background;
pub mod browser_extension_bridge;
pub mod capabilities;
pub mod config;
pub mod config_reload;
pub mod cron;
pub mod cron_delivery;
pub mod error;
pub mod event_bus;
pub mod fail_fast;
pub mod heartbeat;
pub mod kernel;
pub mod metering;
pub mod pairing;
pub mod registry;
pub mod scheduler;
pub mod scope_fence;
pub mod self_improvement;
pub mod sentinel;
pub mod shell_policy;
pub mod supervisor;
pub mod triggers;
pub mod whatsapp_gateway;
pub mod wizard;
pub mod workflow;

pub use kernel::DeliveryTracker;
pub use kernel::T3rnelKernel;
