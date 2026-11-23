//! Memory substrate for the T3rnel Agent Operating System.
//!
//! Provides a unified memory API over three storage backends:
//! - **Structured store** (SQLite): Key-value pairs, sessions, agent state
//! - **Semantic store**: SQLite vector search or LanceDB sidecar-backed search
//! - **Knowledge graph** (SQLite): Entities and relations
//!
//! Agents interact with a single `Memory` trait that abstracts over all three stores.

pub mod consolidation;
pub mod event_store;
pub mod facade;
pub mod hnsw_lite;
#[cfg(feature = "http-memory")]
pub mod http_client;
pub mod knowledge;
pub mod lancedb_client;
pub mod migration;
pub mod namespace;
pub mod policy;
pub mod semantic;
pub mod session;
pub mod structured;
pub mod usage;

mod substrate;
pub use substrate::MemorySubstrate;
pub use substrate::PairedDeviceRecord;
