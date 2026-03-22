//! protocol-level benchmark harness for railscale
//!
//! simulates tailscale clients at the HTTP layer to measure:
//! - registration throughput
//! - map response latency
//! - map response latency under peer load

pub mod harness;
pub mod report;
