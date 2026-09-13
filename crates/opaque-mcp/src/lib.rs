#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Contracts for preparing third-party MCP admission.
//!
//! These offline helpers grant no execution authority. The running stdio
//! adapter continues to expose only its existing built-in operations.

pub mod gateway_contract;
