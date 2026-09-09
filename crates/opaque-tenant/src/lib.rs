//! Tenant custody boundary and the shared, daemon-state-free protocol types
//! behind delegated IdP provisioning.
//!
//! `tenant` is a self-contained extraction: the durable one-tenant-per-broker
//! custody binding, with zero references to `opaqued`'s daemon state in
//! either direction.
//!
//! `provisioning_api` is a *partial* extraction. See that module's doc
//! comment for why the RPC dispatch itself stays in `opaqued`.

pub mod provisioning_api;
pub mod tenant;
