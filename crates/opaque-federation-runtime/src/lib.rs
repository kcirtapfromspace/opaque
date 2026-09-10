//! Opaque federation runtime: the SIEM-export / signed-attestation surface.
//!
//! Cooperating components of the public broker runtime, independently
//! buildable and testable:
//!
//! - [`federation`] — fetching, verifying, and applying signed policy bundles
//!   from an org (`BundleApplier`, hot-swaps the policy engine).
//! - [`export`] — streaming the tamper-evident audit chain off the box to
//!   spool/webhook/syslog transports, plus the independent approval-missing
//!   integrity detector.
//! - [`attest`] — continuous posture attestation and the verify-before-trust
//!   key release exchange.
//! - [`workload_attest`] — the listener-bound workload attestor (peer
//!   credentials -> `WorkloadIdentity`) installed after privilege drop.
//!
//! - [`fleet`] — provider-neutral signed broker reporting contracts and a
//!   bounded reporter. Collectors and organization management live separately.
//!
//! `opaqued` is a binary-only crate: `Enclave`/`DaemonState` are not
//! nameable from here. `federation::BundleApplier` depends on
//! `opaque_core::enclave_facade::EnclaveFacade` instead of a concrete
//! `Enclave`, so `opaqued` can hand it either a `DaemonState` or (during
//! startup, before `DaemonState` exists) a bare `Enclave` — both implement
//! the trait.

pub mod attest;
pub mod export;
pub mod federation;
pub mod fleet;
pub mod workload_attest;
