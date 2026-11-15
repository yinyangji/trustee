//! Hardware-independent contracts shared by KBS, AS and platform drivers.
//!
//! Attestation of a workload and sealing service credentials are independent
//! capabilities. A CPU vendor name must never imply either capability.
pub mod attestation;
pub mod credentials;
pub mod policy;
