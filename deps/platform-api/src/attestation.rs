use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Common application evidence contract. Only an AS adapter, after native
/// cryptographic verification, may populate this claim. Never copy runtime data.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WorkloadBinding {
    pub version: u32,
    pub profile: String,
    pub measurement_algorithm: String,
    pub measurement: String,
    pub reference_id: String,
    pub launch_algorithm: String,
    pub launch_digest: String,
}

/// A driver supplies native evidence verification separately. This interface
/// translates its *verified* claims to the shared application policy contract.
pub trait ApplicationEvidenceAdapter {
    fn application_binding(&self, verified_claims: &Value) -> Option<WorkloadBinding>;
}

pub struct TdxApplicationAdapter;
impl ApplicationEvidenceAdapter for TdxApplicationAdapter {
    fn application_binding(&self, claims: &Value) -> Option<WorkloadBinding> {
        Some(WorkloadBinding {
            version: 1,
            profile: "trustee.tdx-workload.v2".into(),
            measurement_algorithm: "sha384".into(),
            measurement: claims.pointer("/quote/body/rtmr_3")?.as_str()?.into(),
            reference_id: "application_rtmr_3".into(),
            launch_algorithm: "sha384".into(),
            launch_digest: claims.pointer("/quote/body/mr_config_id")?.as_str()?.into(),
        })
    }
}

/// This registry describes implemented adapters, not inferred CPU capabilities.
/// CSV/CCA verification and TKM/TrustZone credential sealing are independent.
pub fn application_binding(tee: &str, verified_claims: &Value) -> Option<WorkloadBinding> {
    match tee {
        "tdx" => TdxApplicationAdapter.application_binding(verified_claims),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unsupported_runtime_measurement_does_not_fall_back_to_boot_measurement() {
        let raw = serde_json::json!({"measurement": "approved", "runtime_data": {"application": "approved"}});
        for tee in ["csv", "cca", "sgx", "sample", "unknown"] {
            assert!(application_binding(tee, &raw).is_none());
        }
        assert!(application_binding("tdx", &raw).is_none());
    }
}
