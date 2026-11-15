//! Mandatory two-mode authorization, evaluated after JWT verification and before
//! any backend call. The administrator's policy can further restrict access.
use policy_engine::{rego::Regorus, Result};
use serde_json::{json, Value};

pub const POLICY: &str = include_str!("../sample_policies/default.rego");

pub async fn authorize(claims: &Value, resource_path: &[&str]) -> Result<bool> {
    let results = Regorus::default()
        .evaluate(
            Some(json!({"plugin": "resource", "resource-path": resource_path}).to_string()),
            claims.to_string(),
            POLICY.into(),
            vec!["data.policy.allow".into()],
            vec![],
        )
        .await?;
    Ok(results
        .eval_rules_result
        .get("data.policy.allow")
        .and_then(Option::as_ref)
        .and_then(Value::as_bool)
        .unwrap_or(false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resource_mode_requires_all_results_even_when_an_admin_policy_allows() {
        let mut claims = json!({"submods": {"cpu0": {
            "ear.status": "affirming", "ear.appraisal-policy-id": "default",
            "ear.trustworthiness-vector": {"executables": 3, "hardware": 2, "configuration": 2},
            "ear.veraison.annotated-evidence": {"snp": {}}
        }}});
        assert!(authorize(&claims, &["default", "test", "key"])
            .await
            .unwrap());
        assert!(!authorize(&claims, &["workload", "test", "key"])
            .await
            .unwrap());
        claims["submods"]["cpu0"]["ear.status"] = json!("warning");
        assert!(!authorize(&claims, &["default", "test", "key"])
            .await
            .unwrap());
        assert!(!authorize(&json!({}), &["default", "test", "key"])
            .await
            .unwrap());
        assert!(!authorize(&claims, &["unknown", "test", "key"])
            .await
            .unwrap());
    }
}
