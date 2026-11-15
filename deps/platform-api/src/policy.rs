use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

/// Public policy modes. Platform verifiers remain responsible for the evidence.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyMode {
    Default,
    Workload,
}

impl PolicyMode {
    pub fn parse(selector: &str) -> Result<Self> {
        match selector {
            "default" => Ok(Self::Default),
            "workload" => Ok(Self::Workload),
            _ => bail!("unsupported policy mode"),
        }
    }

    pub fn policy_ids(self) -> Vec<String> {
        match self {
            Self::Default => vec!["default".into()],
            Self::Workload => vec!["default".into(), "application".into()],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn application_cannot_be_selected_without_the_platform_policy() {
        assert_eq!(
            PolicyMode::parse("workload").unwrap().policy_ids(),
            ["default", "application"]
        );
        assert_eq!(
            PolicyMode::parse("default").unwrap().policy_ids(),
            ["default"]
        );
        assert!(PolicyMode::parse("application").is_err());
    }
}
