//! grant type definition

use serde::{Deserialize, Serialize};

use crate::capability::{AppCapability, NetworkCapability};
use crate::error::ValidationError;
use crate::selector::Selector;

/// a single grant defining access from src to dst
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    /// source selectors - who can initiate the connection
    pub src: Vec<Selector>,

    /// destination selectors - what can be accessed
    pub dst: Vec<Selector>,

    /// network capabilities (ports/protocols)
    /// required if `app` is empty
    #[serde(default)]
    pub ip: Vec<NetworkCapability>,

    /// application capabilities
    /// required if `ip` is empty
    #[serde(default)]
    pub app: Vec<AppCapability>,

    /// source posture requirements (not implemented initially)
    #[serde(default, rename = "srcPosture")]
    pub src_posture: Vec<String>,

    /// routing constraints (tags only)
    #[serde(default)]
    pub via: Vec<String>,
}

impl Grant {
    /// validate the grant structure
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.src.is_empty() {
            return Err(ValidationError::EmptySrc);
        }
        if self.dst.is_empty() {
            return Err(ValidationError::EmptyDst);
        }
        if self.ip.is_empty() && self.app.is_empty() {
            return Err(ValidationError::NoCapabilities);
        }
        // validate via contains only tags
        for via in &self.via {
            if !via.starts_with("tag:") {
                return Err(ValidationError::InvalidVia(via.clone()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::selector::Autogroup;

    #[test]
    fn test_validate_empty_src() {
        let grant = Grant {
            src: vec![],
            dst: vec![Selector::Wildcard],
            ip: vec![NetworkCapability::Wildcard],
            app: vec![],
            src_posture: vec![],
            via: vec![],
        };

        let result = grant.validate();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ValidationError::EmptySrc));
    }

    #[test]
    fn test_validate_empty_dst() {
        let grant = Grant {
            src: vec![Selector::Wildcard],
            dst: vec![],
            ip: vec![NetworkCapability::Wildcard],
            app: vec![],
            src_posture: vec![],
            via: vec![],
        };

        let result = grant.validate();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ValidationError::EmptyDst));
    }

    #[test]
    fn test_validate_no_capabilities() {
        let grant = Grant {
            src: vec![Selector::Wildcard],
            dst: vec![Selector::Wildcard],
            ip: vec![],
            app: vec![],
            src_posture: vec![],
            via: vec![],
        };

        let result = grant.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::NoCapabilities
        ));
    }

    #[test]
    fn test_validate_invalid_via() {
        let grant = Grant {
            src: vec![Selector::Wildcard],
            dst: vec![Selector::Wildcard],
            ip: vec![NetworkCapability::Wildcard],
            app: vec![],
            src_posture: vec![],
            via: vec!["user@example.com".to_string()], // Not a tag!
        };

        let result = grant.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            ValidationError::InvalidVia(s) => assert_eq!(s, "user@example.com"),
            _ => panic!("Expected InvalidVia error"),
        }
    }

    #[test]
    fn test_validate_valid_grant() {
        let grant = Grant {
            src: vec![Selector::Wildcard],
            dst: vec![Selector::Autogroup(Autogroup::Tagged)],
            ip: vec![NetworkCapability::Wildcard],
            app: vec![],
            src_posture: vec![],
            via: vec!["tag:exit-node".to_string()],
        };

        assert!(grant.validate().is_ok());
    }
}
