//! device posture expressions and evaluation
//!
//! posture conditions allow grants to be conditional on device attributes
//! like OS version, tailscale version, or custom attributes

use std::str::FromStr;

/// a namespaced posture attribute (e.g., `node:os`, `custom:tier`)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostureAttr {
    /// namespace (node, custom, ip)
    pub namespace: String,
    /// attribute name within the namespace
    pub name: String,
}

impl PostureAttr {
    /// create a new posture attribute
    pub fn new(namespace: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            name: name.into(),
        }
    }
}

/// comparison operators for posture expressions
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostureOp {
    /// equality (==)
    Eq,
    /// inequality (!=)
    Ne,
    /// less than (<)
    Lt,
    /// less than or equal (<=)
    Le,
    /// greater than (>)
    Gt,
    /// greater than or equal (>=)
    Ge,
    /// list membership (IN)
    In,
    /// list exclusion (NOT IN)
    NotIn,
    /// attribute is set (IS SET)
    IsSet,
    /// attribute is not set (NOT SET)
    NotSet,
}

/// a parsed posture expression
#[derive(Debug, Clone, PartialEq)]
pub enum PostureExpr {
    /// comparison with a string value (e.g., `node:os == 'linux'`)
    Compare {
        /// the attribute to compare
        attr: PostureAttr,
        /// the comparison operator
        op: PostureOp,
        /// the value to compare against
        value: String,
    },
    /// list membership (e.g., `node:os IN ['macos', 'linux']`)
    InList {
        /// the attribute to check
        attr: PostureAttr,
        /// In or NotIn
        op: PostureOp,
        /// list of values to check against
        values: Vec<String>,
    },
    /// presence check (e.g., `custom:managed IS SET`)
    Presence {
        /// the attribute to check
        attr: PostureAttr,
        /// IsSet or NotSet
        op: PostureOp,
    },
}

/// error parsing a posture expression
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PostureParseError {
    /// invalid expression syntax
    #[error("invalid posture expression: {0}")]
    InvalidSyntax(String),
    /// invalid attribute format
    #[error("invalid attribute format: {0}")]
    InvalidAttribute(String),
    /// invalid operator
    #[error("invalid operator: {0}")]
    InvalidOperator(String),
    /// invalid value
    #[error("invalid value: {0}")]
    InvalidValue(String),
}

impl FromStr for PostureExpr {
    type Err = PostureParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_posture_expr(s)
    }
}

fn parse_posture_expr(s: &str) -> Result<PostureExpr, PostureParseError> {
    let s = s.trim();

    // try to parse IS SET / NOT SET first
    if let Some(rest) = s.strip_suffix("IS SET") {
        let attr = parse_attr(rest.trim())?;
        return Ok(PostureExpr::Presence {
            attr,
            op: PostureOp::IsSet,
        });
    }
    if let Some(rest) = s.strip_suffix("NOT SET") {
        let attr = parse_attr(rest.trim())?;
        return Ok(PostureExpr::Presence {
            attr,
            op: PostureOp::NotSet,
        });
    }

    // try IN / NOT IN with list
    if let Some((attr_part, list_part)) = split_list_expr(s, " NOT IN ") {
        let attr = parse_attr(attr_part)?;
        let values = parse_list(list_part)?;
        return Ok(PostureExpr::InList {
            attr,
            op: PostureOp::NotIn,
            values,
        });
    }
    if let Some((attr_part, list_part)) = split_list_expr(s, " IN ") {
        let attr = parse_attr(attr_part)?;
        let values = parse_list(list_part)?;
        return Ok(PostureExpr::InList {
            attr,
            op: PostureOp::In,
            values,
        });
    }

    // try comparison operators (order matters: >= before >, etc.)
    for (op_str, op) in [
        ("==", PostureOp::Eq),
        ("!=", PostureOp::Ne),
        (">=", PostureOp::Ge),
        ("<=", PostureOp::Le),
        (">", PostureOp::Gt),
        ("<", PostureOp::Lt),
    ] {
        if let Some((attr_part, value_part)) = s.split_once(op_str) {
            let attr = parse_attr(attr_part.trim())?;
            let value = parse_string_value(value_part.trim())?;
            return Ok(PostureExpr::Compare { attr, op, value });
        }
    }

    Err(PostureParseError::InvalidSyntax(format!(
        "could not parse: {}",
        s
    )))
}

fn parse_attr(s: &str) -> Result<PostureAttr, PostureParseError> {
    let s = s.trim();
    let (namespace, name) = s
        .split_once(':')
        .ok_or_else(|| PostureParseError::InvalidAttribute(s.to_string()))?;

    if namespace.is_empty() || name.is_empty() {
        return Err(PostureParseError::InvalidAttribute(s.to_string()));
    }

    Ok(PostureAttr::new(namespace, name))
}

fn parse_string_value(s: &str) -> Result<String, PostureParseError> {
    let s = s.trim();
    // expect single-quoted string
    if s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2 {
        Ok(s[1..s.len() - 1].to_string())
    } else {
        Err(PostureParseError::InvalidValue(format!(
            "expected quoted string: {}",
            s
        )))
    }
}

fn split_list_expr<'a>(s: &'a str, sep: &str) -> Option<(&'a str, &'a str)> {
    let idx = s.find(sep)?;
    Some((&s[..idx], &s[idx + sep.len()..]))
}

fn parse_list(s: &str) -> Result<Vec<String>, PostureParseError> {
    let s = s.trim();
    if !s.starts_with('[') || !s.ends_with(']') {
        return Err(PostureParseError::InvalidValue(format!(
            "expected list: {}",
            s
        )));
    }

    let inner = &s[1..s.len() - 1];
    if inner.trim().is_empty() {
        return Ok(vec![]);
    }

    inner
        .split(',')
        .map(|v| parse_string_value(v.trim()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_equality() {
        let expr: PostureExpr = "node:os == 'linux'".parse().unwrap();
        assert_eq!(
            expr,
            PostureExpr::Compare {
                attr: PostureAttr::new("node", "os"),
                op: PostureOp::Eq,
                value: "linux".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_inequality() {
        let expr: PostureExpr = "node:os != 'windows'".parse().unwrap();
        assert_eq!(
            expr,
            PostureExpr::Compare {
                attr: PostureAttr::new("node", "os"),
                op: PostureOp::Ne,
                value: "windows".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_version_gte() {
        let expr: PostureExpr = "node:tsVersion >= '1.40'".parse().unwrap();
        assert_eq!(
            expr,
            PostureExpr::Compare {
                attr: PostureAttr::new("node", "tsVersion"),
                op: PostureOp::Ge,
                value: "1.40".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_version_lt() {
        let expr: PostureExpr = "node:osVersion < '14.0'".parse().unwrap();
        assert_eq!(
            expr,
            PostureExpr::Compare {
                attr: PostureAttr::new("node", "osVersion"),
                op: PostureOp::Lt,
                value: "14.0".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_in_list() {
        let expr: PostureExpr = "node:os IN ['macos', 'linux']".parse().unwrap();
        assert_eq!(
            expr,
            PostureExpr::InList {
                attr: PostureAttr::new("node", "os"),
                op: PostureOp::In,
                values: vec!["macos".to_string(), "linux".to_string()],
            }
        );
    }

    #[test]
    fn test_parse_not_in_list() {
        let expr: PostureExpr = "node:os NOT IN ['windows']".parse().unwrap();
        assert_eq!(
            expr,
            PostureExpr::InList {
                attr: PostureAttr::new("node", "os"),
                op: PostureOp::NotIn,
                values: vec!["windows".to_string()],
            }
        );
    }

    #[test]
    fn test_parse_is_set() {
        let expr: PostureExpr = "custom:managed IS SET".parse().unwrap();
        assert_eq!(
            expr,
            PostureExpr::Presence {
                attr: PostureAttr::new("custom", "managed"),
                op: PostureOp::IsSet,
            }
        );
    }

    #[test]
    fn test_parse_not_set() {
        let expr: PostureExpr = "custom:tier NOT SET".parse().unwrap();
        assert_eq!(
            expr,
            PostureExpr::Presence {
                attr: PostureAttr::new("custom", "tier"),
                op: PostureOp::NotSet,
            }
        );
    }

    #[test]
    fn test_parse_invalid_no_operator() {
        let result: Result<PostureExpr, _> = "node:os linux".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_no_namespace() {
        let result: Result<PostureExpr, _> = "os == 'linux'".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_unquoted_value() {
        let result: Result<PostureExpr, _> = "node:os == linux".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_ip_country() {
        let expr: PostureExpr = "ip:country IN ['US', 'CA', 'GB']".parse().unwrap();
        assert_eq!(
            expr,
            PostureExpr::InList {
                attr: PostureAttr::new("ip", "country"),
                op: PostureOp::In,
                values: vec!["US".to_string(), "CA".to_string(), "GB".to_string()],
            }
        );
    }
}
