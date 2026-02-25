//! device posture expressions and evaluation

use std::collections::HashMap;
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

/// context for evaluating posture expressions
///
/// holds the attribute values for a node that can be checked against posture conditions
#[derive(Debug, Clone, Default)]
pub struct PostureContext {
    attrs: HashMap<String, String>,
}

impl PostureContext {
    /// create an empty posture context
    pub fn new() -> Self {
        Self::default()
    }

    /// set an attribute value
    pub fn set(&mut self, key: &str, value: impl Into<String>) {
        self.attrs.insert(key.to_string(), value.into());
    }

    /// get an attribute value
    pub fn get(&self, key: &str) -> Option<&str> {
        self.attrs.get(key).map(|s| s.as_str())
    }

    /// check if an attribute is set
    pub fn is_set(&self, key: &str) -> bool {
        self.attrs.contains_key(key)
    }
}

impl PostureExpr {
    /// evaluate this expression against a posture context
    pub fn evaluate(&self, ctx: &PostureContext) -> bool {
        match self {
            PostureExpr::Compare { attr, op, value } => {
                let key = format!("{}:{}", attr.namespace, attr.name);
                match ctx.get(&key) {
                    None => false, // unset attribute always fails
                    Some(actual) => match op {
                        PostureOp::Eq => actual == value,
                        PostureOp::Ne => actual != value,
                        PostureOp::Lt => {
                            compare_versions(actual, value) == std::cmp::Ordering::Less
                        }
                        PostureOp::Le => {
                            compare_versions(actual, value) != std::cmp::Ordering::Greater
                        }
                        PostureOp::Gt => {
                            compare_versions(actual, value) == std::cmp::Ordering::Greater
                        }
                        PostureOp::Ge => {
                            compare_versions(actual, value) != std::cmp::Ordering::Less
                        }
                        _ => false, // In/NotIn/IsSet/NotSet handled elsewhere
                    },
                }
            }
            PostureExpr::InList { attr, op, values } => {
                let key = format!("{}:{}", attr.namespace, attr.name);
                match ctx.get(&key) {
                    None => false, // unset attribute always fails
                    Some(actual) => {
                        let in_list = values.iter().any(|v| v == actual);
                        match op {
                            PostureOp::In => in_list,
                            PostureOp::NotIn => !in_list,
                            _ => false,
                        }
                    }
                }
            }
            PostureExpr::Presence { attr, op } => {
                let key = format!("{}:{}", attr.namespace, attr.name);
                let is_set = ctx.is_set(&key);
                match op {
                    PostureOp::IsSet => is_set,
                    PostureOp::NotSet => !is_set,
                    _ => false,
                }
            }
        }
    }
}

/// compare two version strings
///
/// handles versions like "1.40", "1.40.0", "14.0", etc.
/// uses lexicographic comparison of numeric parts
fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let a_parts: Vec<u64> = a
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse().ok())
        .collect();
    let b_parts: Vec<u64> = b
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse().ok())
        .collect();

    for (a_part, b_part) in a_parts.iter().zip(b_parts.iter()) {
        match a_part.cmp(b_part) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }

    // if all compared parts are equal, longer version is greater
    a_parts.len().cmp(&b_parts.len())
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

    // Phase 2: Evaluation tests

    #[test]
    fn test_evaluate_equality() {
        let expr: PostureExpr = "node:os == 'linux'".parse().unwrap();
        let mut ctx = PostureContext::new();
        ctx.set("node:os", "linux");

        assert!(expr.evaluate(&ctx));

        ctx.set("node:os", "windows");
        assert!(!expr.evaluate(&ctx));
    }

    #[test]
    fn test_evaluate_inequality() {
        let expr: PostureExpr = "node:os != 'windows'".parse().unwrap();
        let mut ctx = PostureContext::new();
        ctx.set("node:os", "linux");

        assert!(expr.evaluate(&ctx));

        ctx.set("node:os", "windows");
        assert!(!expr.evaluate(&ctx));
    }

    #[test]
    fn test_evaluate_version_gte() {
        let expr: PostureExpr = "node:tsVersion >= '1.40'".parse().unwrap();
        let mut ctx = PostureContext::new();

        ctx.set("node:tsVersion", "1.50.0");
        assert!(expr.evaluate(&ctx));

        ctx.set("node:tsVersion", "1.40");
        assert!(expr.evaluate(&ctx));

        ctx.set("node:tsVersion", "1.39.9");
        assert!(!expr.evaluate(&ctx));
    }

    #[test]
    fn test_evaluate_in_list() {
        let expr: PostureExpr = "node:os IN ['macos', 'linux']".parse().unwrap();
        let mut ctx = PostureContext::new();

        ctx.set("node:os", "linux");
        assert!(expr.evaluate(&ctx));

        ctx.set("node:os", "macos");
        assert!(expr.evaluate(&ctx));

        ctx.set("node:os", "windows");
        assert!(!expr.evaluate(&ctx));
    }

    #[test]
    fn test_evaluate_not_in_list() {
        let expr: PostureExpr = "node:os NOT IN ['windows']".parse().unwrap();
        let mut ctx = PostureContext::new();

        ctx.set("node:os", "linux");
        assert!(expr.evaluate(&ctx));

        ctx.set("node:os", "windows");
        assert!(!expr.evaluate(&ctx));
    }

    #[test]
    fn test_evaluate_is_set() {
        let expr: PostureExpr = "custom:managed IS SET".parse().unwrap();
        let mut ctx = PostureContext::new();

        // not set - should fail
        assert!(!expr.evaluate(&ctx));

        // set to any value - should pass
        ctx.set("custom:managed", "true");
        assert!(expr.evaluate(&ctx));
    }

    #[test]
    fn test_evaluate_not_set() {
        let expr: PostureExpr = "custom:tier NOT SET".parse().unwrap();
        let mut ctx = PostureContext::new();

        // not set - should pass
        assert!(expr.evaluate(&ctx));

        // set - should fail
        ctx.set("custom:tier", "prod");
        assert!(!expr.evaluate(&ctx));
    }

    #[test]
    fn test_unset_attribute_fails_even_negative() {
        // per tailscale docs: if attribute is unset, posture doesn't match
        // even with negative conditions like !=
        let expr: PostureExpr = "custom:tier != 'prod'".parse().unwrap();
        let ctx = PostureContext::new();

        // attribute not set - should NOT match (even though it's != 'prod')
        assert!(!expr.evaluate(&ctx));
    }

    #[test]
    fn test_evaluate_multiple_conditions_and() {
        // a posture with multiple conditions uses AND semantics
        let conditions = [
            "node:os IN ['macos', 'linux']"
                .parse::<PostureExpr>()
                .unwrap(),
            "node:tsVersion >= '1.40'".parse::<PostureExpr>().unwrap(),
            "node:tsReleaseTrack == 'stable'"
                .parse::<PostureExpr>()
                .unwrap(),
        ];

        let mut ctx = PostureContext::new();
        ctx.set("node:os", "linux");
        ctx.set("node:tsVersion", "1.50.0");
        ctx.set("node:tsReleaseTrack", "stable");

        // all conditions met - passes
        assert!(conditions.iter().all(|c| c.evaluate(&ctx)));

        // one condition fails - overall fails
        ctx.set("node:tsReleaseTrack", "unstable");
        assert!(!conditions.iter().all(|c| c.evaluate(&ctx)));
    }

    #[test]
    fn test_version_comparison_edge_cases() {
        let expr: PostureExpr = "node:tsVersion >= '1.40'".parse().unwrap();
        let mut ctx = PostureContext::new();

        // exact match
        ctx.set("node:tsVersion", "1.40");
        assert!(expr.evaluate(&ctx));

        // with patch version
        ctx.set("node:tsVersion", "1.40.0");
        assert!(expr.evaluate(&ctx));

        // with suffix (like beta)
        ctx.set("node:tsVersion", "1.40.0-beta1");
        assert!(expr.evaluate(&ctx));

        // major version bump
        ctx.set("node:tsVersion", "2.0");
        assert!(expr.evaluate(&ctx));
    }
}
