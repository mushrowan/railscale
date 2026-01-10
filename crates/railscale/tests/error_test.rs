//! tests for error handling with color-eyre
//!
//! these tests verify that error context is properly preserved and displayed

use std::io;

/// test that error context chains are properly preserved
#[test]
fn test_error_context_chain_preserved() {
    use color_eyre::eyre::{Context, Result};

    fn inner_operation() -> Result<(), io::Error> {
        Err(io::Error::new(io::ErrorKind::NotFound, "file not found"))
    }

    fn middle_operation() -> Result<()> {
        inner_operation().context("failed to read config file")
    }

    fn outer_operation() -> Result<()> {
        middle_operation().context("failed to initialize application")
    }

    let err = outer_operation().unwrap_err();
    let err_string = format!("{err:?}");

    // verify the error chain contains all context messages
    assert!(
        err_string.contains("failed to initialize application"),
        "error should contain outer context: {err_string}"
    );
    assert!(
        err_string.contains("failed to read config file"),
        "error should contain middle context: {err_string}"
    );
    assert!(
        err_string.contains("file not found"),
        "error should contain root cause: {err_string}"
    );
}

/// test that eyre::bail! macro works correctly
#[test]
fn test_eyre_bail_macro() {
    use color_eyre::eyre::{Result, bail};

    fn operation_that_fails() -> Result<()> {
        bail!("something went wrong: {}", "invalid input");
    }

    let err = operation_that_fails().unwrap_err();
    assert!(
        err.to_string()
            .contains("something went wrong: invalid input"),
        "bail! should create error with message: {err}"
    );
}

/// test that eyre::ensure! macro works correctly
#[test]
fn test_eyre_ensure_macro() {
    use color_eyre::eyre::{Result, ensure};

    fn validate_positive(n: i32) -> Result<()> {
        ensure!(n > 0, "number must be positive, got {n}");
        Ok(())
    }

    // should pass
    assert!(validate_positive(5).is_ok());

    // should fail with context
    let err = validate_positive(-1).unwrap_err();
    assert!(
        err.to_string().contains("number must be positive, got -1"),
        "ensure! should create error with message: {err}"
    );
}
