//! html templates for user-facing pages.
//!
//! consolidated here to avoid inline html in handlers.

/// registration page shown when OIDC is not configured.
pub fn manual_registration_page(registration_id: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Complete Registration</title>
    <style>
        body {{ font-family: system-ui, -apple-system, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }}
        h1 {{ color: #333; }}
        code {{ background: #f4f4f4; padding: 2px 8px; border-radius: 4px; font-size: 14px; }}
        .command {{ background: #1a1a2e; color: #eee; padding: 15px; border-radius: 8px; margin: 20px 0; }}
        .command code {{ background: transparent; color: #4ade80; }}
    </style>
</head>
<body>
    <h1>Complete Your Registration</h1>
    <p>To complete the registration of your device, run the following command on the server:</p>
    <div class="command">
        <code>railscale nodes approve {registration_id}</code>
    </div>
    <p>After running the command, the Tailscale client will automatically connect.</p>
    <p><small>Registration ID: <code>{registration_id}</code></small></p>
</body>
</html>"#
    )
}

/// success page shown after OIDC authentication completes.
pub const OIDC_SUCCESS_PAGE: &str = r#"<!DOCTYPE html>
<html>
<head><title>Authentication Successful</title></head>
<body>
<h1>Authentication Successful</h1>
<p>You have successfully authenticated. You can close this window and return to the Tailscale client.</p>
</body>
</html>"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manual_registration_page_contains_id() {
        let html = manual_registration_page("test-reg-id-123");
        assert!(html.contains("test-reg-id-123"));
        assert!(html.contains("Complete Your Registration"));
        assert!(html.contains("railscale nodes approve"));
    }

    #[test]
    fn test_oidc_success_page_is_valid_html() {
        assert!(OIDC_SUCCESS_PAGE.contains("Authentication Successful"));
        assert!(OIDC_SUCCESS_PAGE.contains("</html>"));
    }
}
