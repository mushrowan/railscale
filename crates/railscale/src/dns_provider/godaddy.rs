//! godaddy dns provider for ACME dns-01 challenges.

use reqwest::Client;
use secrecy::{ExposeSecret, SecretString};

use super::{DnsProvider, DnsProviderError};

const GODADDY_API: &str = "https://api.godaddy.com/v1";

pub struct GodaddyProvider {
    client: Client,
    api_key: SecretString,
    api_secret: SecretString,
    /// apex domain from base_domain config
    domain: String,
    base_url: String,
}

impl GodaddyProvider {
    pub fn new(api_key: SecretString, api_secret: SecretString, base_domain: String) -> Self {
        Self {
            client: Client::new(),
            api_key,
            api_secret,
            domain: base_domain,
            base_url: GODADDY_API.to_string(),
        }
    }

    #[cfg(test)]
    fn with_base_url(mut self, base_url: String) -> Self {
        self.base_url = base_url;
        self
    }

    /// build the sso-key authorization header value
    fn auth_header(&self) -> String {
        format!(
            "sso-key {}:{}",
            self.api_key.expose_secret(),
            self.api_secret.expose_secret()
        )
    }

    /// derive the relative record name from a full fqdn.
    ///
    /// e.g. for fqdn `_acme-challenge.node.example.com` and domain `example.com`,
    /// returns `_acme-challenge.node`
    fn relative_name(&self, fqdn: &str) -> String {
        let fqdn = fqdn.trim_end_matches('.');
        let domain = self.domain.trim_end_matches('.');
        if let Some(prefix) = fqdn.strip_suffix(domain) {
            prefix.trim_end_matches('.').to_string()
        } else {
            fqdn.to_string()
        }
    }
}

impl DnsProvider for GodaddyProvider {
    async fn set_txt_record(
        &self,
        name: String,
        value: String,
    ) -> Result<String, DnsProviderError> {
        let record_name = self.relative_name(&name);
        let url = format!(
            "{}/domains/{}/records/TXT/{}",
            self.base_url, self.domain, record_name
        );

        let resp = self
            .client
            .put(&url)
            .header("Authorization", self.auth_header())
            .json(&serde_json::json!([{
                "data": value,
                "ttl": 600,
            }]))
            .send()
            .await?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(DnsProviderError::Provider(format!("godaddy: {body}")));
        }

        // godaddy doesn't return a record id — use name as identifier
        Ok(record_name)
    }

    async fn clear_txt_record(
        &self,
        name: String,
        _record_id: String,
    ) -> Result<(), DnsProviderError> {
        let record_name = self.relative_name(&name);
        let url = format!(
            "{}/domains/{}/records/TXT/{}",
            self.base_url, self.domain, record_name
        );

        // godaddy doesn't have a DELETE for individual records —
        // set an empty array to clear all TXT records for this name
        let resp = self
            .client
            .put(&url)
            .header("Authorization", self.auth_header())
            .json(&serde_json::json!([]))
            .send()
            .await?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(DnsProviderError::Provider(format!(
                "godaddy delete: {body}"
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers};

    fn test_provider(base_url: &str) -> GodaddyProvider {
        GodaddyProvider::new(
            SecretString::from("test-key"),
            SecretString::from("test-secret"),
            "example.com".to_string(),
        )
        .with_base_url(base_url.to_string())
    }

    #[test]
    fn relative_name_strips_domain() {
        let provider = test_provider("http://unused");
        assert_eq!(
            provider.relative_name("_acme-challenge.node.example.com"),
            "_acme-challenge.node"
        );
    }

    #[test]
    fn relative_name_handles_trailing_dot() {
        let mut provider = test_provider("http://unused");
        provider.domain = "example.com.".to_string();
        assert_eq!(
            provider.relative_name("_acme-challenge.node.example.com."),
            "_acme-challenge.node"
        );
    }

    #[test]
    fn relative_name_passthrough_when_no_match() {
        let provider = test_provider("http://unused");
        assert_eq!(
            provider.relative_name("_acme-challenge.node.other.org"),
            "_acme-challenge.node.other.org"
        );
    }

    #[tokio::test]
    async fn set_txt_record_puts_to_godaddy() {
        let mock_server = MockServer::start().await;
        Mock::given(matchers::method("PUT"))
            .and(matchers::path(
                "/domains/example.com/records/TXT/_acme-challenge.node",
            ))
            .and(matchers::header(
                "Authorization",
                "sso-key test-key:test-secret",
            ))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider = test_provider(&mock_server.uri());
        let id = DnsProvider::set_txt_record(
            &provider,
            "_acme-challenge.node.example.com".into(),
            "token123".into(),
        )
        .await
        .unwrap();

        assert_eq!(id, "_acme-challenge.node");
    }

    #[tokio::test]
    async fn clear_txt_record_puts_empty_array() {
        let mock_server = MockServer::start().await;
        Mock::given(matchers::method("PUT"))
            .and(matchers::path(
                "/domains/example.com/records/TXT/_acme-challenge.node",
            ))
            .and(matchers::body_json(serde_json::json!([])))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider = test_provider(&mock_server.uri());
        DnsProvider::clear_txt_record(
            &provider,
            "_acme-challenge.node.example.com".into(),
            "_acme-challenge.node".into(),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn set_txt_record_returns_error_on_failure() {
        let mock_server = MockServer::start().await;
        Mock::given(matchers::method("PUT"))
            .respond_with(ResponseTemplate::new(422).set_body_string("invalid record"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider = test_provider(&mock_server.uri());
        let err = DnsProvider::set_txt_record(&provider, "name".into(), "val".into())
            .await
            .unwrap_err();

        assert!(err.to_string().contains("godaddy: invalid record"));
    }
}
