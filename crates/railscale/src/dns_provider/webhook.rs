//! generic webhook dns provider for ACME dns-01 challenges.
//!
//! POST's record changes as JSON to a user-configured URL.
//! optionally signs requests with HMAC-SHA256.

use reqwest::Client;
use secrecy::{ExposeSecret, SecretString};

use super::{DnsProvider, DnsProviderError};

pub struct WebhookProvider {
    client: Client,
    url: String,
    secret: Option<SecretString>,
}

impl WebhookProvider {
    pub fn new(url: String, secret: Option<SecretString>) -> Self {
        Self {
            client: Client::new(),
            url,
            secret,
        }
    }

    /// compute HMAC-SHA256 signature of the request body
    fn sign(&self, body: &[u8]) -> Option<String> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let secret = self.secret.as_ref()?;
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.expose_secret().as_bytes()).ok()?;
        mac.update(body);
        let result = mac.finalize();
        Some(hex::encode(result.into_bytes()))
    }
}

impl DnsProvider for WebhookProvider {
    async fn set_txt_record(
        &self,
        name: String,
        value: String,
    ) -> Result<String, DnsProviderError> {
        let payload = serde_json::json!({
            "action": "set",
            "name": name,
            "value": value,
        });
        let body = serde_json::to_vec(&payload).expect("json serialisation");

        let mut req = self.client.post(&self.url).json(&payload);
        if let Some(sig) = self.sign(&body) {
            req = req.header("X-Signature", sig);
        }

        let resp = req.send().await?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(DnsProviderError::Provider(format!("webhook: {text}")));
        }

        // use name as record id for webhooks
        Ok(name)
    }

    async fn clear_txt_record(
        &self,
        name: String,
        _record_id: String,
    ) -> Result<(), DnsProviderError> {
        let payload = serde_json::json!({
            "action": "clear",
            "name": name,
        });
        let body = serde_json::to_vec(&payload).expect("json serialisation");

        let mut req = self.client.post(&self.url).json(&payload);
        if let Some(sig) = self.sign(&body) {
            req = req.header("X-Signature", sig);
        }

        let resp = req.send().await?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(DnsProviderError::Provider(format!("webhook clear: {text}")));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_produces_hex_hmac() {
        let provider = WebhookProvider::new(
            "https://example.com/dns".to_string(),
            Some(SecretString::from("test-secret")),
        );
        let sig = provider.sign(b"hello");
        assert!(sig.is_some());
        // hmac-sha256 output is 64 hex chars
        assert_eq!(sig.unwrap().len(), 64);
    }

    #[test]
    fn sign_returns_none_without_secret() {
        let provider = WebhookProvider::new("https://example.com/dns".to_string(), None);
        assert!(provider.sign(b"hello").is_none());
    }

    #[tokio::test]
    async fn set_txt_record_posts_to_webhook() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers};

        let mock_server = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/"))
            .and(matchers::body_json(serde_json::json!({
                "action": "set",
                "name": "_acme-challenge.node.example.com",
                "value": "challenge-token-123",
            })))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider = WebhookProvider::new(mock_server.uri(), None);
        let id = DnsProvider::set_txt_record(
            &provider,
            "_acme-challenge.node.example.com".into(),
            "challenge-token-123".into(),
        )
        .await
        .unwrap();

        assert_eq!(id, "_acme-challenge.node.example.com");
    }

    #[tokio::test]
    async fn clear_txt_record_posts_clear_action() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers};

        let mock_server = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/"))
            .and(matchers::body_json(serde_json::json!({
                "action": "clear",
                "name": "_acme-challenge.node.example.com",
            })))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider = WebhookProvider::new(mock_server.uri(), None);
        DnsProvider::clear_txt_record(
            &provider,
            "_acme-challenge.node.example.com".into(),
            "_acme-challenge.node.example.com".into(),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn set_txt_record_includes_signature_header() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers};

        let mock_server = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::header_exists("X-Signature"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider =
            WebhookProvider::new(mock_server.uri(), Some(SecretString::from("my-secret")));
        DnsProvider::set_txt_record(&provider, "name".into(), "val".into())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn set_txt_record_returns_error_on_failure() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers};

        let mock_server = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider = WebhookProvider::new(mock_server.uri(), None);
        let err = DnsProvider::set_txt_record(&provider, "name".into(), "val".into())
            .await
            .unwrap_err();

        assert!(err.to_string().contains("webhook: internal error"));
    }
}
