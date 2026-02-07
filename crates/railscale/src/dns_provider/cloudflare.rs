//! cloudflare dns provider for ACME dns-01 challenges.

use reqwest::Client;
use secrecy::{ExposeSecret, SecretString};

use super::{DnsProvider, DnsProviderError};

const CLOUDFLARE_API: &str = "https://api.cloudflare.com/client/v4";

pub struct CloudflareProvider {
    client: Client,
    api_token: SecretString,
    zone_id: String,
    base_url: String,
}

impl CloudflareProvider {
    pub fn new(api_token: SecretString, zone_id: String) -> Self {
        Self {
            client: Client::new(),
            api_token,
            zone_id,
            base_url: CLOUDFLARE_API.to_string(),
        }
    }

    #[cfg(test)]
    fn with_base_url(mut self, base_url: String) -> Self {
        self.base_url = base_url;
        self
    }
}

impl DnsProvider for CloudflareProvider {
    async fn set_txt_record(
        &self,
        name: String,
        value: String,
    ) -> Result<String, DnsProviderError> {
        let url = format!("{}/zones/{}/dns_records", self.base_url, self.zone_id);

        let resp = self
            .client
            .post(&url)
            .bearer_auth(self.api_token.expose_secret())
            .json(&serde_json::json!({
                "type": "TXT",
                "name": name,
                "content": value,
                "ttl": 120,
            }))
            .send()
            .await?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(DnsProviderError::Provider(format!("cloudflare: {body}")));
        }

        let body: serde_json::Value = resp.json().await?;
        let id = body["result"]["id"]
            .as_str()
            .ok_or_else(|| DnsProviderError::Provider("missing record id in response".into()))?
            .to_string();

        Ok(id)
    }

    async fn clear_txt_record(
        &self,
        _name: String,
        record_id: String,
    ) -> Result<(), DnsProviderError> {
        let url = format!(
            "{}/zones/{}/dns_records/{}",
            self.base_url, self.zone_id, record_id
        );

        let resp = self
            .client
            .delete(&url)
            .bearer_auth(self.api_token.expose_secret())
            .send()
            .await?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(DnsProviderError::Provider(format!(
                "cloudflare delete: {body}"
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers};

    fn test_provider(base_url: &str) -> CloudflareProvider {
        CloudflareProvider::new(SecretString::from("test-token"), "zone123".to_string())
            .with_base_url(base_url.to_string())
    }

    #[tokio::test]
    async fn set_txt_record_creates_record() {
        let mock_server = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/zones/zone123/dns_records"))
            .and(matchers::header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "result": { "id": "record-abc" }
            })))
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

        assert_eq!(id, "record-abc");
    }

    #[tokio::test]
    async fn clear_txt_record_deletes_record() {
        let mock_server = MockServer::start().await;
        Mock::given(matchers::method("DELETE"))
            .and(matchers::path("/zones/zone123/dns_records/record-abc"))
            .and(matchers::header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider = test_provider(&mock_server.uri());
        DnsProvider::clear_txt_record(
            &provider,
            "_acme-challenge.node.example.com".into(),
            "record-abc".into(),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn set_txt_record_returns_error_on_api_failure() {
        let mock_server = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .respond_with(ResponseTemplate::new(403).set_body_string("forbidden"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider = test_provider(&mock_server.uri());
        let err = DnsProvider::set_txt_record(&provider, "name".into(), "val".into())
            .await
            .unwrap_err();

        assert!(err.to_string().contains("cloudflare: forbidden"));
    }
}
