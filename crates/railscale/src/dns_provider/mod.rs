//! dns provider trait and implementations for ACME dns-01 challenges.
//!
//! supports cloudflare, godaddy, and a generic webhook backend.

mod cloudflare;
mod godaddy;
mod webhook;

use railscale_types::DnsProviderConfig;

/// errors from dns provider operations.
#[derive(Debug, thiserror::Error)]
pub enum DnsProviderError {
    /// http request failed
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    /// provider returned an error response
    #[error("provider error: {0}")]
    Provider(String),
}

/// trait for dns providers that can create/delete TXT records.
///
/// used by `/machine/set-dns` to fulfil ACME dns-01 challenges for `tailscale cert`.
/// takes owned strings to avoid lifetime issues with dynamic dispatch.
pub trait DnsProvider: Send + Sync {
    /// create a TXT record, returning a provider-specific record id for later cleanup
    fn set_txt_record(
        &self,
        name: String,
        value: String,
    ) -> impl std::future::Future<Output = Result<String, DnsProviderError>> + Send;

    /// delete a previously created TXT record by its provider record id
    fn clear_txt_record(
        &self,
        name: String,
        record_id: String,
    ) -> impl std::future::Future<Output = Result<(), DnsProviderError>> + Send;
}

/// construct a boxed dns provider from config.
pub fn from_config(config: &DnsProviderConfig, base_domain: &str) -> Box<dyn DnsProviderBoxed> {
    match config {
        DnsProviderConfig::Cloudflare { api_token, zone_id } => Box::new(
            cloudflare::CloudflareProvider::new(api_token.clone(), zone_id.clone()),
        ),
        DnsProviderConfig::Godaddy {
            api_key,
            api_secret,
        } => Box::new(godaddy::GodaddyProvider::new(
            api_key.clone(),
            api_secret.clone(),
            base_domain.to_string(),
        )),
        DnsProviderConfig::Webhook { url, secret } => {
            Box::new(webhook::WebhookProvider::new(url.clone(), secret.clone()))
        }
    }
}

/// object-safe wrapper for DnsProvider, used for dynamic dispatch
pub trait DnsProviderBoxed: Send + Sync {
    /// create a TXT record
    fn set_txt_record(
        &self,
        name: String,
        value: String,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<String, DnsProviderError>> + Send + '_>,
    >;

    /// delete a TXT record
    fn clear_txt_record(
        &self,
        name: String,
        record_id: String,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), DnsProviderError>> + Send + '_>,
    >;
}

impl<T: DnsProvider> DnsProviderBoxed for T {
    fn set_txt_record(
        &self,
        name: String,
        value: String,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<String, DnsProviderError>> + Send + '_>,
    > {
        Box::pin(DnsProvider::set_txt_record(self, name, value))
    }

    fn clear_txt_record(
        &self,
        name: String,
        record_id: String,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), DnsProviderError>> + Send + '_>,
    > {
        Box::pin(DnsProvider::clear_txt_record(self, name, record_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    #[test]
    fn from_config_creates_cloudflare_provider() {
        let config = DnsProviderConfig::Cloudflare {
            api_token: SecretString::from("test-token"),
            zone_id: "zone123".to_string(),
        };
        let _provider = from_config(&config, "example.com");
    }

    #[test]
    fn from_config_creates_godaddy_provider() {
        let config = DnsProviderConfig::Godaddy {
            api_key: SecretString::from("test-key"),
            api_secret: SecretString::from("test-secret"),
        };
        let _provider = from_config(&config, "example.com");
    }

    #[test]
    fn from_config_creates_webhook_provider() {
        let config = DnsProviderConfig::Webhook {
            url: "https://example.com/dns".to_string(),
            secret: Some(SecretString::from("webhook-secret")),
        };
        let _provider = from_config(&config, "example.com");
    }
}
