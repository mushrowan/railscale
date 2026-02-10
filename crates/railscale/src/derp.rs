//! derp map generation for relay coordination.

use railscale_proto::{DerpMap, DerpNode, DerpRegion};
use railscale_types::{Config, DerpConfig};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use thiserror::Error;

/// parse a hostname to extract ipv4/ipv6 fields if it's already an ip address.
/// this prevents the client from doing unnecessary dns lookups.
fn parse_ip_fields(host: &str) -> (Option<String>, Option<String>) {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => (Some(v4.to_string()), None),
        Ok(IpAddr::V6(v6)) => (None, Some(v6.to_string())),
        Err(_) => (None, None), // It's a hostname, let client resolve
    }
}

/// errors that can occur when loading derp maps.
#[derive(Debug, Error)]
pub enum DerpError {
    /// http request failed.
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    /// json parsing failed.
    #[error("JSON parsing failed: {0}")]
    Json(#[from] serde_json::Error),

    /// yaml parsing failed.
    #[error("YAML parsing failed: {0}")]
    Yaml(#[from] serde_yaml::Error),

    /// file i/o failed.
    #[error("File I/O failed: {0}")]
    Io(#[from] std::io::Error),

    /// response too large.
    #[error("DERP map response too large: {0} bytes (max {MAX_DERP_MAP_SIZE})")]
    TooLarge(usize),
}

/// max size for a derp map response (1 MiB)
const MAX_DERP_MAP_SIZE: usize = 1024 * 1024;

/// fetch a derp map from a url (expects json format).
pub async fn fetch_derp_map_from_url(url: &str) -> Result<DerpMap, DerpError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let response = client.get(url).send().await?;

    // check content-length if available before reading body
    if let Some(len) = response.content_length()
        && len as usize > MAX_DERP_MAP_SIZE
    {
        return Err(DerpError::TooLarge(len as usize));
    }

    let bytes = response.bytes().await?;
    if bytes.len() > MAX_DERP_MAP_SIZE {
        return Err(DerpError::TooLarge(bytes.len()));
    }

    let derp_map: DerpMap = serde_json::from_slice(&bytes)?;
    Ok(derp_map)
}

/// load a derp map from a local file path (yaml format, like headscale).
pub fn load_derp_map_from_path(path: &Path) -> Result<DerpMap, DerpError> {
    let contents = std::fs::read_to_string(path)?;
    let derp_map: DerpMap = serde_yaml::from_str(&contents)?;
    Ok(derp_map)
}

/// merge multiple derp maps. later maps override earlier ones for the same region id.
/// regions set to null/none in later maps are removed.
pub fn merge_derp_maps(maps: &[DerpMap]) -> DerpMap {
    let mut regions = HashMap::new();

    for map in maps {
        for (id, region) in &map.regions {
            regions.insert(*id, region.clone());
        }
    }

    DerpMap {
        regions,
        omit_default_regions: false,
    }
}

/// load external derp maps from configured URL and/or local file path.
///
/// if both `derp_map_url` and `derp_map_path` are set, both are loaded and
/// merged (path overrides url for the same region id). returns None if neither
/// is configured.
pub async fn load_external_derp_maps(config: &DerpConfig) -> Result<Option<DerpMap>, DerpError> {
    let mut maps = Vec::new();

    // load from URL first (lower priority)
    if let Some(ref url) = config.derp_map_url {
        match fetch_derp_map_from_url(url).await {
            Ok(map) => {
                tracing::info!(url, regions = map.regions.len(), "loaded derp map from URL");
                maps.push(map);
            }
            Err(e) => {
                tracing::warn!(url, error = %e, "failed to fetch derp map from URL");
            }
        }
    }

    // load from file path (higher priority, overrides URL)
    if let Some(ref path) = config.derp_map_path {
        match load_derp_map_from_path(path) {
            Ok(map) => {
                tracing::info!(
                    ?path,
                    regions = map.regions.len(),
                    "loaded derp map from file"
                );
                maps.push(map);
            }
            Err(e) => {
                tracing::warn!(?path, error = %e, "failed to load derp map from file");
            }
        }
    }

    if maps.is_empty() {
        Ok(None)
    } else {
        Ok(Some(merge_derp_maps(&maps)))
    }
}

/// spawn a background task that periodically refreshes the derp map from
/// external sources (URL/path) and merges with the base map.
///
/// the base map typically contains the embedded DERP region. external regions
/// are merged on top, with later sources overriding earlier ones.
pub fn spawn_derp_map_updater(
    shared_map: std::sync::Arc<tokio::sync::RwLock<DerpMap>>,
    config: DerpConfig,
    base_map: DerpMap,
) {
    let interval_secs = config.update_frequency_secs.max(1);

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));

        loop {
            interval.tick().await;

            match load_external_derp_maps(&config).await {
                Ok(Some(external)) => {
                    let merged = merge_derp_maps(&[base_map.clone(), external]);
                    let mut map = shared_map.write().await;
                    *map = merged;
                    tracing::debug!(
                        regions = map.regions.len(),
                        "refreshed derp map from external sources"
                    );
                }
                Ok(None) => {
                    // no external sources configured, nothing to do
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to refresh derp map");
                }
            }
        }
    });
}

/// generate the derp map for clients.
pub fn generate_derp_map(config: &Config) -> DerpMap {
    let mut map = DerpMap {
        regions: HashMap::new(),
        omit_default_regions: false,
    };

    // if embedded derp is enabled, add it to the map
    if config.derp.embedded_derp.enabled {
        if let Some(runtime) = &config.derp.embedded_derp.runtime {
            let region_id = config.derp.embedded_derp.region_id;
            let host_name = runtime.advertise_host.clone();

            // if host_name is an ip address, populate ipv4/ipv6 to avoid dns lookups
            let (ipv4, ipv6) = parse_ip_fields(&host_name);

            let region = DerpRegion {
                region_id,
                region_code: "embedded".to_string(),
                region_name: config.derp.embedded_derp.region_name.clone(),
                nodes: vec![DerpNode {
                    name: format!("{}a", region_id),
                    region_id,
                    host_name,
                    ipv4,
                    ipv6,
                    stun_port: -1,
                    stun_only: false,
                    derp_port: runtime.advertise_port as i32,
                    can_port_80: false,
                    cert_name: Some(format!("sha256-raw:{}", runtime.cert_fingerprint)),
                    insecure_for_tests: false,
                }],
            };
            map.omit_default_regions = true;
            map.regions.insert(region_id, region);
        } else {
            tracing::warn!("embedded DERP enabled but runtime details were not initialized");
        }
    }

    // if we have no regions, add a default one (e.g., tailscale's new york region)
    if map.regions.is_empty() {
        map.regions.insert(
            1,
            DerpRegion {
                region_id: 1,
                region_code: "nyc".to_string(),
                region_name: "New York City".to_string(),
                nodes: vec![DerpNode {
                    name: "1a".to_string(),
                    region_id: 1,
                    host_name: "derp1a.tailscale.com".to_string(),
                    ipv4: None,
                    ipv6: None,
                    stun_port: 3478,
                    stun_only: false,
                    derp_port: 443,
                    can_port_80: true,
                    cert_name: None,
                    insecure_for_tests: false,
                }],
            },
        );
    }

    map
}

#[cfg(test)]
mod tests {
    use super::*;

    /// test parsing tailscale's official derp map json format.
    /// the format uses pascalcase keys (e.g., "regions", "regionid", "stunport").
    #[test]
    fn test_parse_tailscale_derp_map_format() {
        // this is a minimal example of tailscale's derp map format
        let tailscale_json = r#"{
            "Regions": {
                "1": {
                    "RegionID": 1,
                    "RegionCode": "nyc",
                    "RegionName": "New York City",
                    "Nodes": [
                        {
                            "Name": "1a",
                            "RegionID": 1,
                            "HostName": "derp1a.tailscale.com",
                            "IPv4": "23.92.19.175",
                            "IPv6": "2604:a880:1:20::4e2:6001",
                            "STUNPort": 3478,
                            "STUNOnly": false,
                            "DERPPort": 443,
                            "CanPort80": true
                        }
                    ]
                }
            }
        }"#;

        // parse the tailscale format into our derpmap
        let derp_map: DerpMap =
            serde_json::from_str(tailscale_json).expect("Should parse Tailscale DERP map format");

        // verify the parsed data
        assert_eq!(derp_map.regions.len(), 1);
        let region = derp_map.regions.get(&1).expect("Region 1 should exist");
        assert_eq!(region.region_id, 1);
        assert_eq!(region.region_code, "nyc");
        assert_eq!(region.region_name, "New York City");
        assert_eq!(region.nodes.len(), 1);

        let node = &region.nodes[0];
        assert_eq!(node.name, "1a");
        assert_eq!(node.host_name, "derp1a.tailscale.com");
        assert_eq!(node.ipv4, Some("23.92.19.175".to_string()));
        assert_eq!(node.stun_port, 3478);
        assert!(node.can_port_80);
    }

    /// test that we can fetch a derp map from a url.
    #[tokio::test]
    async fn test_fetch_derp_map_from_url() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        let derp_json = r#"{
            "Regions": {
                "1": {
                    "RegionID": 1,
                    "RegionCode": "nyc",
                    "RegionName": "New York City",
                    "Nodes": [
                        {
                            "Name": "1a",
                            "RegionID": 1,
                            "HostName": "derp1a.example.com",
                            "STUNPort": 3478
                        }
                    ]
                }
            }
        }"#;

        Mock::given(method("GET"))
            .and(path("/derpmap/default"))
            .respond_with(ResponseTemplate::new(200).set_body_string(derp_json))
            .mount(&mock_server)
            .await;

        let url = format!("{}/derpmap/default", mock_server.uri());
        let derp_map = fetch_derp_map_from_url(&url)
            .await
            .expect("Should fetch and parse DERP map");

        assert_eq!(derp_map.regions.len(), 1);
        let region = derp_map.regions.get(&1).unwrap();
        assert_eq!(region.region_code, "nyc");
    }

    /// test loading a derp map from a local yaml file.
    #[test]
    fn test_load_derp_map_from_yaml() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // yaml uses lowercase field names as per headscale's format
        let yaml_content = r#"
Regions:
  900:
    RegionID: 900
    RegionCode: custom
    RegionName: Custom Region
    Nodes:
      - Name: 900a
        RegionID: 900
        HostName: derp.example.com
        STUNPort: 3478
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(yaml_content.as_bytes()).unwrap();

        let derp_map =
            load_derp_map_from_path(temp_file.path()).expect("Should load DERP map from YAML file");

        assert_eq!(derp_map.regions.len(), 1);
        let region = derp_map.regions.get(&900).unwrap();
        assert_eq!(region.region_code, "custom");
    }

    /// test that oversized responses are rejected.
    #[tokio::test]
    async fn test_fetch_derp_map_rejects_oversized_response() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        // respond with a body larger than MAX_DERP_MAP_SIZE
        let big_body = "x".repeat(super::MAX_DERP_MAP_SIZE + 1);

        Mock::given(method("GET"))
            .and(path("/derpmap/big"))
            .respond_with(ResponseTemplate::new(200).set_body_string(big_body))
            .mount(&mock_server)
            .await;

        let url = format!("{}/derpmap/big", mock_server.uri());
        let result = fetch_derp_map_from_url(&url).await;
        assert!(result.is_err(), "oversized response should be rejected");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("too large"),
            "error should mention size: {err}"
        );
    }

    /// test loading external derp map from a local yaml file via config
    #[tokio::test]
    async fn test_load_external_derp_maps_from_path() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let yaml_content = r#"
Regions:
  800:
    RegionID: 800
    RegionCode: ext
    RegionName: External Region
    Nodes:
      - Name: 800a
        RegionID: 800
        HostName: derp-ext.example.com
        STUNPort: 3478
"#;
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(yaml_content.as_bytes()).unwrap();

        let config = DerpConfig {
            derp_map_url: None,
            derp_map_path: Some(temp_file.path().to_path_buf()),
            update_frequency_secs: 3600,
            ..Default::default()
        };

        let result = load_external_derp_maps(&config).await.unwrap();
        assert!(result.is_some(), "should load derp map from path");
        let map = result.unwrap();
        assert!(map.regions.contains_key(&800));
        assert_eq!(map.regions.get(&800).unwrap().region_code, "ext");
    }

    /// test loading external derp map from url via config
    #[tokio::test]
    async fn test_load_external_derp_maps_from_url() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        let derp_json = r#"{
            "Regions": {
                "700": {
                    "RegionID": 700,
                    "RegionCode": "remote",
                    "RegionName": "Remote Region",
                    "Nodes": [{
                        "Name": "700a",
                        "RegionID": 700,
                        "HostName": "derp-remote.example.com",
                        "STUNPort": 3478
                    }]
                }
            }
        }"#;

        Mock::given(method("GET"))
            .and(path("/derpmap"))
            .respond_with(ResponseTemplate::new(200).set_body_string(derp_json))
            .mount(&mock_server)
            .await;

        let config = DerpConfig {
            derp_map_url: Some(format!("{}/derpmap", mock_server.uri())),
            derp_map_path: None,
            update_frequency_secs: 3600,
            ..Default::default()
        };

        let result = load_external_derp_maps(&config).await.unwrap();
        assert!(result.is_some());
        let map = result.unwrap();
        assert!(map.regions.contains_key(&700));
        assert_eq!(map.regions.get(&700).unwrap().region_code, "remote");
    }

    /// test that no external sources returns None
    #[tokio::test]
    async fn test_load_external_derp_maps_none_configured() {
        let config = DerpConfig {
            derp_map_url: None,
            derp_map_path: None,
            update_frequency_secs: 3600,
            ..Default::default()
        };

        let result = load_external_derp_maps(&config).await.unwrap();
        assert!(result.is_none());
    }

    /// test that url and path maps are merged (path overrides url)
    #[tokio::test]
    async fn test_load_external_derp_maps_merges_url_and_path() {
        use std::io::Write;
        use tempfile::NamedTempFile;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        // url provides region 600
        let url_json = r#"{
            "Regions": {
                "600": {
                    "RegionID": 600,
                    "RegionCode": "url-region",
                    "RegionName": "URL Region",
                    "Nodes": [{
                        "Name": "600a",
                        "RegionID": 600,
                        "HostName": "url.example.com",
                        "STUNPort": 3478
                    }]
                }
            }
        }"#;

        Mock::given(method("GET"))
            .and(path("/derpmap"))
            .respond_with(ResponseTemplate::new(200).set_body_string(url_json))
            .mount(&mock_server)
            .await;

        // path provides region 601 and overrides 600
        let yaml_content = r#"
Regions:
  600:
    RegionID: 600
    RegionCode: path-override
    RegionName: Path Override
    Nodes:
      - Name: 600a
        RegionID: 600
        HostName: path.example.com
        STUNPort: 3478
  601:
    RegionID: 601
    RegionCode: path-only
    RegionName: Path Only
    Nodes:
      - Name: 601a
        RegionID: 601
        HostName: path-only.example.com
        STUNPort: 3478
"#;
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(yaml_content.as_bytes()).unwrap();

        let config = DerpConfig {
            derp_map_url: Some(format!("{}/derpmap", mock_server.uri())),
            derp_map_path: Some(temp_file.path().to_path_buf()),
            update_frequency_secs: 3600,
            ..Default::default()
        };

        let result = load_external_derp_maps(&config).await.unwrap();
        assert!(result.is_some());
        let map = result.unwrap();

        // region 600 should be from path (overrides url)
        assert_eq!(map.regions.get(&600).unwrap().region_code, "path-override");
        // region 601 from path only
        assert_eq!(map.regions.get(&601).unwrap().region_code, "path-only");
    }

    /// test the periodic updater writes merged map to shared state
    #[tokio::test]
    async fn test_spawn_derp_map_updater_refreshes() {
        use std::io::Write;
        use std::sync::Arc;
        use tempfile::NamedTempFile;
        use tokio::sync::RwLock;

        // create a yaml file for the updater to read
        let yaml_content = r#"
Regions:
  500:
    RegionID: 500
    RegionCode: updated
    RegionName: Updated Region
    Nodes:
      - Name: 500a
        RegionID: 500
        HostName: updated.example.com
        STUNPort: 3478
"#;
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(yaml_content.as_bytes()).unwrap();

        // base map has region 1 (embedded)
        let base_map = DerpMap {
            regions: [(
                1,
                DerpRegion {
                    region_id: 1,
                    region_code: "embedded".to_string(),
                    region_name: "Embedded".to_string(),
                    nodes: vec![],
                },
            )]
            .into_iter()
            .collect(),
            omit_default_regions: true,
        };

        let shared_map = Arc::new(RwLock::new(base_map.clone()));

        let config = DerpConfig {
            derp_map_url: None,
            derp_map_path: Some(temp_file.path().to_path_buf()),
            // 1 second for test speed
            update_frequency_secs: 1,
            ..Default::default()
        };

        spawn_derp_map_updater(shared_map.clone(), config, base_map);

        // wait for one update cycle
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

        let map = shared_map.read().await;
        // should have both embedded (region 1) and external (region 500)
        assert!(map.regions.contains_key(&1), "should keep embedded region");
        assert!(
            map.regions.contains_key(&500),
            "should have external region"
        );
        assert_eq!(map.regions.get(&500).unwrap().region_code, "updated");
    }

    /// test merging multiple derp maps (later maps override earlier).
    #[test]
    fn test_merge_derp_maps() {
        let map1 = DerpMap {
            regions: [(
                1,
                DerpRegion {
                    region_id: 1,
                    region_code: "nyc".to_string(),
                    region_name: "New York City".to_string(),
                    nodes: vec![],
                },
            )]
            .into_iter()
            .collect(),
            omit_default_regions: false,
        };

        let map2 = DerpMap {
            regions: [
                (
                    1,
                    DerpRegion {
                        region_id: 1,
                        region_code: "nyc-updated".to_string(),
                        region_name: "New York City (Updated)".to_string(),
                        nodes: vec![],
                    },
                ),
                (
                    2,
                    DerpRegion {
                        region_id: 2,
                        region_code: "sfo".to_string(),
                        region_name: "San Francisco".to_string(),
                        nodes: vec![],
                    },
                ),
            ]
            .into_iter()
            .collect(),
            omit_default_regions: false,
        };

        let merged = merge_derp_maps(&[map1, map2]);

        assert_eq!(merged.regions.len(), 2);
        // region 1 should be from map2 (later overrides)
        assert_eq!(merged.regions.get(&1).unwrap().region_code, "nyc-updated");
        // region 2 should be from map2
        assert_eq!(merged.regions.get(&2).unwrap().region_code, "sfo");
    }
}
