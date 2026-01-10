//! derp map generation for relay coordination.

use railscale_proto::{DerpMap, DerpNode, DerpRegion};
use railscale_types::Config;
use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;

/// http request failed
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
}

/// extract hostname from a url, stripping scheme and port.
///
/// e.g. "https://example.com:443" -> "example.com"
fn extract_hostname(url: &str) -> &str {
    url.split("://")
        .nth(1)
        .unwrap_or(url)
        .split(':')
        .next()
        .unwrap_or("localhost")
}

/// fetch a derp map from a url (expects json format).
pub async fn fetch_derp_map_from_url(url: &str) -> Result<DerpMap, DerpError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let response = client.get(url).send().await?;
    let body = response.text().await?;
    let derp_map: DerpMap = serde_json::from_str(&body)?;
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

    DerpMap { regions }
}

/// generate the derp map for clients.
pub fn generate_derp_map(config: &Config) -> DerpMap {
    let mut regions = HashMap::new();

    // if embedded derp is enabled, add it to the map
    if config.derp.embedded_derp.enabled {
        let region_id = config.derp.embedded_derp.region_id;
        let host_name = extract_hostname(&config.server_url).to_string();

        let region = DerpRegion {
            region_id,
            region_code: "embedded".to_string(),
            region_name: config.derp.embedded_derp.region_name.clone(),
            nodes: vec![DerpNode {
                name: format!("{}a", region_id),
                region_id,
                host_name,
                ipv4: None,
                ipv6: None,
                stun_port: 3478,
                stun_only: false,
                derp_port: 443,
                can_port_80: false,
            }],
        };
        regions.insert(region_id, region);
    }

    // if we have no regions, add a default one (e.g., tailscale's new york region)
    // so that nodes can at least communicate via relay if they can't p2p.
    // in a real scenario, we'd probably fetch this from the url in config.
    if regions.is_empty() {
        regions.insert(
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
                }],
            },
        );
    }

    DerpMap { regions }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// test parsing tailscale's official derp map json format.
    //this is a minimal example of tailscale's derp map format
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
        };

        let merged = merge_derp_maps(&[map1, map2]);

        assert_eq!(merged.regions.len(), 2);
        // region 1 should be from map2 (later overrides)
        assert_eq!(merged.regions.get(&1).unwrap().region_code, "nyc-updated");
        // region 2 should be from map2
        assert_eq!(merged.regions.get(&2).unwrap().region_code, "sfo");
    }
}
