use nixcfg::NixSchema;
use railscale_types::{Config, OidcConfig};

fn main() {
    // start with Config::default() for top-level defaults
    let mut defaults =
        serde_json::to_value(Config::default()).expect("Config::default() must be serialisable");

    // for optional submodules that default to None, inject the inner type's
    // defaults so schema children get their default values
    if let serde_json::Value::Object(ref mut map) = defaults {
        map.insert(
            "oidc".to_string(),
            serde_json::to_value(OidcConfig::default()).unwrap(),
        );
    }

    let schema = NixSchema::from::<Config>("railscale").with_defaults(defaults);
    println!("{}", schema.to_json_pretty());
}
