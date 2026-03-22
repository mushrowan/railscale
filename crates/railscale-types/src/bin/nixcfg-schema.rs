use nixcfg::Schema;
use railscale_types::Config;

fn main() {
    let defaults =
        serde_json::to_value(Config::default()).expect("Config::default() must be serialisable");
    let schema = Schema::from::<Config>("railscale").with_defaults(defaults);
    println!("{}", schema.to_json_pretty());
}
