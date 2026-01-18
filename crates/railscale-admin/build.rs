fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    let proto_path = std::path::Path::new(&manifest_dir).join("proto");
    let proto_file = proto_path.join("admin.proto");

    tonic_build::configure()
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .compile_protos(&[proto_file], &[proto_path])?;
    Ok(())
}
