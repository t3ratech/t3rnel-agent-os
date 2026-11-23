use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc);

    let descriptor_path = PathBuf::from(std::env::var("OUT_DIR")?).join("t3rnel_descriptor.bin");

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .file_descriptor_set_path(descriptor_path)
        .compile_protos(&["../../proto/t3rnel/v1/t3rnel.proto"], &["../../proto"])?;

    println!("cargo:rerun-if-changed=../../proto/t3rnel/v1/t3rnel.proto");
    Ok(())
}
