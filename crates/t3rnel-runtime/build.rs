use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc);

    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);
    let descriptor_path = out_dir.join("plugin_descriptor.bin");

    // The plugin host contract: 14 host services (plugin -> core) plus the
    // PluginCallbacks service the core calls back on (core -> plugin).
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .file_descriptor_set_path(descriptor_path)
        .compile_protos(
            &["../../proto/t3rnel/plugin/v1/plugin.proto"],
            &["../../proto"],
        )?;

    println!("cargo:rerun-if-changed=../../proto/t3rnel/plugin/v1/plugin.proto");
    Ok(())
}
