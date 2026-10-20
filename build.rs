use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=proto/signer/v1/signer.proto");

    let include_path = protoc_bin_vendored::include_path()?;

    if std::env::var_os("PROTOC").is_none() {
        let protoc = protoc_bin_vendored::protoc_bin_path()?;
        // SAFETY: build scripts are single-threaded and this runs before
        // prost-build invokes protoc.
        unsafe {
            std::env::set_var("PROTOC", protoc);
        }
    }
    if std::env::var_os("PROTOC_INCLUDE").is_none() {
        // SAFETY: same as above.
        unsafe {
            std::env::set_var("PROTOC_INCLUDE", include_path);
        }
    }

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/signer/v1/signer.proto"], &["proto"])?;

    Ok(())
}
