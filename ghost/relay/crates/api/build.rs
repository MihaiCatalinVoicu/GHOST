//! Generates the relay wire types and gRPC service from the normative schema (spec §9.1:
//! "the normative wire schema MUST live in protocol/relay/v1/*.proto and be generated in CI").

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../protocol");
    let proto = proto_root.join("relay/v1/relay.proto");
    println!("cargo:rerun-if-changed={}", proto.display());
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&[proto], &[proto_root])?;
    Ok(())
}
