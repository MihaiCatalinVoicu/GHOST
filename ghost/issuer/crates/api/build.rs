//! Generates the issuer wire types and gRPC service from the normative schema (Phase 8 design §5.1,
//! §5.2): `protocol/issuer/v1/issuer.proto`.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../protocol");
    let proto = proto_root.join("issuer/v1/issuer.proto");
    println!("cargo:rerun-if-changed={}", proto.display());
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        // No generated `connect()` (it would pull tonic Channel, a clearnet dialer, into every
        // consumer). The client passes its own Tor connector (Phase 8 S7).
        .build_transport(false)
        .compile_protos(&[proto], &[proto_root])?;
    Ok(())
}
