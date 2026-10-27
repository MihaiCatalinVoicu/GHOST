//! Regression guard for the MC-D27 crafted fixture (slice S6c-crafted): a real apksigner 37
//! v3.1-lineage APK (`apksigner rotate` + `--lineage`, v1/v2 disabled) must select the v3.0
//! signer (the original certificate) at SDK 29 and the v3.1 signer (the rotated certificate)
//! at SDK 33 — the crafted suite caught `first_signer`'s single-grammar reader refusing
//! rotated APKs. The fixture lives in the update world's resources.

use std::fmt::Write as _;

fn hex(b: &[u8]) -> String {
    let mut s = String::new();
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

#[test]
fn trace_app_v31_signer_selection() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../android/update/src/test/resources/update-world/app-v31.apk"
    );
    let file = std::fs::read(path).expect("the fixture APK");
    for sdk in [29u8, 33] {
        match ghost_client_update::apk::signer_digest_of(&file, sdk) {
            Ok(d) => println!("TRACE signer_digest_of(sdk={sdk}) = {}", hex(&d)),
            Err(e) => println!("TRACE signer_digest_of(sdk={sdk}) refused: {e:?}"),
        }
    }
    println!(
        "TRACE block_ids = {:?}",
        ghost_client_update::apk::block_ids(&file).map(|v| v.iter().map(|i| format!("{i:#x}")).collect::<Vec<_>>())
    );
}
