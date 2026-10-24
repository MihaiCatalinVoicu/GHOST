//! `ghost-release-ops` — GHOST release operations (Phase 14 design §3, §6).
//!
//! Slice 1: `apk-core`, the §6.5 core rule check used by RK1 (offline) and the online re-check
//! before logging (DS-3, §5.2). Later subcommands: root-build, manifest-build, bundle, leaf.
//! Exit 0 only when the check passes; one fixed line of output (T3 discipline).

use std::process::exit;

use ghost_release_ops::apkcore;

fn usage() -> ! {
    eprintln!(
        "usage:\n  ghost-release-ops apk-core --apk <signed.apk> --unsigned <unsigned.apk>\n  ghost-release-ops apk-core --apk <signed.apk> --unsigned-length <n> --expect <sha256 hex>"
    );
    exit(2)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(|s| s.as_str()) != Some("apk-core") {
        usage();
    }
    let mut apk: Option<String> = None;
    let mut unsigned: Option<String> = None;
    let mut unsigned_length: Option<u64> = None;
    let mut expect: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--apk" => {
                i += 1;
                apk = args.get(i).cloned();
            }
            "--unsigned" => {
                i += 1;
                unsigned = args.get(i).cloned();
            }
            "--unsigned-length" => {
                i += 1;
                unsigned_length = args.get(i).and_then(|s| s.parse().ok());
            }
            "--expect" => {
                i += 1;
                expect = args.get(i).cloned();
            }
            _ => usage(),
        }
        i += 1;
    }
    let apk_path = match apk {
        Some(p) => p,
        None => usage(),
    };
    let file = std::fs::read(&apk_path).unwrap_or_else(|e| {
        eprintln!("apk-core: cannot read {apk_path}: {e}");
        exit(2);
    });
    let result = match (unsigned, unsigned_length, expect) {
        (Some(u), None, None) => {
            let ufile = std::fs::read(&u).unwrap_or_else(|e| {
                eprintln!("apk-core: cannot read {u}: {e}");
                exit(2);
            });
            apkcore::check_core(&file, &ufile)
        }
        (None, Some(n), Some(h)) => {
            let hex_bytes = hex::decode(&h).unwrap_or_else(|_| {
                eprintln!("apk-core: --expect is not hex");
                exit(2);
            });
            let arr: [u8; 32] = hex_bytes.try_into().unwrap_or_else(|_| {
                eprintln!("apk-core: --expect must be 32 bytes");
                exit(2);
            });
            apkcore::check_core_sha256(&file, n, &arr)
        }
        _ => usage(),
    };
    match result {
        Ok((padding, ids)) => {
            let ids: Vec<String> = ids.iter().map(|id| format!("{id:#06x}")).collect();
            println!("CORE_EQUAL padding={padding} blocks={}", ids.join(","));
        }
        Err(e) => {
            println!("APK_CORE_FAIL {e}");
            exit(1);
        }
    }
}
