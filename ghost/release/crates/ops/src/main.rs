//! `ghost-release-ops` — GHOST release operations (Phase 14 design §3, §6).
//!
//! Subcommands: `apk-core` (the §6.5 core rule check used by RK1 offline and the online re-check
//! before logging, DS-3 §5.2) and the document builders (`keygen`, `root-build`, `chain-build`,
//! `proof-build`, `manifest-build`, `bundle`) that drive the stagenet channel end-to-end with
//! software keys. Exit 0 only when a command succeeds; one fixed line of output (T3 discipline),
//! failures print `<CMD>_REFUSED <reason>` and exit 1.

use std::path::PathBuf;
use std::process::exit;

use ghost_release_ops::{apkcore, build};

fn usage() -> ! {
    eprintln!(
        "usage:\n  ghost-release-ops apk-core --apk <signed.apk> --unsigned <unsigned.apk>\n  ghost-release-ops apk-core --apk <signed.apk> --unsigned-length <n> --expect <sha256 hex>\n  ghost-release-ops keygen --out <dir> --spec root:3,release:2,...\n  ghost-release-ops root-build --config <toml> --keys <dir> --out <path>\n  ghost-release-ops chain-build --network <n> --roots <dir> --out <path>\n  ghost-release-ops proof-build --file <logged> --log-index <i> --log-key <n> --submit-key <n> --witness <n>... [--time <unix>] --keys <dir> --out <path>\n  ghost-release-ops manifest-build --source <toml> --root <ghrt> --keys <dir> --attest-keys n1,n2 [--prev <ghrm>] --out <path>\n  ghost-release-ops export-public --tag <tag> --out <dir> [--mtime <unix>]\n  ghost-release-ops bundle --chain <ghrc> --root-proof <ghrp>... --manifest <ghrm> --manifest-proof <ghrp> --out <path>"
    );
    exit(2)
}

/// One `--flag value` occurrence map: flags may repeat (collected in order).
struct Args {
    cmd: String,
    opts: Vec<(String, String)>,
}

impl Args {
    fn get(&self, name: &str) -> Option<&str> {
        self.opts
            .iter()
            .rev()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
    fn all(&self, name: &str) -> Vec<&str> {
        self.opts
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

fn parse_args() -> Args {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let cmd = argv.first().cloned().unwrap_or_else(|| usage());
    let mut opts = Vec::new();
    let mut i = 1;
    while i < argv.len() {
        let flag = argv[i].clone();
        if !flag.starts_with("--") {
            usage();
        }
        let value = argv.get(i + 1).cloned().unwrap_or_else(|| usage());
        opts.push((flag.trim_start_matches("--").to_string(), value));
        i += 2;
    }
    Args { cmd, opts }
}

fn path(a: &Args, name: &str) -> PathBuf {
    a.get(name).map(PathBuf::from).unwrap_or_else(|| usage())
}

fn main() {
    let a = parse_args();
    let result = match a.cmd.as_str() {
        "apk-core" => run_apk_core(&a),
        "keygen" => build::keygen(&path(&a, "out"), a.get("spec").unwrap_or_else(|| usage())),
        "root-build" => build::root_build(&path(&a, "config"), &path(&a, "keys"), &path(&a, "out")),
        "chain-build" => {
            let network: u8 = a
                .get("network")
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| usage());
            build::chain_build(network, &path(&a, "roots"), &path(&a, "out"))
        }
        "proof-build" => {
            let witnesses: Vec<String> = a.all("witness").iter().map(|s| s.to_string()).collect();
            let time = a.get("time").and_then(|s| s.parse().ok());
            let log_index: u8 = a
                .get("log-index")
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| usage());
            build::proof_build(
                &path(&a, "file"),
                log_index,
                a.get("log-key").unwrap_or_else(|| usage()),
                a.get("submit-key").unwrap_or_else(|| usage()),
                &witnesses,
                time,
                &path(&a, "keys"),
                &path(&a, "out"),
            )
        }
        "manifest-build" => {
            let attest: Vec<String> = a
                .get("attest-keys")
                .map(|s| s.split(',').map(|x| x.trim().to_string()).collect())
                .unwrap_or_else(|| usage());
            build::manifest_build(
                &path(&a, "source"),
                &path(&a, "root"),
                &path(&a, "keys"),
                &attest,
                a.get("prev").map(PathBuf::from).as_deref(),
                &path(&a, "out"),
            )
        }
        "inspect" => {
            let today = a.get("today").and_then(|s| s.parse().ok());
            build::inspect(&path(&a, "bundle"), today)
        }
        "sums-compare" => {
            build::sums_compare(&path(&a, "a-local"), &path(&a, "a-job"), &path(&a, "b-job"))
        }
        "export-public" => {
            let mtime = a.get("mtime").and_then(|s| s.parse().ok());
            ghost_release_ops::export::export_public(
                a.get("tag").unwrap_or_else(|| usage()),
                &path(&a, "out"),
                mtime,
            )
        }
        "bundle" => {
            let proofs: Vec<PathBuf> = a.all("root-proof").iter().map(PathBuf::from).collect();
            build::bundle(
                &path(&a, "chain"),
                &proofs,
                &path(&a, "manifest"),
                &path(&a, "manifest-proof"),
                &path(&a, "out"),
            )
        }
        _ => usage(),
    };
    let cmd = a.cmd.to_uppercase().replace('-', "_");
    match result {
        Ok(line) => println!("{line}"),
        Err(reason) => {
            println!("{cmd}_REFUSED {reason}");
            exit(1);
        }
    }
}

fn run_apk_core(a: &Args) -> Result<String, String> {
    let apk_path = a.get("apk").unwrap_or_else(|| usage());
    let file = std::fs::read(apk_path).map_err(|e| format!("cannot read {apk_path}: {e}"))?;
    match (
        a.get("unsigned"),
        a.get("unsigned-length"),
        a.get("expect"),
        a.get("extract"),
    ) {
        (Some(u), None, None, None) => {
            let ufile = std::fs::read(u).map_err(|e| format!("cannot read {u}: {e}"))?;
            apkcore::check_core(&file, &ufile)
        }
        (None, Some(n), Some(h), None) => {
            let len: u64 = n.parse().map_err(|_| "unsigned-length not a number")?;
            let arr: [u8; 32] = hex::decode(h)
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| "--expect must be 32 hex bytes".to_string())?;
            apkcore::check_core_sha256(&file, len, &arr)
        }
        (None, None, None, Some(out)) => {
            // Extract the unsigned core deriving the length from the zero padding before the
            // signing block (AGP's debug signing pads to 4 bytes, not the release pipeline's
            // 4096; see extract_core_inferred). For fixtures and attestation tooling the
            // unsigned build was not retained; the (core, length) pair stays self-consistent
            // for the client's own extraction.
            let (core, unsigned_length) =
                apkcore::extract_core_inferred(&file).map_err(|e| e.to_string())?;
            let sha = sha256_hex(&core);
            std::fs::write(&out, &core).map_err(|e| format!("cannot write {out}: {e}"))?;
            return Ok(format!(
                "CORE_EXTRACTED path={out} unsigned_length={unsigned_length} sha256={sha}"
            ));
        }
        _ => usage(),
    }
    .map(|(padding, ids)| {
        let ids: Vec<String> = ids.iter().map(|id| format!("{id:#06x}")).collect();
        format!("CORE_EQUAL padding={padding} blocks={}", ids.join(","))
    })
    .map_err(|e| e.to_string())
}

fn sha256_hex(b: &[u8]) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(b);
    hex::encode(h.finalize())
}
