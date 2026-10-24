//! `ghost-verify` — the CLI (Phase 14 design §9.1). Fixed vocabulary on stdout, exit 0 on
//! `VERIFIED`, 1 on `REFUSED`, 2 on usage errors.

use std::path::PathBuf;
use std::process::exit;

use ghost_client_release::root::GHRT;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()) {
        Some("apk") => run_apk(&args[1..]),
        _ => {
            eprintln!(
                "usage:\n  ghost-verify apk --bundle <current.ghrb> --apk <signed.apk> --root <anchor.ghrt> --day <epoch day> --now <unix seconds> [--sdk <n>...]"
            );
            exit(2);
        }
    }
}

fn run_apk(args: &[String]) {
    let mut bundle: Option<PathBuf> = None;
    let mut apk: Option<PathBuf> = None;
    let mut root: Option<PathBuf> = None;
    let mut day: Option<u32> = None;
    let mut now: Option<u64> = None;
    let mut sdks: Vec<u8> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let take = |i: &mut usize| -> String {
            *i += 1;
            args.get(*i).cloned().unwrap_or_else(|| {
                eprintln!("missing value for {}", args[*i - 1]);
                exit(2);
            })
        };
        match args[i].as_str() {
            "--bundle" => bundle = Some(PathBuf::from(take(&mut i))),
            "--apk" => apk = Some(PathBuf::from(take(&mut i))),
            "--root" => root = Some(PathBuf::from(take(&mut i))),
            "--day" => day = Some(take(&mut i).parse().unwrap_or_else(|_| exit(2))),
            "--now" => now = Some(take(&mut i).parse().unwrap_or_else(|_| exit(2))),
            "--sdk" => sdks.push(take(&mut i).parse().unwrap_or_else(|_| exit(2))),
            other => {
                eprintln!("unknown argument {other}");
                exit(2);
            }
        }
        i += 1;
    }
    let (bundle, apk, root, day, now) = match (bundle, apk, root, day, now) {
        (Some(b), Some(a), Some(r), Some(d), Some(n)) => (b, a, r, d, n),
        _ => {
            eprintln!("apk needs --bundle, --apk, --root, --day and --now");
            exit(2);
        }
    };
    let bundle = std::fs::read(&bundle).unwrap_or_else(|e| {
        eprintln!("cannot read bundle: {e}");
        exit(2);
    });
    let apk = std::fs::read(&apk).unwrap_or_else(|e| {
        eprintln!("cannot read apk: {e}");
        exit(2);
    });
    let root = std::fs::read(&root).unwrap_or_else(|e| {
        eprintln!("cannot read root: {e}");
        exit(2);
    });
    let anchor = match GHRT::parse(&root) {
        Ok(r) => r,
        Err(e) => {
            println!("REFUSED MALFORMED");
            eprintln!("anchor root does not parse: {e}");
            exit(1);
        }
    };
    let verdict = ghost_verify::apk(&bundle, &apk, &anchor, day, now, &sdks);
    println!("{}", ghost_verify::apk_line(&verdict));
    match verdict {
        ghost_verify::ApkVerdict::Verified { .. } => exit(0),
        ghost_verify::ApkVerdict::Refused(_) => exit(1),
    }
}
