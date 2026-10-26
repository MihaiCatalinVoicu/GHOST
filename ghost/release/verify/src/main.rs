//! `ghost-verify` — the CLI (Phase 14 design §9.1). Fixed vocabulary on stdout, exit 0 on
//! `VERIFIED`, 1 on `REFUSED`, 2 on usage errors.

use std::path::PathBuf;
use std::process::exit;

use ghost_client_release::root::GHRT;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()) {
        Some("apk") => run_apk(&args[1..]),
        Some("libs") => run_libs(&args[1..]),
        Some("operator") => run_operator(&args[1..]),
        Some("fetch") => run_fetch(&args[1..]),
        _ => {
            eprintln!(
                "usage:\n  ghost-verify apk --bundle <current.ghrb> --apk <signed.apk> --root <anchor.ghrt> --day <epoch day> --now <unix seconds> [--sdk <n>...]\n  ghost-verify libs --bundle <b> --apk <a> --root <r> --day <n> --now <n>\n  ghost-verify operator --bundle <b> --root <r> --binary <f> --kind relay|issuer --day <n> --now <n>\n  ghost-verify fetch --socks 127.0.0.1:9050 --mirror <onion:port> --path <p> --out <f> [--bound <bytes>] [--range a-b]"
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

fn run_libs(args: &[String]) {
    let mut bundle: Option<PathBuf> = None;
    let mut apk: Option<PathBuf> = None;
    let mut root: Option<PathBuf> = None;
    let mut day: Option<u32> = None;
    let mut now: Option<u64> = None;
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
            eprintln!("libs needs --bundle, --apk, --root, --day and --now");
            exit(2);
        }
    };
    let bundle = std::fs::read(&bundle).unwrap_or_else(|e| { eprintln!("cannot read bundle: {e}"); exit(2); });
    let apk = std::fs::read(&apk).unwrap_or_else(|e| { eprintln!("cannot read apk: {e}"); exit(2); });
    let root = std::fs::read(&root).unwrap_or_else(|e| { eprintln!("cannot read root: {e}"); exit(2); });
    let anchor = match GHRT::parse(&root) {
        Ok(r) => r,
        Err(_) => {
            println!("REFUSED MALFORMED");
            exit(1);
        }
    };
    match ghost_verify::libs(&bundle, &apk, &anchor, day, now) {
        Ok(lines) => {
            let mut bad = false;
            for l in &lines {
                println!("{}", ghost_verify::libs_line(l));
                if l.status != "VERIFIED" {
                    bad = true;
                }
            }
            exit(if bad { 1 } else { 0 });
        }
        Err(e) => {
            println!("REFUSED {e}");
            exit(1);
        }
    }
}

fn run_operator(args: &[String]) {
    let mut bundle: Option<PathBuf> = None;
    let mut root: Option<PathBuf> = None;
    let mut binary: Option<PathBuf> = None;
    let mut kind: Option<String> = None;
    let mut day: Option<u32> = None;
    let mut now: Option<u64> = None;
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
            "--root" => root = Some(PathBuf::from(take(&mut i))),
            "--binary" => binary = Some(PathBuf::from(take(&mut i))),
            "--kind" => kind = Some(take(&mut i)),
            "--day" => day = Some(take(&mut i).parse().unwrap_or_else(|_| exit(2))),
            "--now" => now = Some(take(&mut i).parse().unwrap_or_else(|_| exit(2))),
            other => {
                eprintln!("unknown argument {other}");
                exit(2);
            }
        }
        i += 1;
    }
    let (bundle, root, binary, kind, day, now) = match (bundle, root, binary, kind, day, now) {
        (Some(b), Some(r), Some(f), Some(k), Some(d), Some(n)) => (b, r, f, k, d, n),
        _ => {
            eprintln!("operator needs --bundle, --root, --binary, --kind relay|issuer, --day and --now");
            exit(2);
        }
    };
    let bundle = std::fs::read(&bundle).unwrap_or_else(|e| { eprintln!("cannot read bundle: {e}"); exit(2); });
    let binary = std::fs::read(&binary).unwrap_or_else(|e| { eprintln!("cannot read binary: {e}"); exit(2); });
    let root = std::fs::read(&root).unwrap_or_else(|e| { eprintln!("cannot read root: {e}"); exit(2); });
    let anchor = match GHRT::parse(&root) {
        Ok(r) => r,
        Err(_) => {
            println!("REFUSED MALFORMED");
            exit(1);
        }
    };
    let verdict = ghost_verify::operator(&bundle, &binary, &anchor, &kind, day, now);
    println!("{}", ghost_verify::operator_line(&verdict));
    match verdict {
        ghost_verify::OperatorVerdict::Verified { .. } => exit(0),
        _ => exit(1),
    }
}

fn run_fetch(args: &[String]) {
    let mut socks = "127.0.0.1:9050".to_string();
    let mut mirror: Option<String> = None;
    let mut path: Option<String> = None;
    let mut out: Option<PathBuf> = None;
    let mut bound = ghost_verify::fetch::DEFAULT_BOUND;
    let mut range: Option<(u64, u64)> = None;
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
            "--socks" => socks = take(&mut i),
            "--mirror" => mirror = Some(take(&mut i)),
            "--path" => path = Some(take(&mut i)),
            "--out" => out = Some(PathBuf::from(take(&mut i))),
            "--bound" => bound = take(&mut i).parse().unwrap_or_else(|_| exit(2)),
            "--range" => {
                let v = take(&mut i);
                let (a, b) = v.split_once('-').unwrap_or_else(|| exit(2));
                range = Some((a.parse().unwrap_or_else(|_| exit(2)), b.parse().unwrap_or_else(|_| exit(2))));
            }
            other => {
                eprintln!("unknown argument {other}");
                exit(2);
            }
        }
        i += 1;
    }
    let (mirror, path, out) = match (mirror, path, out) {
        (Some(m), Some(p), Some(o)) => (m, p, o),
        _ => {
            eprintln!("fetch needs --mirror, --path and --out");
            exit(2);
        }
    };
    let (host, port) = match mirror.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or_else(|_| exit(2))),
        None => (mirror, 80u16),
    };
    match ghost_verify::fetch::socks_fetch(&socks, &host, port, &path, range, bound) {
        Ok(body) => {
            if let Err(e) = std::fs::write(&out, &body) {
                eprintln!("cannot write {}: {e}", out.display());
                exit(2);
            }
            println!("FETCHED bytes={}", body.len());
            exit(0);
        }
        Err(e) => {
            println!("REFUSED FETCH_FAILED {e}");
            exit(1);
        }
    }
}
