//! `ghost-verify` — the CLI (Phase 14 design §9.1). Fixed vocabulary on stdout, exit 0 on
//! `VERIFIED` / no monitor findings, 1 on `REFUSED` or findings, 2 on usage errors.

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
        Some("monitor") => run_monitor(&args[1..]),
        _ => {
            eprintln!(
                "usage:\n  ghost-verify apk --bundle <current.ghrb> --apk <signed.apk> --root <anchor.ghrt> --day <epoch day> --now <unix seconds> [--sdk <n>...]\n  ghost-verify libs --bundle <b> --apk <a> --root <r> --day <n> --now <n>\n  ghost-verify operator --bundle <b> --root <r> --binary <f> --kind relay|issuer --day <n> --now <n>\n  ghost-verify fetch --socks 127.0.0.1:9050 --mirror <onion:port> --path <p> --out <f> [--bound <bytes>] [--range a-b]\n  ghost-verify monitor --archive <dir> --root <anchor.ghrt> (--leaves <file> | --log-origin <o> --log-base-url <url> --log-key-hash <hex> --log-verification-key <hex>) [--schedule-key <hex>] [--served-record <file>] [--today <day>]"
            );
            exit(2);
        }
    }
}

/// `monitor` (design §5.3): walks the archive, attaches the log's leaves (offline `--leaves`
/// or a live `--log-*` fetch) and the served record, prints one `FLAG …` line per finding.
/// Exit 0 with none, 1 with findings or a refused input, 2 on usage.
fn run_monitor(args: &[String]) {
    let mut archive: Option<PathBuf> = None;
    let mut root: Option<PathBuf> = None;
    let mut leaves_file: Option<PathBuf> = None;
    let mut log_origin: Option<String> = None;
    let mut log_base_url: Option<String> = None;
    let mut log_key_hash: Option<String> = None;
    let mut log_verification_key: Option<String> = None;
    let mut schedule_key: Option<String> = None;
    let mut served_record: Option<PathBuf> = None;
    let mut today: Option<u32> = None;
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
            "--archive" => archive = Some(PathBuf::from(take(&mut i))),
            "--root" => root = Some(PathBuf::from(take(&mut i))),
            "--leaves" => leaves_file = Some(PathBuf::from(take(&mut i))),
            "--log-origin" => log_origin = Some(take(&mut i)),
            "--log-base-url" => log_base_url = Some(take(&mut i)),
            "--log-key-hash" => log_key_hash = Some(take(&mut i)),
            "--log-verification-key" => log_verification_key = Some(take(&mut i)),
            "--schedule-key" => schedule_key = Some(take(&mut i)),
            "--served-record" => served_record = Some(PathBuf::from(take(&mut i))),
            "--today" => today = Some(take(&mut i).parse().unwrap_or_else(|_| exit(2))),
            other => {
                eprintln!("unknown argument {other}");
                exit(2);
            }
        }
        i += 1;
    }
    let (archive, root) = match (archive, root) {
        (Some(a), Some(r)) => (a, r),
        _ => {
            eprintln!("monitor needs --archive and --root");
            exit(2);
        }
    };
    let offline = leaves_file.is_some();
    let live = log_origin.is_some()
        || log_base_url.is_some()
        || log_key_hash.is_some()
        || log_verification_key.is_some();
    if offline == live {
        eprintln!("monitor needs exactly one of --leaves FILE or the --log-* live flags");
        exit(2);
    }
    if live
        && !(log_origin.is_some()
            && log_base_url.is_some()
            && log_key_hash.is_some()
            && log_verification_key.is_some())
    {
        eprintln!("live mode needs --log-origin, --log-base-url, --log-key-hash and --log-verification-key together");
        exit(2);
    }
    let today = today.unwrap_or_else(|| {
        (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() / 86_400)
            .unwrap_or(0)) as u32
    });
    let anchor = std::fs::read(&root).unwrap_or_else(|e| {
        eprintln!("REFUSED MONITOR_ROOT_UNREADABLE {e}");
        exit(1);
    });
    if GHRT::parse(&anchor).is_err() {
        println!("REFUSED MALFORMED");
        eprintln!("anchor root does not parse");
        exit(1);
    }
    let schedule_key = schedule_key.map(|s| {
        let b = hex::decode(s.trim()).unwrap_or_else(|_| {
            eprintln!("REFUSED MONITOR_SCHEDULE_KEY the --schedule-key is not hex");
            exit(1);
        });
        let key: [u8; 32] = b.try_into().unwrap_or_else(|_| {
            eprintln!("REFUSED MONITOR_SCHEDULE_KEY the --schedule-key is not 32 bytes");
            exit(1);
        });
        key
    });
    let mut monitor =
        match ghost_verify::archive::Monitor::load(&archive, &anchor, schedule_key.as_ref(), today)
        {
            Ok(m) => m,
            Err(e) => {
                println!("REFUSED {e}");
                exit(1);
            }
        };
    // The policy's log entry the live flags must match (the anchor root lists the logs).
    let raw_leaves: Vec<ghost_verify::sigsum::RawLeaf> = if let Some(file) = leaves_file {
        let text = std::fs::read_to_string(&file).unwrap_or_else(|e| {
            eprintln!("REFUSED MONITOR_LEAVES_UNREADABLE {e}");
            exit(1);
        });
        let mut out = Vec::new();
        for (n, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            match ghost_verify::sigsum::parse_leaf_line(line) {
                Ok(leaf) => out.push(leaf),
                Err(e) => {
                    println!("REFUSED MONITOR_LEAF_LINE line={} reason={e}", n + 1);
                    exit(1);
                }
            }
        }
        out
    } else {
        let origin = log_origin.unwrap();
        let base = log_base_url.unwrap();
        let key_hash = hex::decode(log_key_hash.unwrap().trim()).unwrap_or_else(|_| exit(2));
        let vkey = hex::decode(log_verification_key.unwrap().trim()).unwrap_or_else(|_| exit(2));
        let anchor = GHRT::parse(&anchor).unwrap_or_else(|_| exit(2));
        let policy = anchor
            .body
            .logs
            .iter()
            .find(|l| l.origin == origin.as_bytes());
        let matches = match policy {
            Some(entry) => {
                &ghost_client_release::key_id(&entry.key)[..] == key_hash.as_slice()
                    && sha256_hex(&vkey) == hex::encode(&key_hash)
            }
            None => false,
        };
        if !matches {
            println!("REFUSED MONITOR_LOG_POLICY --log-origin is not the anchor root's log, or the key hash does not match it");
            exit(1);
        }
        let head = match ghost_verify::sigsum::get_tree_head_cosigned(&base) {
            Ok(h) => h,
            Err(e) => {
                println!("REFUSED MONITOR_LOG_FETCH {e}");
                exit(1);
            }
        };
        let mut out = Vec::new();
        let mut next = 0u64;
        while next < head.tree_size {
            match ghost_verify::sigsum::get_leaves(&base, next, head.tree_size - 1) {
                Ok(batch) if !batch.is_empty() => {
                    out.extend(batch);
                    next = out.len() as u64;
                }
                Ok(_) => {
                    println!("REFUSED MONITOR_LOG_FETCH get-leaves answered no leaves at {next}");
                    exit(1);
                }
                Err(e) => {
                    println!("REFUSED MONITOR_LOG_FETCH {e}");
                    exit(1);
                }
            }
        }
        out
    };
    if let Err(e) = monitor.attach_leaves(&raw_leaves) {
        println!("REFUSED {e}");
        exit(1);
    }
    if let Some(file) = served_record {
        let text = std::fs::read_to_string(&file).unwrap_or_else(|e| {
            eprintln!("REFUSED MONITOR_SERVED_UNREADABLE {e}");
            exit(1);
        });
        if let Err(e) = monitor.attach_served_record(&text) {
            println!("REFUSED MONITOR_SERVED_LINE {e}");
            exit(1);
        }
    }
    let findings = monitor.run();
    for finding in &findings {
        println!("{finding}");
    }
    exit(if findings.is_empty() { 0 } else { 1 });
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(bytes))
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
            eprintln!(
                "operator needs --bundle, --root, --binary, --kind relay|issuer, --day and --now"
            );
            exit(2);
        }
    };
    let bundle = std::fs::read(&bundle).unwrap_or_else(|e| {
        eprintln!("cannot read bundle: {e}");
        exit(2);
    });
    let binary = std::fs::read(&binary).unwrap_or_else(|e| {
        eprintln!("cannot read binary: {e}");
        exit(2);
    });
    let root = std::fs::read(&root).unwrap_or_else(|e| {
        eprintln!("cannot read root: {e}");
        exit(2);
    });
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
                range = Some((
                    a.parse().unwrap_or_else(|_| exit(2)),
                    b.parse().unwrap_or_else(|_| exit(2)),
                ));
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
