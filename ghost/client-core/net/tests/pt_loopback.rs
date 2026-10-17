//! Phase 12 §12.3/§12.5: the loopback pluggable-transport harness (PT-L1/PT-L2) and the
//! capture/privacy suites (PT-P1/PT-P2), arti half.
//!
//! The harness is self-contained on the host (the pragmatic shape of §12.3, S3-T2):
//!   - the loopback **relay** is the pinned Tor expert bundle
//!     (`ghost/third_party/tor-expert/FETCH.sh`, tor 0.4.9.11 — the same build the S0 evidence
//!     ran in WSL), with its own datadir, a generated identity, `BridgeRelay 1`, and one
//!     throwaway v3 onion service pointing at an in-test echo socket;
//!   - the **PT server** is the pinned pruned lyrebird in managed mode wrapping the relay's
//!     ORPort through a recording proxy (`ghost/third_party/lyrebird/BUILD.sh HARNESS=1`);
//!   - the **client** is this crate's `TorTransport` (arti + ptmgr) with one obfs4 bridge line
//!     pointing at a second recording proxy in front of the lyrebird server.
//!
//! Assertions: bootstrap to 100% within [`BOOTSTRAP_DEADLINE`]; a stream to the harness's own
//! onion service answers (the loopback proof of a directory-validated circuit through the PT);
//! two isolation scopes ride two circuits; the keystore is empty (Phase 6 invariant); the
//! client↔bridge capture has no TLS record shape (PT-L1, the S0-T5-aware rule — the naive
//! 2-byte scan false-positives on obfs4 ciphertext and is pinned as such); the relay-facing
//! byte class on the PT path equals the plain-bridge path (PT-P2); no bridge-line text appears
//! in any on-disk file or child log, including after the PT server is killed mid-attempt
//! (PT-P1, T58's canary).
//!
//! Fixtures: `$GHOST_PT_TOR` / `$GHOST_PT_LYREBIRD` override the defaults under
//! `ghost/third_party/`. Missing fixtures are a hard failure of an explicitly requested run
//! (the harness fails loudly, never silently skips). Run with:
//! `cargo test -p ghost-client-net --test pt_loopback -- --ignored --nocapture`
//! (`GHOST_PT_KEEP=1` keeps the workdir; `GHOST_PT_RECORD_DIR=<dir>` also copies the measured
//! shape record there for the privacy fixtures).

use ghost_client_net::{
    IsolationScope, OnionAddress, TorTransport, TransportConfig, BOOTSTRAP_DEADLINE,
};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tor_proto::client::stream::ClientStreamCtrl as _;

// ---------------------------------------------------------------------------
// Fixture discovery
// ---------------------------------------------------------------------------

fn ghost_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is ghost/client-core/net.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonicalize the crate root")
}

fn require_fixture(path: PathBuf, what: &str, how: &str) -> PathBuf {
    if path.is_file() {
        path
    } else {
        panic!("pt_loopback: missing {what} at {path:?}.\nFetch the fixtures first: {how}")
    }
}

fn tor_exe() -> PathBuf {
    if let Ok(p) = std::env::var("GHOST_PT_TOR") {
        return require_fixture(
            PathBuf::from(p),
            "tor daemon ($GHOST_PT_TOR)",
            "bash ghost/third_party/tor-expert/FETCH.sh",
        );
    }
    let exe = if cfg!(windows) { "tor.exe" } else { "tor" };
    require_fixture(
        ghost_root()
            .join("third_party/tor-expert/.cache/tor-expert/tor")
            .join(exe),
        "tor daemon",
        "bash ghost/third_party/tor-expert/FETCH.sh",
    )
}

fn lyrebird_exe() -> PathBuf {
    if let Ok(p) = std::env::var("GHOST_PT_LYREBIRD") {
        return require_fixture(
            PathBuf::from(p),
            "lyrebird harness binary ($GHOST_PT_LYREBIRD)",
            "cd ghost/third_party/lyrebird && SKIP_ANDROID=1 HARNESS=1 bash BUILD.sh",
        );
    }
    let name = if cfg!(windows) {
        "lyrebird-windows-amd64"
    } else {
        "lyrebird-linux-amd64"
    };
    require_fixture(
        ghost_root().join("third_party/lyrebird/out").join(name),
        "lyrebird harness binary",
        "cd ghost/third_party/lyrebird && SKIP_ANDROID=1 HARNESS=1 bash BUILD.sh",
    )
}

async fn free_port() -> u16 {
    // Bind-then-release: racy on a busy loopback in principle, loopback-test-standard in practice
    // (the recording proxies below bind :0 themselves and are race-free; only the tor/lyrebird
    // config ports take this path).
    TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a free port")
        .local_addr()
        .expect("local addr")
        .port()
}

fn phase(msg: &str) {
    eprintln!("pt-loopback [{}]: {msg}", humantime());
    PHASES
        .lock()
        .unwrap()
        .push(format!("pt-loopback [{}]: {msg}", humantime()));
}

/// The harness's own phase output, mirrored for the G-T7 run-log fixture.
fn phases_log() -> String {
    PHASES.lock().unwrap().join("\n")
}
static PHASES: std::sync::LazyLock<Mutex<Vec<String>>> =
    std::sync::LazyLock::new(|| Mutex::new(Vec::new()));

fn humantime() -> String {
    format!("{:?}", Instant::now() - t0())
}
fn t0() -> Instant {
    static T: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    *T.get_or_init(Instant::now)
}

// ---------------------------------------------------------------------------
// Managed child processes (tor, lyrebird server) with captured logs
// ---------------------------------------------------------------------------

type LogBuf = Arc<Mutex<Vec<u8>>>;

/// A stdout-line transform applied before a child line lands in the persisted capture.
type LineScrub = Box<dyn Fn(&str) -> String + Send + Sync>;

/// One spawned harness process. `stdin` is held open for the PT server's
/// TOR_PT_EXIT_ON_STDIN_CLOSE contract; the stdout/stderr streams are drained by reader
/// threads into `log` (shared) so a child can never stall on a full pipe.
struct ManagedChild {
    child: Child,
    #[allow(dead_code)]
    stdin: Option<ChildStdin>,
    log: LogBuf,
}

impl ManagedChild {
    /// Spawn `cmd`, draining both streams into `log`. `on_stdout_line` observes stdout lines
    /// as they arrive (the PT server's SMETHOD negotiation) — it always sees the raw line.
    /// `scrub_stdout_line`, when set, transforms a stdout line before it lands in `log`: the
    /// PT server child's SMETHOD line carries the transport cert (`ARGS:cert=…`), the very
    /// material T58's canary forbids in any captured log, so the persisted capture records
    /// the negotiation without the cert (G-T7's fixture is the redacted capture).
    fn spawn(
        name: &'static str,
        mut cmd: Command,
        on_stdout_line: Option<std::sync::mpsc::Sender<String>>,
        scrub_stdout_line: Option<LineScrub>,
    ) -> Self {
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd
            .spawn()
            .unwrap_or_else(|e| panic!("pt_loopback: spawn {name}: {e}"));
        let log: LogBuf = Arc::new(Mutex::new(Vec::new()));
        let mut out = child.stdout.take().expect("piped stdout");
        let mut err = child.stderr.take().expect("piped stderr");
        let out_log = Arc::clone(&log);
        let err_log = Arc::clone(&log);
        let tag = name.to_owned();
        std::thread::spawn(move || {
            let mut reader = BufReader::with_capacity(64 * 1024, &mut out);
            let mut line = Vec::new();
            loop {
                line.clear();
                match reader.read_until(b'\n', &mut line) {
                    Ok(0) => break,
                    Ok(_) => {
                        let raw = String::from_utf8_lossy(&line).trim_end().to_owned();
                        if let Some(tx) = &on_stdout_line {
                            let _ = tx.send(raw.clone());
                        }
                        let persisted = match &scrub_stdout_line {
                            Some(f) => f(&raw),
                            None => raw,
                        };
                        let mut g = out_log.lock().unwrap();
                        g.extend_from_slice(format!("[{tag}.out] ").as_bytes());
                        g.extend_from_slice(persisted.as_bytes());
                        g.push(b'\n');
                    }
                    Err(_) => break,
                }
            }
        });
        let tag = name.to_owned();
        std::thread::spawn(move || {
            let mut reader = BufReader::with_capacity(64 * 1024, &mut err);
            let mut line = Vec::new();
            loop {
                line.clear();
                match reader.read_until(b'\n', &mut line) {
                    Ok(0) => break,
                    Ok(_) => {
                        let mut g = err_log.lock().unwrap();
                        g.extend_from_slice(format!("[{tag}.err] ").as_bytes());
                        g.extend_from_slice(&line);
                    }
                    Err(_) => break,
                }
            }
        });
        let stdin = child.stdin.take();
        ManagedChild { child, stdin, log }
    }

    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    fn log_string(&self) -> String {
        String::from_utf8_lossy(&self.log.lock().unwrap()).into_owned()
    }

    /// The last `n` bytes of the captured output (failure forensics).
    fn log_tail(&self, n: usize) -> String {
        let log = self.log.lock().unwrap();
        let start = log.len().saturating_sub(n);
        String::from_utf8_lossy(&log[start..]).into_owned()
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        self.kill();
    }
}

// ---------------------------------------------------------------------------
// The loopback relay (pinned tor) + the lyrebird server (managed mode)
// ---------------------------------------------------------------------------

struct TorRelay {
    child: ManagedChild,
    fingerprint: String,
    datadir: PathBuf,
}

impl TorRelay {
    fn start(tor: &Path, work: &Path, orport: u16, echo_port: u16) -> Self {
        let datadir = work.join("relay");
        std::fs::create_dir_all(&datadir).unwrap();
        let hs = datadir.join("hs");
        let torrc = datadir.join("torrc");
        // C-Tor's torrc treats backslash as an escape; forward slashes are accepted by the
        // Windows APIs the daemon calls.
        let dir = datadir.display().to_string().replace('\\', "/");
        let hs_dir = hs.display().to_string().replace('\\', "/");
        // C-Tor's bridge descriptor generation refuses private addresses ("Don't know my
        // address" → the descriptor never builds → /tor/server/authority has nothing to serve,
        // and arti — unlike the S0 C-Tor client — requires the bridge descriptor). Pin a
        // documentation-range address (RFC 5737 TEST-NET-1): never routable, so nothing can
        // reach it, and never used — the client connects via the bridge line's address through
        // the PT. The ORPort/Address mismatch warning is the standard NAT shape and harmless.
        std::fs::write(
            &torrc,
            format!(
                "DataDirectory {dir}\n\
                 SocksPort 0\n\
                 ORPort 127.0.0.1:{orport}\n\
                 Address 192.0.2.1\n\
                 BridgeRelay 1\n\
                 ExitRelay 0\n\
                 Log info stdout\n\
                 HiddenServiceDir {hs_dir}\n\
                 HiddenServiceVersion 3\n\
                 HiddenServicePort 80 127.0.0.1:{echo_port}\n",
            ),
        )
        .unwrap();
        // The daemon resolves its data/geoip files relative to its own directory; run it from
        // its datadir so no global state is read.
        let mut cmd = Command::new(tor);
        cmd.arg("-f").arg(&torrc).current_dir(&datadir);
        let child = ManagedChild::spawn("tor-relay", cmd, None, None);
        // The fingerprint file lands once the identity key is generated.
        let fp_file = datadir.join("fingerprint");
        let fingerprint = (0..120)
            .find_map(|_| {
                if let Ok(text) = std::fs::read_to_string(&fp_file) {
                    let fp = text
                        .lines()
                        .find_map(|l| l.split_whitespace().last())
                        .map(str::to_owned);
                    if fp.is_some() {
                        return fp;
                    }
                }
                std::thread::sleep(Duration::from_secs(1));
                None
            })
            .unwrap_or_else(|| panic!("pt_loopback: the relay wrote no identity fingerprint"));
        assert!(
            fingerprint.len() == 40 && fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
            "unexpected relay fingerprint: {fingerprint}"
        );
        phase(&format!("relay up, identity {fingerprint}"));
        TorRelay {
            child,
            fingerprint,
            datadir,
        }
    }

    /// The throwaway v3 onion's hostname (written once the service key exists), if ready yet.
    fn onion(&self) -> Option<String> {
        std::fs::read_to_string(self.datadir.join("hs").join("hostname"))
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| s.ends_with(".onion"))
    }
}

struct LyrebirdServer {
    child: ManagedChild,
    cert: String,
}

impl LyrebirdServer {
    /// Managed server mode wrapping `orport_target` (the recording proxy in front of the
    /// relay's ORPort), fresh state → fresh obfs4 cert, held-open stdin.
    fn start(bin: &Path, work: &Path, bind_port: u16, orport_target: u16) -> Self {
        let state = work.join("ptserver").join("state");
        std::fs::create_dir_all(&state).unwrap();
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        let mut cmd = Command::new(bin);
        cmd.args(["-enableLogging", "-logLevel", "DEBUG"])
            .env("TOR_PT_MANAGED_TRANSPORT_VER", "1")
            .env("TOR_PT_STATE_LOCATION", &state)
            .env("TOR_PT_EXIT_ON_STDIN_CLOSE", "1")
            .env("TOR_PT_SERVER_TRANSPORTS", "obfs4")
            .env(
                "TOR_PT_SERVER_BINDADDR",
                format!("obfs4-127.0.0.1:{bind_port}"),
            )
            .env("TOR_PT_ORPORT", format!("127.0.0.1:{orport_target}"))
            .env("TOR_PT_EXTENDED_SERVER_PORT", "");
        let child = ManagedChild::spawn(
            "lyrebird-server",
            cmd,
            Some(tx),
            Some(Box::new(|line| {
                // Persist the negotiation without its ARGS: the SMETHOD ARGS carry the
                // transport cert — the line's cert= material, which T58 keeps out of every
                // capture.
                match line.split(" ARGS:").next() {
                    Some(head) => format!("{head} [ARGS redacted: the transport cert]"),
                    None => line.to_string(),
                }
            })),
        );
        // The SMETHOD line carries the fresh obfs4 cert the bridge line must name (V-T3).
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut smethod = String::new();
        while Instant::now() < deadline {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(line) if line.starts_with("SMETHOD obfs4") => {
                    smethod = line;
                    break;
                }
                Ok(_) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        let cert = smethod
            .split("cert=")
            .nth(1)
            .and_then(|rest| rest.split(',').next())
            .map(str::to_owned)
            .unwrap_or_else(|| panic!("pt_loopback: no SMETHOD cert in: {smethod:?}"));
        phase(&format!("lyrebird server up on 127.0.0.1:{bind_port}"));
        LyrebirdServer { child, cert }
    }
}

// ---------------------------------------------------------------------------
// Recording proxies (the capture instruments)
// ---------------------------------------------------------------------------

#[allow(clippy::disallowed_methods)]
// Test-only loopback plumbing of the §12.3 capture harness: this is not a client dial path —
// the production rule (one onion address, one isolation token through
// transport::connect_isolated) is untouched; the proxies record what the harness itself
// carries between its own loopback processes.
async fn dial_loopback(port: u16) -> std::io::Result<TcpStream> {
    TcpStream::connect(("127.0.0.1", port)).await
}

/// A TCP pipe 127.0.0.1:<port> → 127.0.0.1:<target> recording both directions.
struct RecordingProxy {
    port: u16,
    c2s: Arc<Mutex<Vec<u8>>>,
    s2c: Arc<Mutex<Vec<u8>>>,
    _task: tokio::task::JoinHandle<()>,
}

impl RecordingProxy {
    async fn start(target_port: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
        let port = listener.local_addr().unwrap().port();
        let c2s: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let s2c: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let task = {
            let c2s = Arc::clone(&c2s);
            let s2c = Arc::clone(&s2c);
            tokio::spawn(async move {
                loop {
                    let (client, _) = match listener.accept().await {
                        Ok(pair) => pair,
                        Err(_) => break,
                    };
                    let upstream = match dial_loopback(target_port).await {
                        Ok(u) => u,
                        Err(_) => continue,
                    };
                    let (mut cr, mut cw) = client.into_split();
                    let (mut ur, mut uw) = upstream.into_split();
                    let c2s_t = Arc::clone(&c2s);
                    let s2c_t = Arc::clone(&s2c);
                    tokio::spawn(async move {
                        let mut buf = [0u8; 16 * 1024];
                        loop {
                            match cr.read(&mut buf).await {
                                Ok(0) => break,
                                Ok(n) => {
                                    c2s_t.lock().unwrap().extend_from_slice(&buf[..n]);
                                    if uw.write_all(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    });
                    tokio::spawn(async move {
                        let mut buf = [0u8; 16 * 1024];
                        loop {
                            match ur.read(&mut buf).await {
                                Ok(0) => break,
                                Ok(n) => {
                                    s2c_t.lock().unwrap().extend_from_slice(&buf[..n]);
                                    if cw.write_all(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    });
                }
            })
        };
        RecordingProxy {
            port,
            c2s,
            s2c,
            _task: task,
        }
    }

    fn take_c2s(&self) -> Vec<u8> {
        std::mem::take(&mut *self.c2s.lock().unwrap())
    }
    fn take_s2c(&self) -> Vec<u8> {
        std::mem::take(&mut *self.s2c.lock().unwrap())
    }
    fn c2s_len(&self) -> usize {
        self.c2s.lock().unwrap().len()
    }
    fn s2c_len(&self) -> usize {
        self.s2c.lock().unwrap().len()
    }
}

/// The in-test TCP target of the throwaway onion service: answers any payload with a marker,
/// so a completed onion stream is proven by the bytes, not by a connect alone.
async fn start_echo() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            ECHO_CONN_COUNT.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                if n > 0 {
                    ECHO_BYTES.fetch_add(n as u64, Ordering::SeqCst);
                }
                let _ = sock
                    .write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 14\r\n\r\npt-loopback-ok")
                    .await;
                let _ = sock.flush().await;
            });
        }
    });
    (port, task)
}

/// Forensics for the onion phase: did the echo target see the stream, and did bytes arrive?
static ECHO_CONN_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static ECHO_BYTES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

// ---------------------------------------------------------------------------
// The capture classifiers (PT-L1's S0-T5-aware fixture and PT-P2's relay shape)
// ---------------------------------------------------------------------------

#[derive(Debug, Default, PartialEq)]
struct CaptureStats {
    c2s_len: usize,
    s2c_len: usize,
    first_c2s: Option<u8>,
    first_s2c: Option<u8>,
    /// 3-byte TLS record-layer signature `\x16\x03\x0[1-4]` (S0's per-payload scan rule).
    tls3_c2s: usize,
    tls3_s2c: usize,
    /// Naive 2-byte `\x16\x03`: S0-T5 — this appears by chance in multi-MB obfs4 ciphertext
    /// (7 635 153 B carried ~97 hits against ~116 expected) and must NOT be the fixture's rule.
    tls2_c2s: usize,
    tls2_s2c: usize,
    /// Whether every 3-byte hit stands at least 64 B from the next (chance scatter, not a
    /// record layer).
    tls3_isolated_c2s: bool,
    tls3_isolated_s2c: bool,
}

/// Overlapping scan, the chance model S0 measured against.
fn count_tls_prefixes(data: &[u8]) -> (usize, usize) {
    let mut three = 0usize;
    let mut two = 0usize;
    for w in data.windows(3) {
        if w[0] == 0x16 && w[1] == 0x03 {
            two += 1;
            if (0x01..=0x04).contains(&w[2]) {
                three += 1;
            }
        }
    }
    (three, two)
}

/// Chance expectation of the naive 2-byte rule over `n` uniformly random bytes (S0: 116 at
/// 7.6 MB, 97 measured — the model the fixture pins).
fn tls2_chance_expectation(n: usize) -> f64 {
    n.saturating_sub(1) as f64 / 65536.0
}

/// Chance expectation of the 3-byte record-layer signature over `n` uniformly random bytes
/// (the third byte must be 0x01..=0x04: a further factor 4/256). S0's 7.6 MB capture expected
/// ≈ 0 and measured 0; a full bootstrap capture (~20 MB through the PT hop) expects ≈ 5 —
/// the first green run measured exactly 5, scattered.
fn tls3_chance_expectation(n: usize) -> f64 {
    tls2_chance_expectation(n) * 4.0 / 256.0
}

/// Structure check separating chance scatter from a real TLS record layer: a genuine TLS
/// stream produces a signature hit at every record header — records are at most 16 KiB long,
/// so consecutive hits land < 64 B apart in any handshake prefix. Chance hits over MB of
/// obfs4 ciphertext are megabytes apart. A hit with another hit within 64 B means structure.
fn tls3_hits_are_isolated(data: &[u8]) -> bool {
    let mut last: Option<usize> = None;
    for (i, w) in data.windows(3).enumerate() {
        if w[0] == 0x16 && w[1] == 0x03 && (0x01..=0x04).contains(&w[2]) {
            if let Some(l) = last {
                if i - l < 64 {
                    return false;
                }
            }
            last = Some(i);
        }
    }
    true
}

fn capture_stats(c2s: &[u8], s2c: &[u8]) -> CaptureStats {
    let (tls3_c2s, tls2_c2s) = count_tls_prefixes(c2s);
    let (tls3_s2c, tls2_s2c) = count_tls_prefixes(s2c);
    CaptureStats {
        c2s_len: c2s.len(),
        s2c_len: s2c.len(),
        first_c2s: c2s.first().copied(),
        first_s2c: s2c.first().copied(),
        tls3_c2s,
        tls3_s2c,
        tls2_c2s,
        tls2_s2c,
        tls3_isolated_c2s: tls3_hits_are_isolated(c2s),
        tls3_isolated_s2c: tls3_hits_are_isolated(s2c),
    }
}

/// PT-L1's S0-T5-aware rule for a hop that must NOT look like Tor TLS (client↔bridge):
/// no TLS first byte; the 3-byte record-layer signatures present only at chance density,
/// never as a clustered record layer; and the naive 2-byte hits present at chance level
/// (pins the capture non-empty and the fixture's nuance). The absolute-zero 3-byte rule of
/// the first design could not survive a full bootstrap capture: ~20 MB of obfs4 ciphertext
/// expects ≈ 5 chance hits (measured 5, all isolated).
fn assert_no_tls_record_shape(stats: &CaptureStats, hop: &str) {
    assert!(
        stats.first_c2s != Some(0x16) && stats.first_s2c != Some(0x16),
        "{hop}: a TLS-looking first byte: {stats:?}"
    );
    let expect3 = tls3_chance_expectation(stats.c2s_len) + tls3_chance_expectation(stats.s2c_len);
    assert!(
        (stats.tls3_c2s + stats.tls3_s2c) as f64 <= expect3 * 8.0 + 16.0,
        "{hop}: {hits} TLS record-layer signatures (\\x16\\x03\\x0[1-4]) against ≈ {expect3:.0} \
         expected by chance over {} B: a density far above chance is a real TLS record layer \
         inside the capture (PT-L1)",
        stats.c2s_len + stats.s2c_len,
        hits = stats.tls3_c2s + stats.tls3_s2c,
    );
    assert!(
        stats.tls3_isolated_c2s && stats.tls3_isolated_s2c,
        "{hop}: clustered TLS record-layer signatures (hits < 64 B apart): a record layer, \
         not chance scatter — the obfs4 hop must not present a Tor TLS stream (PT-L1): {stats:?}"
    );
    let expect = tls2_chance_expectation(stats.c2s_len);
    assert!(
        stats.tls2_c2s > 0 && (stats.tls2_c2s as f64) < expect * 8.0 + 16.0,
        "{hop}: naive 2-byte hits {hits} are not chance-consistent with {n} B (expect ≈ {expect:.0}): \
         S0-T5's false-positive nuance must hold",
        hits = stats.tls2_c2s,
        n = stats.c2s_len,
    );
}

/// PT-L1's opposite rule for the relay-facing hop: the ORPort MUST present Tor TLS.
fn assert_tor_tls_shape(stats: &CaptureStats, hop: &str) {
    assert!(
        stats.tls3_c2s > 0,
        "{hop}: no TLS record-layer signature in {n} B: the relay-facing hop must \
         present the Tor TLS shape (PT-P2's baseline)",
        n = stats.c2s_len,
    );
    assert_eq!(
        stats.first_c2s,
        Some(0x16),
        "{hop}: TLS must open the stream: {stats:?}"
    );
}

/// Strict TLS record parse: (content_type, record_version_minor) of every record that parses
/// cleanly, stopping at the first malformed header (truncation at the capture end included).
fn tls_record_prefix(data: &[u8]) -> Vec<(u8, u8)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 5 <= data.len() {
        let typ = data[i];
        let minor = data[i + 2];
        let len = u16::from_be_bytes([data[i + 3], data[i + 4]]) as usize;
        if data[i + 1] != 0x03 || !matches!(typ, 20..=23) || !matches!(minor, 1..=4) {
            break;
        }
        if i + 5 + len > data.len() {
            break;
        }
        out.push((typ, minor));
        i += 5 + len;
    }
    out
}

/// PT-P2's byte-class signature of the relay-facing stream: the handshake choreography (the
/// record-type sequence up to the first application-data record) plus the sorted alphabet of
/// record (type, version) pairs over the parseable prefix. Chunking-independent — TCP
/// coalescing changes record *counts*, never the handshake's type sequence or the versions.
#[derive(Debug, PartialEq)]
struct RelayShape {
    handshake: Vec<(u8, u8)>,
    alphabet: Vec<(u8, u8)>,
}

fn relay_shape(data: &[u8]) -> Option<RelayShape> {
    let records = tls_record_prefix(data);
    let handshake_end = records
        .iter()
        .position(|(typ, _)| *typ == 23)
        .unwrap_or(records.len());
    if handshake_end == 0 {
        return None;
    }
    let mut alphabet = records.clone();
    alphabet.sort_unstable();
    alphabet.dedup();
    Some(RelayShape {
        handshake: records[..handshake_end].to_vec(),
        alphabet,
    })
}

// ---------------------------------------------------------------------------
// Disk/log canary (T58, PT-P1)
// ---------------------------------------------------------------------------

/// Every file under `roots` whose bytes contain any needle (the bridge line's fingerprint,
/// cert, or the exact line text).
fn files_containing(roots: &[&Path], needles: &[String]) -> Vec<(PathBuf, String)> {
    fn walk(d: &Path, needles: &[String], out: &mut Vec<(PathBuf, String)>, depth: usize) {
        if depth > 8 {
            return;
        }
        if let Ok(entries) = std::fs::read_dir(d) {
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, needles, out, depth + 1);
                } else if let Ok(bytes) = std::fs::read(&p) {
                    let text = String::from_utf8_lossy(&bytes);
                    for n in needles {
                        if text.contains(n.as_str()) {
                            out.push((p.clone(), n.clone()));
                        }
                    }
                }
            }
        }
    }
    let mut out = Vec::new();
    for root in roots {
        walk(root, needles, &mut out, 0);
    }
    out
}

/// PT-P1's disk canary (T58, amended by S3-T8). Arti 0.46 persists the *configured* bridge's
/// identity in its own guard state (`guards.json` — id keys, PT settings incl. the cert) and
/// the fetched bridge descriptor in its directory cache (`dir.sqlite3`): upstream-designed,
/// C-Tor-equivalent behaviour, no config knob exists to switch it off, and the per-attempt
/// state dir is deleted with the attempt (design §5.3). The canary's corrected scope: no file
/// under the client's state/cache outside arti's own two stores may carry any needle
/// (fingerprint, cert, line), and the full bridge-line *text* must appear nowhere at all —
/// arti stores structured fields, never the line.
fn assert_canary_clean(roots: &[&Path], needles: &[String], line_text: &str, context: &str) {
    let hits = files_containing(roots, needles);
    let outside_artis_own_stores: Vec<_> = hits
        .iter()
        .filter(|(p, _)| {
            p.file_name()
                .map(|n| n != "guards.json" && n != "dir.sqlite3")
                .unwrap_or(true)
        })
        .cloned()
        .collect();
    assert!(
        outside_artis_own_stores.is_empty(),
        "{context}: bridge-line material outside arti's own guard/dir stores: {outside_artis_own_stores:?}"
    );
    // The line text itself must never be persisted verbatim, even inside arti's stores.
    let text_hits = files_containing(roots, std::slice::from_ref(&line_text.to_string()));
    assert!(
        text_hits.is_empty(),
        "{context}: the full bridge-line text was persisted verbatim: {text_hits:?}"
    );
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "loopback PT gate: needs the pinned tor + lyrebird fixtures (third_party/tor-expert/FETCH.sh, lyrebird BUILD.sh HARNESS=1) and the network; runs on dispatch/weekly"]
async fn pt_l1_l2_p1_obfs4_loopback() {
    if let Ok(level) = std::env::var("GHOST_LIVE_LOG") {
        let _ = tracing_subscriber::fmt().with_env_filter(level).try_init();
    }
    let tor = tor_exe();
    let lyrebird = lyrebird_exe();
    let keep = std::env::var("GHOST_PT_KEEP").is_ok();
    let work = std::env::temp_dir().join(format!(
        "ghost-pt-loopback-{}-{}",
        std::process::id(),
        t0().elapsed().as_millis()
    ));
    std::fs::create_dir_all(&work).unwrap();

    phase("fixtures resolved");
    let (echo_port, _echo) = start_echo().await;
    let orport = free_port().await;
    let relay = TorRelay::start(&tor, &work, orport, echo_port);

    // GHOST_PT_PLAINONLY (diagnostic): control run — the same relay over a plain bridge
    // line, no PT anywhere. Discriminates an arti↔C-Tor-bridge dir issue from a PT issue.
    if std::env::var("GHOST_PT_PLAINONLY").is_ok() {
        let proxy_direct = RecordingProxy::start(orport).await;
        let plain_line = format!("127.0.0.1:{} {}", proxy_direct.port, relay.fingerprint);
        let cfg3 = TransportConfig {
            state_dir: work.join("plain-state"),
            cache_dir: work.join("plain-cache"),
            bridge_lines: vec![plain_line],
            pt_dir: None,
        };
        let client3 = TorTransport::create(&cfg3).expect("create the plain-bridge client");
        let t3 = Instant::now();
        client3
            .bootstrap()
            .await
            .expect("plain-bridge control bootstrap");
        phase(&format!(
            "PLAIN-ONLY CONTROL: bootstrapped in {:?}",
            t3.elapsed()
        ));
        // Diagnostic (S3-T6 follow-up): the same onion echo the PT run attempts, over the
        // plain bridge. Discriminates an arti↔C-Tor onion-service data-path issue from a
        // PT-specific one.
        let mut host = None;
        for _ in 0..90 {
            host = relay.onion();
            if host.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        let onion = host.expect("the throwaway v3 onion's hostname appeared");
        // First: a C-Tor client (direct, SOCKS5) to the same service — the S0-shape client.
        // If THIS gets the echo, the service side is healthy and the fault is arti's.
        let ctor_socks = free_port().await;
        let ctor_dir = work.join("ctor-client");
        std::fs::create_dir_all(&ctor_dir).unwrap();
        let ctor_torrc = ctor_dir.join("torrc");
        std::fs::write(
            &ctor_torrc,
            format!(
                "DataDirectory {}\nSocksPort 127.0.0.1:{ctor_socks}\nClientOnly 1\nLog info stdout\n",
                ctor_dir.display().to_string().replace('\\', "/"),
            ),
        )
        .unwrap();
        let mut ctor_cmd = Command::new(tor_exe());
        ctor_cmd.arg("-f").arg(&ctor_torrc).current_dir(&ctor_dir);
        let ctor = ManagedChild::spawn("ctor-client", ctor_cmd, None, None);
        let boot_deadline = Instant::now() + Duration::from_secs(150);
        while Instant::now() < boot_deadline {
            if ctor.log_string().contains("Bootstrapped 100%") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        assert!(
            ctor.log_string().contains("Bootstrapped 100%"),
            "the C-Tor control client never bootstrapped:\n{}",
            ctor.log_tail(4000)
        );
        phase("PLAIN-ONLY: the C-Tor control client bootstrapped (direct)");
        {
            let mut s = tokio::time::timeout(Duration::from_secs(60), dial_loopback(ctor_socks))
                .await
                .expect("socks connect")
                .expect("socks connect");
            s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut buf = vec![0u8; 512];
            let n = s.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], &[0x05, 0x00], "socks greeting rejected: {n}");
            let host_b = onion.as_bytes();
            let mut req = vec![0x05, 0x01, 0x00, 0x03, host_b.len() as u8];
            req.extend_from_slice(host_b);
            req.extend_from_slice(&[0x00, 0x50]);
            s.write_all(&req).await.unwrap();
            let n = tokio::time::timeout(Duration::from_secs(120), s.read(&mut buf))
                .await
                .expect("socks connect reply")
                .unwrap();
            assert_eq!(buf[1], 0x00, "socks CONNECT to the onion refused: {n}");
            phase(&format!(
                "PLAIN-ONLY: C-Tor SOCKS stream to the onion open (echo conns: {})",
                ECHO_CONN_COUNT.load(Ordering::SeqCst)
            ));
            s.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
            match tokio::time::timeout(Duration::from_secs(60), s.read(&mut buf)).await {
                Ok(n) => {
                    let n = n.unwrap();
                    phase(&format!(
                        "PLAIN-ONLY: C-TOR ONION ECHO ANSWERED {n} bytes (echo conns: {}, echo bytes in: {}): {:?}",
                        ECHO_CONN_COUNT.load(Ordering::SeqCst),
                        ECHO_BYTES.load(Ordering::SeqCst),
                        String::from_utf8_lossy(&buf[..n])
                    ));
                }
                Err(_) => panic!(
                    "C-TOR onion answer within 1 minute: echo conns={}, echo bytes in={}",
                    ECHO_CONN_COUNT.load(Ordering::SeqCst),
                    ECHO_BYTES.load(Ordering::SeqCst)
                ),
            }
        }
        drop(ctor);
        let addr = OnionAddress::parse(&format!("{onion}:80")).unwrap();
        let mut stream = tokio::time::timeout(
            Duration::from_secs(120),
            client3.connect(&addr, &IsolationScope::Namespace([9; 32])),
        )
        .await
        .expect("plain onion connect within 2 minutes")
        .expect("plain onion connect");
        phase(&format!(
            "PLAIN-ONLY: onion connected (echo conns: {})",
            ECHO_CONN_COUNT.load(Ordering::SeqCst)
        ));
        stream.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
        stream.flush().await.unwrap();
        let mut buf = vec![0u8; 64];
        match tokio::time::timeout(Duration::from_secs(60), stream.read(&mut buf)).await {
            Ok(n) => {
                let n = n.unwrap();
                phase(&format!(
                    "PLAIN-ONLY: onion answered {n} bytes (echo conns: {}, echo bytes in: {})",
                    ECHO_CONN_COUNT.load(Ordering::SeqCst),
                    ECHO_BYTES.load(Ordering::SeqCst)
                ));
            }
            Err(_) => panic!(
                "PLAIN-ONLY onion answer within 1 minute: echo conns={}, echo bytes in={}",
                ECHO_CONN_COUNT.load(Ordering::SeqCst),
                ECHO_BYTES.load(Ordering::SeqCst)
            ),
        }
        return;
    }

    // Capture point 2 (relay-facing): what the ORPort sees from the PT server.
    // GHOST_PT_NOCAPTURE (diagnostic): run the chain without the recording proxies, to
    // isolate a stall to the proxies or the PT chain itself.
    let nocap = std::env::var("GHOST_PT_NOCAPTURE").is_ok();
    let proxy_orport = RecordingProxy::start(orport).await;
    let server_bind = free_port().await;
    let orport_target = if nocap { orport } else { proxy_orport.port };
    let mut server = LyrebirdServer::start(&lyrebird, &work, server_bind, orport_target);

    // Capture point 1 (the PT hop): between arti's PT client and the lyrebird server.
    let proxy_bridge = RecordingProxy::start(server_bind).await;
    let bridge_target = if nocap {
        server_bind
    } else {
        proxy_bridge.port
    };

    // The client-side PT binary: ptmgr execs <pt_dir>/lyrebird (directly on the host, S3-T1).
    let pt_client_dir = work.join("pt-client");
    std::fs::create_dir_all(&pt_client_dir).unwrap();
    let pt_client_bin = pt_client_dir.join("lyrebird");
    std::fs::copy(&lyrebird, &pt_client_bin).unwrap();

    let bridge_line = format!(
        "obfs4 127.0.0.1:{} {} cert={} iat-mode=0",
        bridge_target, relay.fingerprint, server.cert
    );
    let needles = vec![
        relay.fingerprint.clone(),
        server.cert.clone(),
        bridge_line.clone(),
    ];

    // -- PT-L2: bootstrap through the obfs4 bridge to 100% ----------------------------
    let state1 = work.join("client1-state");
    let cache1 = work.join("client1-cache");
    let cfg1 = TransportConfig {
        state_dir: state1.clone(),
        cache_dir: cache1.clone(),
        bridge_lines: vec![bridge_line.clone()],
        pt_dir: Some(pt_client_dir.clone()),
    };
    let client1 = TorTransport::create(&cfg1).expect("create the PT client");
    let t_boot = Instant::now();
    // Drive the bootstrap while polling for the throwaway onion's hostname (written as soon
    // as the service key exists, usually well before the bootstrap finishes).
    let mut host: Option<String> = None;
    let boot_secs = {
        let mut boot = Box::pin(client1.bootstrap());
        loop {
            tokio::select! {
                r = &mut boot => {
                    if let Err(e) = r {
                        // Forensics before the assert fires: which hop saw bytes, and what the
                        // children logged (a spawn failure, a refused ORPort, a bad cert…).
                        panic!(
                            "bootstrap through the local obfs4 bridge failed: {e}\n\
                             pt-hop c2s={} s2c={} bytes; relay-facing c2s={} s2c={} bytes\n\
                             --- relay log tail ---\n{}\n--- lyrebird server log tail ---\n{}",
                            proxy_bridge.c2s_len(),
                            proxy_bridge.s2c_len(),
                            proxy_orport.c2s_len(),
                            proxy_orport.s2c_len(),
                            relay.child.log_tail(4000),
                            server.child.log_tail(4000),
                        );
                    }
                    break t_boot.elapsed();
                }
                _ = tokio::time::sleep(Duration::from_secs(1)) => {
                    if host.is_none() {
                        host = relay.onion();
                    }
                }
            }
        }
    };
    assert!(
        boot_secs <= BOOTSTRAP_DEADLINE,
        "bootstrap {boot_secs:?} exceeded the deadline"
    );
    phase(&format!(
        "PT-L2: arti bootstrapped 100% through obfs4 in {boot_secs:?}"
    ));

    // The bootstrap actually rode the PT: bytes on both capture points.
    let pt_c2s = proxy_bridge.take_c2s();
    let pt_s2c = proxy_bridge.take_s2c();
    assert!(
        pt_c2s.len() > 1024 * 1024,
        "the PT hop carried only {} B: nothing bootstrapped through the bridge",
        pt_c2s.len()
    );

    // -- A directory-validated circuit through the PT, proven by the harness's onion --
    let onion = host.expect("the throwaway v3 onion's hostname appeared");
    let addr = OnionAddress::parse(&format!("{onion}:80")).unwrap();
    let connect = |scope: IsolationScope| {
        let t = &client1;
        let a = &addr;
        async move {
            // Fresh isolated HS circuits cross the real network's intro/rendezvous points
            // through the bridge: measured 4 s to 80 s across runs, once >120 s — the budget
            // is generous, the deadline still bounds a genuinely stuck attempt.
            tokio::time::timeout(Duration::from_secs(300), t.connect(a, &scope))
                .await
                .expect("onion connect within 5 minutes")
                .expect("onion connect through the PT")
        }
    };
    let mut stream_a = connect(IsolationScope::Namespace([7; 32])).await;
    phase(&format!(
        "onion stream a connected (echo conns so far: {})",
        ECHO_CONN_COUNT.load(Ordering::SeqCst)
    ));
    // Arti's DataWriter coalesces sub-cell writes: without poll_flush the 18-byte request
    // sits in the cell buffer forever (tor-proto's documented contract) — the flush is what
    // puts the DATA cell on the wire.
    stream_a.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
    stream_a.flush().await.unwrap();
    let mut buf = vec![0u8; 64];
    let n = match tokio::time::timeout(Duration::from_secs(60), stream_a.read(&mut buf)).await {
        Ok(n) => n.unwrap(),
        Err(_) => panic!(
            "onion answer within 1 minute: echo conns={}, echo bytes in={} (0 bytes in means \
             the client's GET never reached the onion service's backend; >0 means the echo \
             answered but the response never reached the client)\n\
             pt-hop since bootstrap: c2s={} s2c={} B; relay-facing since bootstrap: c2s={} s2c={} B\n\
             --- relay log tail ---\n{}",
            ECHO_CONN_COUNT.load(Ordering::SeqCst),
            ECHO_BYTES.load(Ordering::SeqCst),
            proxy_bridge.c2s_len(),
            proxy_bridge.s2c_len(),
            proxy_orport.c2s_len(),
            proxy_orport.s2c_len(),
            relay.child.log_tail(200000),
        ),
    };
    phase(&format!(
        "onion read returned {n} bytes (echo conns: {}, echo bytes in: {})",
        ECHO_CONN_COUNT.load(Ordering::SeqCst),
        ECHO_BYTES.load(Ordering::SeqCst)
    ));
    assert!(
        n > 0 && buf[..n].windows(14).any(|w| w == b"pt-loopback-ok"),
        "the onion stream must answer the harness's echo: {:?}",
        String::from_utf8_lossy(&buf[..n])
    );
    phase("onion stream through the PT answered the echo");

    let stream_b = connect(IsolationScope::Namespace([8; 32])).await;
    let tunnel = |s: &arti_client::DataStream| {
        s.client_stream_ctrl()
            .and_then(|c| c.tunnel())
            .expect("stream is attached to a tunnel")
    };
    assert!(
        !Arc::ptr_eq(&tunnel(&stream_a), &tunnel(&stream_b)),
        "two isolation scopes must ride two circuits after a PT bootstrap (PT-L2 assertion 4)"
    );
    phase("two isolation scopes ride two circuits");
    drop(stream_a);
    drop(stream_b);

    assert_eq!(
        TorTransport::keystore_files_for_tests(&state1),
        Vec::<PathBuf>::new(),
        "the keystore must stay empty after a real PT bootstrap (Phase 6 invariant)"
    );

    // -- PT-L1: the client↔bridge capture has no Tor TLS record shape -----------------
    let pt_stats = capture_stats(&pt_c2s, &pt_s2c);
    phase(&format!("PT-L1 capture: {pt_stats:?}"));
    assert_no_tls_record_shape(&pt_stats, "client↔bridge (obfs4)");

    // -- PT-P2's PT half: the relay-facing capture presents Tor TLS --------------------
    let or_c2s = proxy_orport.take_c2s();
    let or_s2c = proxy_orport.take_s2c();
    let or_stats = capture_stats(&or_c2s, &or_s2c);
    phase(&format!("relay-facing (via PT) capture: {or_stats:?}"));
    assert_tor_tls_shape(&or_stats, "bridge→ORPort");
    let shape_pt =
        relay_shape(&or_c2s).expect("the relay-facing PT stream parses as a TLS record prefix");

    // -- PT-P1: T58's canary after a real bootstrap ------------------------------------
    assert_canary_clean(
        &[&state1, &cache1],
        &needles,
        &bridge_line,
        "PT-P1 after a real PT bootstrap",
    );
    // The child-log half of T58's canary mirrors G-T7's fixture rule: the forbidden sink is
    // the line *shape* (`obfs4 ip:port FP`) and `cert=` material. The relay's bare fingerprint
    // is NOT a needle — the relay legitimately announces its own identity in its log (the
    // committed fixture's rule, pt-no-bridge-line-in-logs.sh, pins exactly this).
    let logs = format!("{}{}", relay.child.log_string(), server.child.log_string());
    for line in logs.lines() {
        assert!(
            !(line.contains("obfs4") && line.contains(&relay.fingerprint)),
            "PT-P1: a bridge-line shape in the harness logs: {line}"
        );
    }
    for needle in &[server.cert.clone(), bridge_line.clone()] {
        assert!(
            !logs.contains(needle.as_str()),
            "PT-P1: bridge-line material in the harness logs: {needle}\n\
             --- server log tail ---\n{}\n--- relay log tail ---\n{}",
            server.child.log_tail(3000),
            relay.child.log_tail(2000),
        );
    }
    phase("PT-P1: no bridge-line material on disk or in the child logs");

    // -- PT-P1: the PT process dies mid-attempt -----------------------------------------
    // A second client starts its bootstrap through the same bridge; once its obfs4 handshake
    // is on the wire, the lyrebird SERVER process is killed: the PT path dies mid-attempt.
    let state2 = work.join("client2-state");
    let cache2 = work.join("client2-cache");
    let cfg2 = TransportConfig {
        state_dir: state2.clone(),
        cache_dir: cache2.clone(),
        bridge_lines: vec![bridge_line.clone()],
        pt_dir: Some(pt_client_dir.clone()),
    };
    let client2 = TorTransport::create(&cfg2).expect("create the second PT client");
    let c2s_before = proxy_bridge.c2s_len();
    // Drive the second bootstrap until its obfs4 handshake is on the wire (the attempt is
    // genuinely mid-flight), then kill the lyrebird SERVER process: the PT path dies
    // mid-attempt from the client's point of view.
    let mut boot2 = Box::pin(client2.bootstrap());
    let saw_second_handshake = loop {
        tokio::select! {
            r = &mut boot2 => panic!(
                "the second bootstrap finished before the kill landed: {r:?}"
            ),
            _ = tokio::time::sleep(Duration::from_millis(250)) => {
                if proxy_bridge.c2s_len() > c2s_before {
                    break true;
                }
            }
        }
    };
    assert!(
        saw_second_handshake,
        "the second client's obfs4 handshake never reached the bridge"
    );
    phase("second client is mid-attempt through the PT; killing the lyrebird server");
    server.child.kill();
    // The bootstrap must not succeed against a dead PT server; give arti's retries a moment,
    // then abandon the attempt (the harness's own abort path) and scan.
    let outcome = tokio::select! {
        r = &mut boot2 => Some(r),
        _ = tokio::time::sleep(Duration::from_secs(20)) => None,
    };
    assert!(
        outcome.as_ref().map(|r| r.is_err()).unwrap_or(true),
        "a bootstrap succeeded although the PT server was killed mid-attempt: {outcome:?}"
    );
    drop(boot2);
    drop(client2);
    assert_canary_clean(
        &[&state2, &cache2],
        &needles,
        &bridge_line,
        "PT-P1 after a mid-attempt PT process death",
    );
    phase("PT-P1: mid-attempt process death left no bridge-line material");

    // -- PT-P2's direct half: the same relay over a plain bridge line ---------------------
    let proxy_direct = RecordingProxy::start(orport).await;
    let plain_line = format!("127.0.0.1:{} {}", proxy_direct.port, relay.fingerprint);
    let state3 = work.join("client3-state");
    let cache3 = work.join("client3-cache");
    let cfg3 = TransportConfig {
        state_dir: state3.clone(),
        cache_dir: cache3.clone(),
        bridge_lines: vec![plain_line],
        pt_dir: None,
    };
    let client3 = TorTransport::create(&cfg3).expect("create the plain-bridge client");
    let t3 = Instant::now();
    client3.bootstrap().await.expect("plain-bridge bootstrap");
    phase(&format!("plain-bridge bootstrap in {:?}", t3.elapsed()));
    if std::env::var("GHOST_PT_PLAINONLY").is_ok() {
        phase("GHOST_PT_PLAINONLY: returning after the plain-bridge control");
        return;
    }
    drop(client3);
    let dir_c2s = proxy_direct.take_c2s();
    let shape_direct = relay_shape(&dir_c2s)
        .expect("the relay-facing direct stream parses as a TLS record prefix");
    phase(&format!("relay shape (PT):     {shape_pt:?}"));
    phase(&format!("relay shape (direct): {shape_direct:?}"));
    assert_eq!(
        shape_pt, shape_direct,
        "PT-P2: the relay-visible byte class must be identical on the PT and the direct path"
    );

    // -- The records for the privacy fixtures ----------------------------------------------
    let record = format!(
        "# ghost pt-loopback relay-shape record (measured, one run; the privacy harness fixture)\n\
         # pt path:      c2s={pt_len} bytes\n\
         # direct path:  c2s={dir_len} bytes\n\
         pt      handshake={pt_hand:?} alphabet={pt_alpha:?}\n\
         direct  handshake={dir_hand:?} alphabet={dir_alpha:?}\n",
        pt_len = or_c2s.len(),
        dir_len = dir_c2s.len(),
        pt_hand = shape_pt.handshake,
        pt_alpha = shape_pt.alphabet,
        dir_hand = shape_direct.handshake,
        dir_alpha = shape_direct.alphabet,
    );
    // G-T7's run-log fixture: the harness's own phase output + the two children captures.
    // The server's SMETHOD negotiation is redacted at the capture layer (the transport cert
    // is the line's cert= material; T58) — everything else is the verbatim run record.
    let run_log = format!(
        "{}\n\n--- tor-relay log ---\n{}\n--- lyrebird-server log (SMETHOD ARGS redacted) ---\n{}",
        phases_log(),
        relay.child.log_string(),
        server.child.log_string(),
    );
    let record_dir = work.join("record");
    std::fs::create_dir_all(&record_dir).unwrap();
    std::fs::write(record_dir.join("pt-relay-shape.txt"), &record).unwrap();
    std::fs::write(record_dir.join("harness-run.log"), &run_log).unwrap();
    if let Ok(dir) = std::env::var("GHOST_PT_RECORD_DIR") {
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(Path::new(&dir).join("pt-relay-shape.txt"), &record).unwrap();
        std::fs::write(Path::new(&dir).join("harness-run.log"), &run_log).unwrap();
    }
    phase(&format!(
        "shape record + run log written under {}",
        record_dir.display()
    ));

    // -- Teardown --------------------------------------------------------------------------
    drop(relay);
    drop(proxy_bridge);
    drop(proxy_orport);
    drop(proxy_direct);
    if keep {
        phase(&format!(
            "GHOST_PT_KEEP=1: workdir kept at {}",
            work.display()
        ));
    } else {
        let _ = std::fs::remove_dir_all(&work);
    }
}

// ---------------------------------------------------------------------------
// The classifier's fast in-CI half (no network): PT-L1's S0-T5 nuance pinned in-process
// ---------------------------------------------------------------------------

#[test]
fn capture_classifier_units() {
    // A real TLS ClientHello opens with the record-layer signature the fixture looks for.
    let mut tls = vec![0x16, 0x03, 0x01, 0x00, 0x2c];
    tls.extend_from_slice(&[0x01; 0x2c]);
    tls.extend_from_slice(&[0x14, 0x03, 0x01, 0x00, 0x01, 0x01]); // change_cipher_spec
    tls.extend_from_slice(&[0x17, 0x03, 0x01, 0x00, 0x10]);
    tls.extend_from_slice(&[0xaa; 0x10]);
    let prefix = tls_record_prefix(&tls);
    assert_eq!(prefix, vec![(0x16, 1), (0x14, 1), (0x17, 1)]);
    let shape = relay_shape(&tls).expect("tls parses");
    assert_eq!(shape.handshake, vec![(0x16, 1), (0x14, 1)]);
    assert!(shape.alphabet.contains(&(0x17, 1)));

    // obfs4-shaped noise: no TLS shape, first byte random, and the naive 2-byte rule fires at
    // chance level only — the S0-T5 regression vector (97 hits at 7 635 153 B, ≈116 expected).
    let n = 7_635_153usize;
    let expect = tls2_chance_expectation(n);
    assert!((expect - 116.5).abs() < 1.0, "S0's chance model: {expect}");
    // A deterministic stand-in stream: xorshift bytes; assert the 3-byte rule stays clean over
    // 8 MB while the 2-byte rule fires often (a fixture banning the naive rule would fail).
    let mut state = 0x9e3779b97f4a7c15u64;
    let mut noise = Vec::with_capacity(8 << 20);
    while noise.len() < (8 << 20) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        noise.extend_from_slice(&state.to_le_bytes());
    }
    let (three, two) = count_tls_prefixes(&noise);
    assert_eq!(three, 0, "no TLS record signature in noise: {three}");
    assert!(
        two > 0,
        "the naive 2-byte rule MUST fire on noise (S0-T5): the fixture's nuance"
    );
    let stats = capture_stats(&noise, &noise);
    assert_no_tls_record_shape(&stats, "noise");

    // Truncation is not a crash: a cut inside a record yields the records before it (a cut
    // inside the FIRST record yields none — the strict parse never invents a record).
    assert_eq!(tls_record_prefix(&tls[..20]), Vec::<(u8, u8)>::new());
    assert_eq!(tls_record_prefix(&tls[..49]), vec![(0x16, 1)]);
    assert_eq!(tls_record_prefix(&tls[..50]), vec![(0x16, 1)]);
    assert!(relay_shape(&[0x17, 0x03, 0x01, 0x00, 0x10]).is_none());
}
