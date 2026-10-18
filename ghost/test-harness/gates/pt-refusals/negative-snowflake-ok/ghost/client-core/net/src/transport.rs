//! Embedded Tor transport (Arti). Connections are only ever made to [`OnionAddress`] values with
//! an explicit isolation token; the Arti client itself is not exposed outside this crate.
//!
//! Creation and bootstrap are separate so the caller can abort a bootstrap that stalls on a
//! censored network and switch to bridges (ADR-16 auto mode). Bridges are optional plain
//! `IP:PORT FINGERPRINT` lines or pluggable-transport lines (`obfs4 …`, `webtunnel …`, validated
//! by [`bridge_line`]); PT lines run through arti's managed `pt-client` support (tor-ptmgr)
//! launching the extracted, hash-verified lyrebird binary from `pt_dir` **through the system
//! dynamic linker** — the exec target is `/system/bin/linker(64)` and the binary is its first
//! argument (rev 3, §5.4.5/OA-4: a direct execve of a filesDir binary is SELinux-denied for
//! targetSdk ≥ 29).
//! `snowflake` and every other name stay refused (Phase 12b). There is no non-Tor mode.

use crate::bridge_line;
use crate::isolation::{IsolationScope, Isolations};
use crate::onion::OnionAddress;
use arti_client::config::{BridgeConfigBuilder, CfgPath, TorClientConfigBuilder};
use arti_client::{BootstrapBehavior, DataStream, ErrorKind, HasKind, StreamPrefs, TorClient};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tor_config::ExplicitOrAuto;
use tor_guardmgr::VanguardMode;
use tor_rtcompat::PreferredRuntime;

/// Upper bound for one bootstrap attempt. Arti's own directory retries are uncapped on a blocked
/// network; the caller gets a `tor_bootstrap_timeout` instead of an indefinite block.
pub const BOOTSTRAP_DEADLINE: Duration = Duration::from_secs(180);

/// The lyrebird executable inside [`TransportConfig::pt_dir`], extracted from the APK assets and
/// hash-verified by the Android side (design §5.4; ADR-61 point 5).
pub const LYREBIRD_BINARY: &str = "lyrebird";

#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Directory for Tor state and directory cache (must be app-private, no-backup).
    pub state_dir: PathBuf,
    pub cache_dir: PathBuf,
    /// Bridge lines: plain `IP:PORT FINGERPRINT` or, with `pt_dir` set, `obfs4 …`/`webtunnel …`
    /// lines (validated by [`bridge_line`]); empty = direct Tor. `snowflake …` and every other
    /// shape is refused as a configuration error (Phase 12b).
    pub bridge_lines: Vec<String>,
    /// Directory holding the extracted, hash-verified PT binaries (`<abi>/lyrebird` under the
    /// app's filesDir/pt; design §5.2). `None` = PT unavailable: PT bridge lines are then rejected
    /// with [`TransportError::PtBinaryMissing`].
    pub pt_dir: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub enum TransportError {
    /// Invalid configuration: an unsupported or malformed bridge line.
    Config(String),
    /// A pluggable-transport bridge line was configured but the PT binary is unavailable:
    /// `pt_dir` is `None` or the hash-verified lyrebird does not exist there. A config error at
    /// create time, never a bootstrap-time hang (design §5.2).
    PtBinaryMissing,
    /// The PT child cannot be launched because the system dynamic linker for this ABI is
    /// absent (rev 3, §5.4.5/OA-4: the exec target is the linker itself, not the filesDir
    /// binary — direct execve of `app_data_file` is SELinux-denied for targetSdk ≥ 29, while
    /// mmap-exec is granted). Config class, like [`Self::PtBinaryMissing`].
    PtLinkerMissing,
    /// The Tor client could not be set up locally: state or cache directory unusable
    /// (permissions, disk full, read-only), directory cache or keystore failed to open. Nothing
    /// to do with bridges. (A state directory locked by another live client is NOT reported: Arti
    /// then runs with read-only state, so two transports must never share a state directory.)
    Setup(String),
    /// Bootstrap failed with an error. The client cannot bootstrap again (see [`Self::BootstrapSpent`]).
    Bootstrap(String),
    /// The bootstrap deadline passed. The client cannot bootstrap again.
    BootstrapTimeout,
    /// An earlier bootstrap attempt on this client failed, timed out or was aborted. Arti may keep
    /// the abandoned directory task and would report a later bootstrap on the same client as done
    /// without a usable directory, so the client must be closed and a new one created.
    BootstrapSpent,
    /// A connection was requested before a successful bootstrap. Connections never start a
    /// bootstrap implicitly (Arti runs in manual bootstrap mode).
    NotBootstrapped,
    Connect(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Config(m) => write!(f, "tor config: {m}"),
            TransportError::PtBinaryMissing => f.write_str(
                "tor config: pluggable-transport bridge lines need the extracted PT binary",
            ),
            TransportError::PtLinkerMissing => {
                f.write_str("tor config: the system dynamic linker for the PT child is absent")
            }
            TransportError::Setup(m) => write!(f, "tor setup: {m}"),
            TransportError::Bootstrap(m) => write!(f, "tor bootstrap: {m}"),
            TransportError::BootstrapTimeout => f.write_str("tor bootstrap timed out"),
            TransportError::BootstrapSpent => {
                f.write_str("tor bootstrap already failed on this client; create a new one")
            }
            TransportError::NotBootstrapped => f.write_str("tor is not bootstrapped"),
            TransportError::Connect(m) => write!(f, "onion connect: {m}"),
        }
    }
}

impl std::error::Error for TransportError {}

pub struct TorTransport {
    client: Arc<TorClient<PreferredRuntime>>,
    isolations: Isolations,
    /// Set when a bootstrap attempt did not end in success (error, deadline or dropped future).
    bootstrap_abandoned: AtomicBool,
    /// Serializes bootstrap attempts, so an attempt waiting behind one that fails sees the flag.
    bootstrap_lock: tokio::sync::Mutex<()>,
}

/// Marks the bootstrap as abandoned unless disarmed by an attempt that succeeded.
struct AbandonGuard<'a> {
    flag: &'a AtomicBool,
    completed: bool,
}

impl Drop for AbandonGuard<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.flag.store(true, Ordering::SeqCst);
        }
    }
}

impl TorTransport {
    /// Builds the Arti configuration: onion addresses allowed, vanguards-lite, bridges as
    /// configured. Every bridge line is validated against the grammar table before arti sees it
    /// (design §3.3: the snowflake branch of arti's parser never runs); PT lines additionally
    /// require the extracted lyrebird binary, checked here so a missing binary is a config error,
    /// not a bootstrap-time hang.
    pub fn build_config(
        cfg: &TransportConfig,
    ) -> Result<arti_client::TorClientConfig, TransportError> {
        let mut b = TorClientConfigBuilder::default();
        b.storage()
            .state_dir(CfgPath::new_literal(cfg.state_dir.clone()))
            .cache_dir(CfgPath::new_literal(cfg.cache_dir.clone()));
        b.address_filter().allow_onion_addrs(true);
        // Every GHOST circuit ends at a relay operator's onion service: pin vanguards-lite so a
        // malicious operator cannot walk rendezvous circuits to the client's guard (Prop 333).
        b.vanguards()
            .mode(ExplicitOrAuto::Explicit(VanguardMode::Lite));
        if !cfg.bridge_lines.is_empty() {
            let set = bridge_line::validate_set(&cfg.bridge_lines).map_err(|e| {
                TransportError::Config(format!("bridge line {}: {}", e.index, e.error))
            })?;
            if set.iter().any(|(_, kind)| kind.needs_pt_binary()) {
                let (linker, binary) = pt_exec(cfg)?;
                // The child inherits arti's process environment (S0-T4: ptmgr overlays TOR_PT_*
                // on the inherited environment, no env_clear), so GHOST scrubs its own process
                // environment before any PT-spawning client exists (design §5.3).
                scrub_pt_child_env(&cfg.state_dir);
                let mut transport = arti_client::config::pt::TransportConfigBuilder::default();
                transport
                    .protocols(
                        ["obfs4", "webtunnel"]
                            .iter()
                            .map(|name| {
                                name.parse::<arti_client::config::PtTransportName>()
                                    .expect("static transport names parse")
                            })
                            .collect(),
                    )
                    // Rev 3 (§5.4.5, OA-4 resolution): on Android the exec target is the
                    // *system linker* and the verified binary's absolute path is its first
                    // argument — a direct execve of a filesDir binary is SELinux-denied for
                    // targetSdk ≥ 29 (execute_no_trans on app_data_file), while mmap-exec is
                    // granted — running the binary through the linker needs exactly the
                    // granted permissions and no arti patch (ptmgr's config is `path` +
                    // `arguments`). Off-device (host builds, the §12.3 loopback harness)
                    // `pt_exec` returns the binary itself for a direct exec (S3-T1).
                    .path(CfgPath::new_literal(linker))
                    .arguments(binary)
                    // ptmgr 0.46 launches managed PTs lazily on first channel use (the flag is
                    // stored but unread there); pinning the lazy policy keeps client creation
                    // spawn-free, so a PT process appears only when a bootstrap actually uses one.
                    .run_on_startup(false);
                b.bridges().transports().push(transport);
            }
            for (index, _) in &set {
                let line = &cfg.bridge_lines[*index];
                let bridge: BridgeConfigBuilder = line
                    .parse()
                    .map_err(|e| TransportError::Config(format!("bridge line {index}: {e}")))?;
                b.bridges().bridges().push(bridge);
            }
            b.bridges()
                .enabled(arti_client::config::BoolOrAuto::Explicit(true));
        }
        b.build()
            .map_err(|e| TransportError::Config(format!("{e}")))
    }

    /// Installs the process-wide rustls crypto provider (ring) used by Arti's directory client.
    /// Idempotent: a second call is a no-op.
    pub fn install_crypto_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    /// Creates the Tor client without touching the network. Must run inside a tokio runtime
    /// context. Call [`TorTransport::bootstrap`] next. Bridge-line errors are
    /// [`TransportError::Config`]; local setup failures are [`TransportError::Setup`].
    pub fn create(cfg: &TransportConfig) -> Result<Self, TransportError> {
        Self::install_crypto_provider();
        let config = Self::build_config(cfg)?;
        let client = TorClient::builder()
            .config(config)
            // Only bootstrap() bootstraps: a relay call before it fails fast (NotBootstrapped)
            // instead of starting an untracked bootstrap that its RPC deadline could abandon.
            .bootstrap_behavior(BootstrapBehavior::Manual)
            .create_unbootstrapped()
            .map_err(|e| TransportError::Setup(format!("{e}")))?;
        Ok(TorTransport {
            client,
            isolations: Isolations::default(),
            bootstrap_abandoned: AtomicBool::new(false),
            bootstrap_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// Bootstraps the directory and guards, bounded by [`BOOTSTRAP_DEADLINE`]. Fails closed: no
    /// fallback transport exists. The future can be dropped to abort the attempt. After any
    /// failure (error, timeout or abort) this client only returns
    /// [`TransportError::BootstrapSpent`]: close it and create a new one for another attempt.
    /// Concurrent calls are serialized; a successful bootstrap may be awaited again (no-op).
    pub async fn bootstrap(&self) -> Result<(), TransportError> {
        self.bootstrap_within(BOOTSTRAP_DEADLINE).await
    }

    async fn bootstrap_within(&self, deadline: Duration) -> Result<(), TransportError> {
        // Declared before the guard: on every exit the guard drops (and sets the flag) first,
        // then the lock is released, so a waiting attempt always sees a failed one.
        let _serial = self.bootstrap_lock.lock().await;
        if self.bootstrap_abandoned.load(Ordering::SeqCst) {
            return Err(TransportError::BootstrapSpent);
        }
        let mut guard = AbandonGuard {
            flag: &self.bootstrap_abandoned,
            completed: false,
        };
        // Any non-success leaves the guard armed: the client is spent.
        match tokio::time::timeout(deadline, self.client.bootstrap()).await {
            Ok(Ok(())) => {
                guard.completed = true;
                Ok(())
            }
            Ok(Err(e)) => Err(TransportError::Bootstrap(format!("{e}"))),
            Err(_) => Err(TransportError::BootstrapTimeout),
        }
    }

    /// Opens a stream to an onion address on the circuit set owned by `scope`.
    pub async fn connect(
        &self,
        addr: &OnionAddress,
        scope: &IsolationScope,
    ) -> Result<DataStream, TransportError> {
        connect_isolated(&self.client, addr, self.isolations.token_for(scope)).await
    }

    /// Regular files under `state_dir/keystore` (empty if the directory does not exist). Used by
    /// tests to prove the client stores no keys there.
    #[doc(hidden)]
    pub fn keystore_files_for_tests(state_dir: &std::path::Path) -> Vec<PathBuf> {
        keystore_files(state_dir)
    }

    /// Drops every isolation token; the next request per scope builds fresh circuits.
    pub fn rotate_circuits(&self) {
        self.isolations.rotate_all();
    }

    /// Ends an issuer flow (Phase 8 design §11.7): its isolation token is dropped, so no later call
    /// reuses the flow's circuits. Unknown flows are ignored.
    pub fn end_issuer_flow(&self, flow: &[u8; 16]) {
        self.isolations.end_flow(flow);
    }

    pub(crate) fn client(&self) -> Arc<TorClient<PreferredRuntime>> {
        Arc::clone(&self.client)
    }

    pub(crate) fn isolation_token(&self, scope: &IsolationScope) -> arti_client::IsolationToken {
        self.isolations.token_for(scope)
    }
}

fn keystore_files(state_dir: &std::path::Path) -> Vec<PathBuf> {
    fn walk(d: &std::path::Path, out: &mut Vec<PathBuf>) {
        if let Ok(entries) = std::fs::read_dir(d) {
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else {
                    out.push(p);
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(&state_dir.join("keystore"), &mut out);
    out
}

/// Resolves the PT launch shape for a config that contains PT bridge lines (rev 3, §5.4.5,
/// OA-4 resolved): `pt_dir` must be set and `lyrebird` must exist inside it (design §5.2 — the
/// up-front check so a missing binary is a create-time config error, not a bootstrap-time
/// hang; the binary's hash was verified at extraction time by the Android side, PT-1/S2).
///
/// The launch shape is platform-split (S3-T1):
/// - **Android**: `(system linker, [binary path])` — the linker is exec'ed and the binary is
///   its first argument, never a direct execve of the filesDir file (SELinux
///   `execute_no_trans` denies that for targetSdk ≥ 29; mmap-exec is granted, which is all the
///   linker needs).
/// - **Every other host** (the §8.4 host build and S3's loopback harness): `(binary, [])` —
///   the verified binary is exec'ed directly; the SELinux rule has no counterpart off-device.
fn pt_exec(cfg: &TransportConfig) -> Result<(PathBuf, Vec<String>), TransportError> {
    let binary = pt_binary(cfg)?;
    #[cfg(target_os = "android")]
    {
        let linker = pt_linker()?;
        Ok((linker, vec![binary.to_string_lossy().into_owned()]))
    }
    #[cfg(not(target_os = "android"))]
    {
        Ok((binary, Vec::new()))
    }
}

/// The system dynamic linker for this process's ABI (rev 3, §5.4.5). Resolved at runtime from
/// the compiled target (`std::env::consts::ARCH` — the same selection that picked the ABI's
/// `libghost_client_net.so` and the extracted binary): 64-bit ABIs (both shipped ones)
/// interpret through `/system/bin/linker64`, 32-bit ABIs through `/system/bin/linker`. The
/// linker's own existence is verified here; a device without it cannot launch any PT child
/// and gets the typed [`TransportError::PtLinkerMissing`] (config class) at create time.
/// Android-only: off-device `pt_exec` execs the binary directly (S3-T1), so the host build
/// never resolves a linker (and stays unit-testable without a `/system/bin`).
#[cfg(target_os = "android")]
fn pt_linker() -> Result<PathBuf, TransportError> {
    let name = match std::env::consts::ARCH {
        "aarch64" | "x86_64" => "linker64",
        // 32-bit ABIs are not shipped today (SHIPPED_ABIS is 64-bit only); the arm|x86 names
        // keep the resolution total for a future ABI addition.
        "arm" | "x86" | "x86_32" => "linker",
        _ => return Err(TransportError::PtLinkerMissing),
    };
    let path = PathBuf::from("/system/bin").join(name);
    // The host build (§8.4) has no /system/bin: config-build must stay unit-testable there, and
    // PT never spawns off-device (ptmgr launches lazily; the suites run stand-in binaries).
    // The existence gate is therefore Android-only; on Android it is the product path.
    #[cfg(target_os = "android")]
    if !path.is_file() {
        return Err(TransportError::PtLinkerMissing);
    }
    Ok(path)
}

/// Resolves the extracted lyrebird binary: `pt_dir` must be set and `lyrebird` must exist
/// inside it (design §5.2). The binary's hash was verified at extraction time by the Android
/// side (PT-1, slice S2); here only existence is checked.
fn pt_binary(cfg: &TransportConfig) -> Result<PathBuf, TransportError> {
    let dir = cfg.pt_dir.as_ref().ok_or(TransportError::PtBinaryMissing)?;
    let binary = dir.join(LYREBIRD_BINARY);
    if binary.is_file() {
        Ok(binary)
    } else {
        Err(TransportError::PtBinaryMissing)
    }
}

/// Environment variables a PT child must not see (design §5.3): every proxy variable (a PT makes
/// its own connections; an inherited proxy would reroute and de-anonymise them) and `HOME`
/// (must not point at readable storage). `TMPDIR` is redirected into the attempt's own
/// app-private state directory.
const PT_ENV_STRIP: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    "HOME",
];

/// Sanitises the process environment before the first PT-spawning client is created.
///
/// S0-T4 (evidence §5): ptmgr spawns with `Command::new(path).args(arguments).envs(TOR_PT_*)` —
/// the child **inherits arti's full process environment**; there is no env_clear or scrub on the
/// arti side. The scrub is therefore GHOST's own job and can only be process-wide (ptmgr exposes
/// no per-spawn environment hook). The variables are removed, not edited; removal is idempotent,
/// and a PT child inherits the app's (Android: already minimal) environment plus nothing that
/// names the user. Idempotent and cheap: runs on every PT config build.
fn scrub_pt_child_env(state_dir: &Path) {
    for var in PT_ENV_STRIP {
        std::env::remove_var(var);
    }
    // The attempt's state dir already exists at this point (arti's storage layer created it by
    // the time a PT could spawn); redirecting TMPDIR there keeps any child temp file inside the
    // per-attempt dir that the caller deletes with the attempt (design §5.3).
    std::env::set_var("TMPDIR", state_dir);
}

/// The only place in the crate that opens a Tor stream (clippy `disallowed-methods` bans the Arti
/// dial methods everywhere else): one onion address, one explicit isolation token.
#[allow(clippy::disallowed_methods)]
pub(crate) async fn connect_isolated(
    client: &TorClient<PreferredRuntime>,
    addr: &OnionAddress,
    isolation: arti_client::IsolationToken,
) -> Result<DataStream, TransportError> {
    let mut prefs = StreamPrefs::new();
    prefs.set_isolation(isolation);
    client
        .connect_with_prefs((addr.host(), addr.port()), &prefs)
        .await
        .map_err(|e| match e.kind() {
            ErrorKind::BootstrapRequired => TransportError::NotBootstrapped,
            _ => TransportError::Connect(format!("{e}")),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tor_guardmgr::VanguardConfig;

    fn cfg(name: &str, bridges: Vec<&str>) -> TransportConfig {
        let dir = std::env::temp_dir().join(format!("ghost-net-cfg-test-{name}"));
        TransportConfig {
            state_dir: dir.join("state"),
            cache_dir: dir.join("cache"),
            bridge_lines: bridges.into_iter().map(str::to_owned).collect(),
            pt_dir: None,
        }
    }

    /// A `pt_dir` containing a stand-in lyrebird file: config-build checks existence only
    /// (arti's ptmgr launches lazily), so no real binary is needed for the unit suites.
    fn fake_pt_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ghost-net-pt-test-{name}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(LYREBIRD_BINARY), b"not-a-real-binary").unwrap();
        dir
    }

    const OBFS4_LINE: &str = "obfs4 192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567 \
        cert=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw== \
        iat-mode=0";
    const WEBTUNNEL_LINE: &str =
        "webtunnel 192.0.2.11:443 0123456789ABCDEF0123456789ABCDEF01234567 \
        url=https://192.0.2.11/abcdefghijklmnop ver=abcdef0123";

    #[test]
    fn config_builds_with_and_without_plain_bridges() {
        TorTransport::build_config(&cfg("direct", vec![])).expect("direct config builds");
        TorTransport::build_config(&cfg(
            "bridge",
            vec!["192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567"],
        ))
        .expect("plain bridge config builds");
        assert!(matches!(
            TorTransport::build_config(&cfg("broken", vec!["not a bridge line"])),
            Err(TransportError::Config(_))
        ));
    }

    #[test]
    fn pluggable_transport_lines_need_the_pt_binary() {
        // Enabling pluggable transports is this deliberate change (Phase 12, ADR-16 → ADR-61):
        // obfs4/webtunnel lines now parse, but only with pt_dir pointing at the extracted binary.
        let no_pt = cfg("obfs4-nopt", vec![OBFS4_LINE]);
        assert!(matches!(
            TorTransport::build_config(&no_pt),
            Err(TransportError::PtBinaryMissing)
        ));
        // PT lines are rejected before arti's parser sees them when no binary is installed…
        let mut missing = cfg("obfs4-missing", vec![OBFS4_LINE]);
        missing.pt_dir = Some(std::env::temp_dir().join("ghost-net-pt-test-does-not-exist"));
        assert!(matches!(
            TorTransport::build_config(&missing),
            Err(TransportError::PtBinaryMissing)
        ));
        // …and build once the (stand-in) binary exists. No PT process spawns at build or
        // create time: ptmgr launches lazily on first channel use, so the unit suites need no
        // real binary. (The ptmgr wiring itself is proven end to end by S3's loopback harness.)
        let mut ok = cfg("obfs4-ok", vec![OBFS4_LINE, WEBTUNNEL_LINE]);
        ok.pt_dir = Some(fake_pt_dir("obfs4-ok"));
        TorTransport::build_config(&ok).expect("PT config builds with the binary");
    }

    #[test]
    fn pt_launch_shape_is_platform_split() {
        // Rev 3 (§5.4.5, OA-4 resolution): on Android the ptmgr exec is
        // `path = <system linker>`, `arguments = [<absolute binary path>]` — never a direct
        // execve of the filesDir binary (SELinux execute_no_trans denies that for
        // targetSdk ≥ 29; the linker needs only the granted mmap-exec). On every other host
        // the verified binary is exec'ed directly (S3-T1: the loopback harness of §12.3 runs
        // arti on the host, where the SELinux rule has no counterpart). The existence gate
        // lives behind cfg(android), so the host build resolves paths without checking them.
        let mut c = cfg("pt-exec-shape", vec![OBFS4_LINE]);
        c.pt_dir = Some(fake_pt_dir("pt-exec-shape"));
        let (exec_target, args) = pt_exec(&c).expect("exec shape resolves with the binary");
        assert!(
            exec_target.is_absolute() && exec_target.ends_with(LYREBIRD_BINARY),
            "the verified binary is always resolved: {exec_target:?}"
        );
        #[cfg(target_os = "android")]
        {
            let expected = match std::env::consts::ARCH {
                "aarch64" | "x86_64" => "linker64",
                _ => "linker",
            };
            assert!(
                exec_target.to_string_lossy().ends_with(expected),
                "the exec target is the {expected} linker: {exec_target:?}"
            );
            assert_eq!(args.len(), 1, "exactly one argument (the binary): {args:?}");
            assert!(
                args[0].ends_with(LYREBIRD_BINARY) && std::path::Path::new(&args[0]).is_absolute(),
                "the argument is the binary's absolute path: {args:?}"
            );
        }
        #[cfg(not(target_os = "android"))]
        {
            assert!(
                exec_target.ends_with(LYREBIRD_BINARY),
                "off-device the exec target is the binary itself: {exec_target:?}"
            );
            assert!(
                args.is_empty(),
                "direct exec takes no wrapper argument: {args:?}"
            );
        }
        // Binary-first ordering: no pt_dir refuses with PtBinaryMissing before any linker
        // resolution (a missing binary and a missing linker are both config class, but the
        // binary check is the one a misconfigured install meets).
        let none = cfg("pt-exec-none", vec![OBFS4_LINE]);
        assert!(matches!(
            pt_exec(&none),
            Err(TransportError::PtBinaryMissing)
        ));
    }

    #[test]
    fn snowflake_lines_stay_refused() {
        // The 12b deferral is pinned: a distinct config refusal, not a parse through arti.
        let line = "snowflake 192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567";
        let mut c = cfg("snowflake", vec![line]);
        c.pt_dir = Some(fake_pt_dir("snowflake"));
        match TorTransport::build_config(&c) {
            Err(TransportError::Config(m)) => {
                assert!(m.contains("bridge line 0"), "error names the index: {m}");
                assert!(m.contains("snowflake"), "error names the deferral: {m}");
                assert!(!m.contains("192.0.2.10"), "the line text never leaks: {m}");
            }
            other => panic!("snowflake must stay refused, got {other:?}"),
        }
    }

    #[test]
    fn vanguards_lite_is_enabled() {
        let built = TorTransport::build_config(&cfg("vanguards", vec![])).unwrap();
        let vanguards: &VanguardConfig = built.as_ref();
        assert_eq!(vanguards.mode(), VanguardMode::Lite);
    }

    #[test]
    fn create_failures_are_setup_errors_not_bridge_errors() {
        // A regular file where the state directory should be cannot be used by Arti.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("not-a-dir");
        std::fs::write(&file, b"x").unwrap();
        let cfg = TransportConfig {
            state_dir: file.clone(),
            cache_dir: file,
            bridge_lines: vec![],
            pt_dir: None,
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        match TorTransport::create(&cfg) {
            Err(TransportError::Setup(_)) => {}
            Err(other) => panic!("expected Setup, got {other:?}"),
            Ok(_) => panic!("a file as state dir must not be accepted"),
        }
    }

    #[test]
    fn a_bootstrap_that_timed_out_is_never_reported_as_done_later() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let dir = tempfile::tempdir().unwrap();
        let c = |n: &str| TransportConfig {
            state_dir: dir.path().join(n).join("state"),
            cache_dir: dir.path().join(n).join("cache"),
            bridge_lines: vec![],
            pt_dir: None,
        };
        let t = TorTransport::create(&c("a")).unwrap();
        // A zero deadline elapses before any directory fetch can finish.
        let first = rt.block_on(t.bootstrap_within(Duration::ZERO));
        assert!(matches!(first, Err(TransportError::BootstrapTimeout)));
        let retry = rt.block_on(t.bootstrap_within(Duration::from_secs(30)));
        assert!(
            matches!(retry, Err(TransportError::BootstrapSpent)),
            "a retry on an abandoned client must fail, got {retry:?}"
        );

        // Same for an attempt whose future is dropped mid-way (e.g. cancelled by close()).
        let t2 = TorTransport::create(&c("b")).unwrap();
        drop(t2.bootstrap()); // never polled: nothing started
        assert!(!t2.bootstrap_abandoned.load(Ordering::SeqCst));
        rt.block_on(async {
            let mut f = Box::pin(t2.bootstrap());
            let _ = tokio::time::timeout(Duration::from_millis(1), &mut f).await;
        });
        assert!(matches!(
            rt.block_on(t2.bootstrap_within(Duration::from_secs(30))),
            Err(TransportError::BootstrapSpent)
        ));

        // An attempt waiting behind one that times out is not reported as done.
        let t3 = Arc::new(TorTransport::create(&c("c")).unwrap());
        let (a, b) = rt.block_on(async {
            let first = t3.bootstrap_within(Duration::from_millis(200));
            let second = async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                t3.bootstrap_within(Duration::from_secs(30)).await
            };
            tokio::join!(first, second)
        });
        assert!(matches!(a, Err(TransportError::BootstrapTimeout)), "{a:?}");
        assert!(matches!(b, Err(TransportError::BootstrapSpent)), "{b:?}");
    }

    #[test]
    fn connections_never_bootstrap_implicitly() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let dir = tempfile::tempdir().unwrap();
        let t = TorTransport::create(&TransportConfig {
            state_dir: dir.path().join("state"),
            cache_dir: dir.path().join("cache"),
            bridge_lines: vec![],
            pt_dir: None,
        })
        .unwrap();
        let addr = OnionAddress::parse(
            "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion:443",
        )
        .unwrap();
        let r = rt.block_on(async {
            tokio::time::timeout(
                Duration::from_secs(10),
                t.connect(&addr, &IsolationScope::Namespace([1; 32])),
            )
            .await
        });
        assert!(
            matches!(r, Ok(Err(TransportError::NotBootstrapped))),
            "a connect before bootstrap must fail fast"
        );
        // No bootstrap was started behind our back: the client can still bootstrap normally.
        assert!(!t.bootstrap_abandoned.load(Ordering::SeqCst));
    }

    #[test]
    fn creating_the_client_puts_no_key_in_the_keystore() {
        // Arti opens a native keystore under state_dir/keystore (tor-keymgr's `keymgr` feature is
        // on through tor-chanmgr). The RUSTSEC-2023-0071 acceptance rests on nothing in the client
        // generating or storing private keys; tests/live_tor.rs checks the same after a real
        // bootstrap and onion connections.
        let dir = tempfile::tempdir().unwrap();
        let c = TransportConfig {
            state_dir: dir.path().join("state"),
            cache_dir: dir.path().join("cache"),
            bridge_lines: vec![],
            pt_dir: None,
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let _t = TorTransport::create(&c).unwrap();
        // The keystore directory exists (so the check below is not vacuous) and holds no key.
        assert!(c.state_dir.join("keystore").is_dir());
        assert_eq!(keystore_files(&c.state_dir), Vec::<PathBuf>::new());
    }

    #[test]
    fn a_pt_configured_client_leaves_no_line_or_key_on_disk() {
        // PT-U6's in-process half (T58's storage half): a client configured with PT bridge lines
        // must persist nothing outside the SQLCipher database once slice S2 owns the lines —
        // today the lines live only in TransportConfig, so the assertion set is: arti's state and
        // cache dirs contain no bridge line and no key material (the keystore invariant of
        // Phase 6, unchanged), and no PT process spawned during create (lazy ptmgr launch).
        let dir = tempfile::tempdir().unwrap();
        let pt_dir = fake_pt_dir("pt-no-line-on-disk");
        let c = TransportConfig {
            state_dir: dir.path().join("state"),
            cache_dir: dir.path().join("cache"),
            bridge_lines: vec![OBFS4_LINE.to_owned()],
            pt_dir: Some(pt_dir),
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let t = TorTransport::create(&c).expect("PT client creates without spawning");
        drop(t);
        assert_eq!(keystore_files(&c.state_dir), Vec::<PathBuf>::new());
        // No file under state or cache may contain the bridge line (the canary discipline of
        // §6.4, run in-process; PT-P1 completes it with a real bootstrap and a filesDir scan).
        for needle in ["0123456789ABCDEF01234567", "cert=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw=="] {
            for root in [&c.state_dir, &c.cache_dir] {
                let hits = files_containing(root, needle);
                assert!(hits.is_empty(), "bridge-line material in {root:?}: {hits:?}");
            }
        }
    }

    /// Files under `root` whose contents contain `needle` (small test walk).
    fn files_containing(root: &Path, needle: &str) -> Vec<PathBuf> {
        fn walk(d: &Path, needle: &str, out: &mut Vec<PathBuf>) {
            if let Ok(entries) = std::fs::read_dir(d) {
                for e in entries.flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        walk(&p, needle, out);
                    } else if let Ok(text) = std::fs::read_to_string(&p) {
                        if text.contains(needle) {
                            out.push(p);
                        }
                    }
                }
            }
        }
        let mut out = Vec::new();
        walk(root, needle, &mut out);
        out
    }

    #[test]
    fn create_does_not_need_the_network_and_isolation_tokens_are_per_scope() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let t = TorTransport::create(&cfg("create", vec![])).expect("unbootstrapped client");
        let a = t.isolation_token(&IsolationScope::Namespace([1; 32]));
        let b = t.isolation_token(&IsolationScope::Namespace([2; 32]));
        assert_ne!(a, b);
        assert_eq!(a, t.isolation_token(&IsolationScope::Namespace([1; 32])));
        t.rotate_circuits();
        assert_ne!(a, t.isolation_token(&IsolationScope::Namespace([1; 32])));
    }
}
