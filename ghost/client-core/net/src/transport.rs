//! Embedded Tor transport (Arti). Connections are only ever made to [`OnionAddress`] values with
//! an explicit isolation token; the Arti client itself is not exposed outside this crate.
//!
//! Creation and bootstrap are separate so the caller can abort a bootstrap that stalls on a
//! censored network and switch to bridges (ADR-16 auto mode). Bridges are optional *plain*
//! bridge lines (`IP:PORT FINGERPRINT`); pluggable transports (obfs4, webtunnel, snowflake) are
//! not compiled in yet and are rejected as a configuration error (Phase 12). There is no non-Tor
//! mode.

use crate::isolation::{IsolationScope, Isolations};
use crate::onion::OnionAddress;
use arti_client::config::{BridgeConfigBuilder, CfgPath, TorClientConfigBuilder};
use arti_client::{BootstrapBehavior, DataStream, ErrorKind, HasKind, StreamPrefs, TorClient};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tor_config::ExplicitOrAuto;
use tor_guardmgr::VanguardMode;
use tor_rtcompat::PreferredRuntime;

/// Upper bound for one bootstrap attempt. Arti's own directory retries are uncapped on a blocked
/// network; the caller gets a `tor_bootstrap_timeout` instead of an indefinite block.
pub const BOOTSTRAP_DEADLINE: Duration = Duration::from_secs(180);

#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Directory for Tor state and directory cache (must be app-private, no-backup).
    pub state_dir: PathBuf,
    pub cache_dir: PathBuf,
    /// Plain bridge lines (`IP:PORT FINGERPRINT`); empty = direct Tor. Pluggable-transport lines
    /// (`obfs4 ...`, `webtunnel ...`, `snowflake ...`) are rejected with [`TransportError::Config`]
    /// until pluggable transports are enabled (Phase 12).
    pub bridge_lines: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum TransportError {
    /// Invalid configuration: an unsupported or malformed bridge line.
    Config(String),
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
    /// configured.
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
            for line in &cfg.bridge_lines {
                let bridge: BridgeConfigBuilder = line
                    .parse()
                    .map_err(|e| TransportError::Config(format!("{e}")))?;
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
        }
    }

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
    fn pluggable_transport_lines_are_rejected_until_enabled() {
        // Enabling pluggable transports must be a deliberate change (Phase 12, ADR-16).
        let obfs4 =
            "obfs4 192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=AAAA iat-mode=0";
        assert!(matches!(
            TorTransport::build_config(&cfg("obfs4", vec![obfs4])),
            Err(TransportError::Config(_))
        ));
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
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let _t = TorTransport::create(&c).unwrap();
        // The keystore directory exists (so the check below is not vacuous) and holds no key.
        assert!(c.state_dir.join("keystore").is_dir());
        assert_eq!(keystore_files(&c.state_dir), Vec::<PathBuf>::new());
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
