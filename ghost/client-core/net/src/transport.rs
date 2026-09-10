//! Embedded Tor transport (Arti). Connections are only ever made to [`OnionAddress`] values with
//! an explicit isolation token. Bridges (ADR-16) are optional bridge lines; when the list is empty
//! the client uses the public Tor network directly. There is no non-Tor mode.

use crate::isolation::{IsolationScope, Isolations};
use crate::onion::OnionAddress;
use arti_client::config::{BridgeConfigBuilder, CfgPath, TorClientConfigBuilder};
use arti_client::{DataStream, StreamPrefs, TorClient};
use std::path::PathBuf;
use std::sync::Arc;
use tor_rtcompat::PreferredRuntime;

#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Directory for Tor state and directory cache (must be app-private, no-backup).
    pub state_dir: PathBuf,
    pub cache_dir: PathBuf,
    /// Bridge lines (`obfs4 ...`, `webtunnel ...`, plain `IP:PORT FINGERPRINT`); empty = direct.
    pub bridge_lines: Vec<String>,
}

#[derive(Debug)]
pub enum TransportError {
    Config(String),
    Bootstrap(String),
    Connect(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Config(m) => write!(f, "tor config: {m}"),
            TransportError::Bootstrap(m) => write!(f, "tor bootstrap: {m}"),
            TransportError::Connect(m) => write!(f, "onion connect: {m}"),
        }
    }
}

impl std::error::Error for TransportError {}

pub struct TorTransport {
    client: Arc<TorClient<PreferredRuntime>>,
    isolations: Isolations,
}

impl TorTransport {
    /// Builds the Arti configuration: onion addresses allowed, bridges as configured.
    pub fn build_config(
        cfg: &TransportConfig,
    ) -> Result<arti_client::TorClientConfig, TransportError> {
        let mut b = TorClientConfigBuilder::default();
        b.storage()
            .state_dir(CfgPath::new_literal(cfg.state_dir.clone()))
            .cache_dir(CfgPath::new_literal(cfg.cache_dir.clone()));
        b.address_filter().allow_onion_addrs(true);
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

    /// Creates and bootstraps the Tor client. Fails closed: no fallback transport exists.
    pub async fn bootstrap(cfg: &TransportConfig) -> Result<Self, TransportError> {
        Self::install_crypto_provider();
        let config = Self::build_config(cfg)?;
        let client = TorClient::create_bootstrapped(config)
            .await
            .map_err(|e| TransportError::Bootstrap(format!("{e}")))?;
        Ok(TorTransport {
            client,
            isolations: Isolations::default(),
        })
    }

    /// Opens a stream to an onion address on the circuit set owned by `scope`.
    pub async fn connect(
        &self,
        addr: &OnionAddress,
        scope: &IsolationScope,
    ) -> Result<DataStream, TransportError> {
        let mut prefs = StreamPrefs::new();
        prefs.set_isolation(self.isolations.token_for(scope));
        self.client
            .connect_with_prefs((addr.host(), addr.port()), &prefs)
            .await
            .map_err(|e| TransportError::Connect(format!("{e}")))
    }

    pub fn client(&self) -> Arc<TorClient<PreferredRuntime>> {
        Arc::clone(&self.client)
    }

    pub fn isolations(&self) -> &Isolations {
        &self.isolations
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_builds_with_and_without_bridges() {
        let dir = std::env::temp_dir().join("ghost-net-cfg-test");
        let cfg = TransportConfig {
            state_dir: dir.join("state"),
            cache_dir: dir.join("cache"),
            bridge_lines: vec![],
        };
        TorTransport::build_config(&cfg).expect("direct config builds");
        let with_bridge = TransportConfig {
            bridge_lines: vec![
                "192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567".to_string()
            ],
            ..cfg.clone()
        };
        TorTransport::build_config(&with_bridge).expect("bridge config builds");
        let broken = TransportConfig {
            bridge_lines: vec!["not a bridge line".to_string()],
            ..cfg
        };
        assert!(matches!(
            TorTransport::build_config(&broken),
            Err(TransportError::Config(_))
        ));
    }
}
