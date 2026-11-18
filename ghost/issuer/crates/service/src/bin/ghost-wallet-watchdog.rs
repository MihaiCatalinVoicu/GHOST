//! One-shot JSON-RPC healthcheck for the supervised `monero-wallet-rpc` container.
//! No output and no secret on the command line: `RPC_LOGIN` or Docker's login secret is used.
#![forbid(unsafe_code)]

use std::process::ExitCode;
use std::time::Duration;

use ghost_issuer::rail::digest::Credentials;
use ghost_issuer::rail::monero::{Endpoint, RpcClient, Timeouts};
use serde_json::json;

const DEFAULT_URL: &str = "http://127.0.0.1:38083";
const LOGIN_SECRET: &str = "/run/secrets/wallet_rpc_login";

fn credentials() -> Option<Credentials> {
    let login = match std::env::var("RPC_LOGIN") {
        Ok(value) => value,
        Err(_) => std::fs::read_to_string(LOGIN_SECRET).ok()?,
    };
    Credentials::parse_login(&login).ok()
}

fn healthy() -> bool {
    if std::env::args_os().nth(1).is_some() {
        return false;
    }
    let url = std::env::var("GHOST_WALLET_RPC_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());
    let Some(endpoint) = Endpoint::parse_url(&url).ok() else {
        return false;
    };
    let Some(credentials) = credentials() else {
        return false;
    };
    let timeouts = Timeouts {
        connect: Duration::from_secs(3),
        call: Duration::from_secs(10),
        long: Duration::from_secs(10),
    };
    RpcClient::new(endpoint, credentials, timeouts)
        .and_then(|client| client.call("get_height", json!({})))
        .is_ok()
}

fn main() -> ExitCode {
    if healthy() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
