//! The mirror transport (Phase 14 design §7.1, §7.2, §7.8): HTTP/2 with prior knowledge inside
//! the onion stream, on the `Update` isolation scope, with the paths, ranges and bounds built
//! natively — Kotlin can name neither an onion nor a path nor an offset (PM-D9, PM-D10). The
//! mirror set (two canonical onions, the network, the offered APK's hash and length) is built
//! by `UpdateNative.nativeMirrorSet` and read only here.

use std::time::Duration;

use http::header::{CONTENT_RANGE, RANGE};
use http::{Method, Request, StatusCode, Uri};
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;
use tokio::time::timeout;

use crate::categories as cat;
use crate::onion::OnionAddress;
use crate::relay_client::onion_connector;
use crate::transport::TorTransport;
use crate::isolation::IsolationScope;

/// The fixed 4 MiB range step of an APK download (§7.2).
pub(crate) const CHUNK: u64 = 4 * 1024 * 1024;
/// What one fetch may return, fixed before reading (§4.8 / §7.2): the bundle bound, a chunk.
const BUNDLE_MAX: usize = 1_048_576;

/// Lowercase hex of 32 bytes (the APK path names the file by its SHA-256).
fn hex64(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 15) as usize] as char);
    }
    out
}

/// The network's path segment (§7.2 `<net>`).
pub fn network_path(network: u8) -> Option<&'static str> {
    match network {
        1 => Some("mainnet"),
        2 => Some("stagenet"),
        3 => Some("stagenet-drill"),
        _ => None,
    }
}

/// One mirror set of an update run (§7.8), built natively from the stored state and the run's
/// draw. The two onions are the canonical `<56 base32>.onion:<port>` spellings.
#[derive(Debug, Clone)]
pub struct MirrorSet {
    pub first: Vec<u8>,
    pub second: Vec<u8>,
    pub network: u8,
    pub apk_sha256: Option<[u8; 32]>,
    pub apk_length: u64,
}

impl MirrorSet {
    fn onion(&self, slot: u8) -> Option<OnionAddress> {
        let raw = match slot {
            0 => &self.first,
            1 => &self.second,
            _ => return None,
        };
        OnionAddress::parse(std::str::from_utf8(raw).ok()?).ok()
    }

    /// The path of one fetch, built from verified state only.
    pub(crate) fn path(&self, kind: u8, chunk_index: u64) -> Result<String, &'static str> {
        let net = network_path(self.network).ok_or(cat::INVALID_ARGUMENT)?;
        match kind {
            0 => Ok(format!("/ghost/v1/{net}/current.ghrb")),
            1 => {
                let sha = self.apk_sha256.ok_or(cat::INVALID_ARGUMENT)?;
                let length = self.apk_length;
                if chunk_index.checked_mul(CHUNK).ok_or(cat::INVALID_ARGUMENT)? >= length {
                    return Err(cat::INVALID_ARGUMENT);
                }
                Ok(format!("/ghost/v1/{net}/apk/{}", hex64(&sha)))
            }
            _ => Err(cat::INVALID_ARGUMENT),
        }
    }
}

/// A fetch over the mirror's onion stream. `kind` 0 = bundle (expect 200, bound 1 MiB),
/// `kind` 1 = APK chunk `chunk_index` (expect 206 with the matching `content-range`, bound
/// `CHUNK` or the file's tail). Returns the bytes.
pub async fn fetch(
    transport: &TorTransport,
    set: &MirrorSet,
    slot: u8,
    kind: u8,
    chunk_index: u64,
    deadline: Duration,
) -> Result<Vec<u8>, &'static str> {
    let onion = set.onion(slot).ok_or(cat::INVALID_ARGUMENT)?;
    let path = set.path(kind, chunk_index)?;
    let authority = std::str::from_utf8(match slot {
        0 => &set.first,
        _ => &set.second,
    })
    .map_err(|_| cat::INVALID_ARGUMENT)?;

    let http = HyperClient::builder(TokioExecutor::new())
        .http2_only(true)
        // The fingerprint the mirrors see is pinned (§7.2), here and in the relay/issuer
        // clients: explicit SETTINGS rather than hyper's defaults.
        .http2_initial_stream_window_size(65_535)
        .http2_initial_connection_window_size(65_535)
        .http2_max_frame_size(16_384)
        .http2_adaptive_window(false)
        .build(onion_connector(
            transport,
            &onion,
            &IsolationScope::Update,
        ));
    let uri: Uri = format!("http://{authority}{path}")
        .parse()
        .map_err(|_| cat::INVALID_ARGUMENT)?;
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(uri)
        // No user-agent, no accept-encoding, nothing client-specific (§7.2): hyper sends none
        // unless asked, and the range below is the only header.
        .header(http::header::HOST, authority);
    if kind == 1 {
        let start = chunk_index * CHUNK;
        let end = (start + CHUNK).min(set.apk_length) - 1;
        builder = builder.header(RANGE, format!("bytes={start}-{end}"));
    }
    let request = builder.body(http_body_util::Empty::<hyper::body::Bytes>::new()).map_err(|_| cat::INTERNAL)?;

    let response = timeout(deadline, http.request(request))
        .await
        .map_err(|_| cat::TIMEOUT)?
        .map_err(|_| cat::TRANSPORT)?;
    let status = response.status();
    let bound = if kind == 0 {
        if status != StatusCode::OK {
            return Err(cat::MALFORMED_RESPONSE);
        }
        BUNDLE_MAX
    } else {
        if status != StatusCode::PARTIAL_CONTENT {
            return Err(cat::MALFORMED_RESPONSE);
        }
        let expected = format!(
            "bytes {}-{}/{}",
            chunk_index * CHUNK,
            (chunk_index * CHUNK + CHUNK).min(set.apk_length) - 1,
            set.apk_length
        );
        let got = response
            .headers()
            .get(CONTENT_RANGE)
            .and_then(|v| v.to_str().ok())
            .ok_or(cat::MALFORMED_RESPONSE)?;
        if got != expected {
            return Err(cat::MALFORMED_RESPONSE);
        }
        CHUNK as usize
    };
    let mut body = response.into_body();
    let mut out: Vec<u8> = Vec::new();
    use http_body_util::BodyExt;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| cat::MALFORMED_RESPONSE)?;
        if let Some(data) = frame.data_ref() {
            out.extend_from_slice(data);
            // The fixed bound is checked before reading on (§4.8/§7.2). MC-D13 (the
            // `test-mutants` feature, host libraries only): the response is read past its
            // bound. The selector's default keeps the shipped check.
            #[cfg(feature = "test-mutants")]
            let bound_checked = !ghost_client_update::mutants::active(
                ghost_client_update::mutants::PAST_BOUND,
            );
            #[cfg(not(feature = "test-mutants"))]
            let bound_checked = true;
            if bound_checked && out.len() > bound {
                return Err(cat::MALFORMED_RESPONSE);
            }
        }
    }
    if kind == 1 && out.is_empty() {
        return Err(cat::MALFORMED_RESPONSE);
    }
    Ok(out)
}
