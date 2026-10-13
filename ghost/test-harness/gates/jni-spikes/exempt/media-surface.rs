//! Fixture: the media surface `MediaNative` writes (Phase 11 design §13.2; slice S2), which the DM
//! gate's media half requires of its scan root: `MEDIA_CLOSED_LIST` of `client-core/dm/src/jni_media.rs`,
//! sealBegin through sniff, so the `spikes/` exemption is the only thing this root is tested for.
//! The two host-only entries (`testVectors`, `testSealBeginWithKey`, `MEDIA_TEST_LIST`) are excluded
//! here as the gate's source half excludes `^test` names; G-M5's library half, not a source fixture,
//! is what checks them. The names restate the constant, as `vectors-entry.rs` restates `MlsVectors.run`.

/// Seal a blob: begin.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_ghost_crypto_bridge_MediaNative_sealBegin() {}
/// Seal a blob: append.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_ghost_crypto_bridge_MediaNative_sealAppend() {}
/// Seal a blob: finish.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_ghost_crypto_bridge_MediaNative_sealFinish() {}
/// Seal a blob: abort.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_ghost_crypto_bridge_MediaNative_sealAbort() {}
/// Open a reader.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_ghost_crypto_bridge_MediaNative_readerOpen() {}
/// Read a chunk.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_ghost_crypto_bridge_MediaNative_readerChunk() {}
/// Validate and finish a reader.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_ghost_crypto_bridge_MediaNative_readerValidateFinish() {}
/// Close a reader.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_ghost_crypto_bridge_MediaNative_readerClose() {}
/// Canonicalize a JPEG.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_ghost_crypto_bridge_MediaNative_jpegCanonicalize() {}
/// Sniff a blob's type.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_ghost_crypto_bridge_MediaNative_sniff() {}
