//! Fixture: the update surface `UpdateNative`/`TorMirrorTransport` write (Phase 14 design §9.3;
//! slice S6), which the DM gate's G-D5 half requires of its scan root: `CLOSED_UPDATE` and
//! `CLOSED_MIRROR` of `client-core/net/src/update.rs`, nativeEmbeddedChain through
//! nativeApkChunkStep plus the one fetch entry, and §11.3's `UpdateMutants.select` selector the
//! source half diffs both directions. The names restate the constants, as `media-surface.rs`
//! restates `MEDIA_CLOSED_LIST`, so the `spikes/` exemption stays the only thing this root is
//! tested for.

/// The embedded root chain of this build's network.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_ghost_network_UpdateNative_nativeEmbeddedChain() {}
/// Start an epoch.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_ghost_network_UpdateNative_nativeStart() {}
/// Accept a verified bundle.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_ghost_network_UpdateNative_nativeAccept() {}
/// Decide the offer.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_ghost_network_UpdateNative_nativeOffer() {}
/// Begin the streaming APK check.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_ghost_network_UpdateNative_nativeApkBegin() {}
/// Feed the signed footer first.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_ghost_network_UpdateNative_nativeApkFooter() {}
/// Feed an APK chunk.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_ghost_network_UpdateNative_nativeApkUpdate() {}
/// Finish the APK check.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_ghost_network_UpdateNative_nativeApkFinish() {}
/// Abort the APK check.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_ghost_network_UpdateNative_nativeApkAbort() {}
/// Set the mirror set.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_ghost_network_UpdateNative_nativeMirrorSet() {}
/// Close the mirror set.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_ghost_network_UpdateNative_nativeMirrorSetClose() {}
/// The bootstrap relay directory.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_ghost_network_UpdateNative_nativeBootstrapRelays() {}
/// The manifest's relay directory.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_ghost_network_UpdateNative_nativeManifestRelays() {}
/// The loopback mirror path.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_ghost_network_UpdateNative_nativeMirrorPath() {}
/// One loopback chunk step.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_ghost_network_UpdateNative_nativeApkChunkStep() {}
/// One fetch of the run.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_ghost_network_TorMirrorTransport_nativeFetch() {}
/// §11.3's mutant selector (test libraries only; the source half checks both directions).
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_ghost_network_UpdateMutants_select() {}
