//! GHOST release operations library (Phase 14). The binary (`main.rs`) is a thin CLI over this.
//! Slice 1 implements the §6.5 core rule (`apk-core`); root-build, manifest-build, bundle and the
//! Sigsum add-leaf request land with the release-tooling slices (RK1's signer paths need the
//! hardware tokens; stagenet uses software keys through `ghost-client-release`'s `sign_entry`).

pub mod apkcore;
