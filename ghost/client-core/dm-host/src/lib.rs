//! `ghost-dm-host`: the test-only host build of the DM JNI surface (design §2.3, §2.7, §15.1).
//!
//! JVM tests must run the **real ratchet**, which is native, so the `android` CI job builds this
//! `cdylib` for `x86_64-unknown-linux-gnu` (and the owner's machine for `x86_64-pc-windows-msvc`,
//! verified in S0′ V-5) and passes `-Dghost.dm.native=<path>`; `DmNative` loads that path in tests
//! and `ghost_client_net` on Android. The exported symbols are the same ones the shipped library
//! carries, because both come from the same `export_jni!` invocation over the same crate — that is
//! what makes the host/Android equivalence test of §15.9 item 7 an equivalence test rather than a
//! comparison of two implementations.
//!
//! This package is **never built for Android** and is excluded from the shipped graph, so the
//! client allowlist and the third-party notices do not see it.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

ghost_client_dm::export_jni!();
