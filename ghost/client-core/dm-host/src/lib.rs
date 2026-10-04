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
//! **The symbols more** (slice S12, §22.8.10 point 6): `DmEquivalence.run`, the deterministic
//! case runner of `ghost_client_dm::equivalence`, since §22.37 `DmEquivalence.bindingHooks`, the
//! per-context switch of MC-20's mutant and KC5b's replayed binding (`ghost_client_dm::binding::
//! hooks`), and since §22.38 `DmEquivalence.stateWrapHook` and `DmEquivalence.sidecarLogHook`, the
//! per-context switches of ME-24's and MC-30's mutants (`ghost_client_dm::wrap::hooks`,
//! `ghost_client_dm::olm::state::hooks`), all behind the `test-vectors` feature. Built for `x86_64-linux-android` this library is
//! the emulator's test library, packaged only in the `androidTest` APK; G-R6 checks it exports the
//! closed list plus exactly those entries, and that the shipped `libghost_client_net.so` exports no
//! `DmEquivalence` symbol.
//!
//! **One check more, and no symbol** (§15.5 PQ1, §22.20): `ghost-client-dm`'s `pq-spy` feature runs
//! PQ1 as an assertion around every `openIntro` — exactly one X-Wing decapsulation and one inner key
//! per open, and the same open with one bit of the decapsulated secret flipped must be `NOT_OPEN` —
//! so every JVM world opens its intros under it. A violation is a caught panic, `INTERNAL`; nothing else the surface returns
//! changes, and the second, perturbed open draws no randomness. `DmPqSpyNativeTest` refuses a host
//! library built without it.
//!
//! **The channel surface** (Phase 10 design §10.1, slice S2b): `ghost_client_mls::export_jni!()`
//! exports `MlsNative` — the same closed list `libghost_client_net.so` exports, from the same crate
//! — and `ghost_client_mls::export_vectors_jni!()` its one test entry, `MlsVectors.run`, the case
//! runner of the JDK vector replay (§12.2). G-M6 checks this library exports exactly those, and the
//! shipped one no `MlsVectors` symbol.
//!
//! This package is **never shipped** and is excluded from the shipped graph, so the client
//! allowlist and the third-party notices do not see it.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

ghost_client_dm::export_jni!();
ghost_client_dm::export_equivalence_jni!();
ghost_client_mls::export_jni!();
ghost_client_mls::export_vectors_jni!();
