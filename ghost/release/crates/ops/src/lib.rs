//! GHOST release operations library (Phase 14). The binary (`main.rs`) is a thin CLI over this.
//! Slice 1 implements the §6.5 core rule (`apk-core`); slice 2 adds the document builders
//! (`build`): root/chain/proof/manifest/bundle for the stagenet channel with software keys —
//! RK1's hardware-token (PKCS#11) signer paths replace `load_signing_key` at the ceremonies.

pub mod apkcore;
pub mod build;
pub mod export;
pub mod records;
pub mod sbom;
