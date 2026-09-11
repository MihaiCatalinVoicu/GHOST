//! Negative fixture: proves the logging and placeholder gates scan client-core/ (the crate that
//! ships in the APK). Never compiled.
pub fn connect(relay: &str) -> bool {
    eprintln!("connecting to {relay}");
    true // placeholder
}
