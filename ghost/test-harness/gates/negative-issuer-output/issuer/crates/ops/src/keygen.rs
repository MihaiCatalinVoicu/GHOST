//! Negative fixture: only output.rs of the operator tools writes files (line 3 is reported).
pub fn created(path: &std::path::Path) {
    std::fs::create_dir_all(path).unwrap();
}
