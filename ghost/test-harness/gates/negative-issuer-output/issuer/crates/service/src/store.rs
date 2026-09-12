//! Negative fixture: store.rs creates its database (line 3 is allowed) but never the console.
pub fn open(path: &std::path::Path) {
    let _ = redb::Database::create(path);
    let _ = std::io::stdout();
}
