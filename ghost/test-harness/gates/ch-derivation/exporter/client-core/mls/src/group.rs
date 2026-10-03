// Fixture: an export under another label.
fn a(g: &G) {
    g.export_secret(&c, "ghost/v1/ch/other", id, 32);
}
