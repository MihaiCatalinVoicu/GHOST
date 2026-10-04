// Fixture: the two exports, one split over lines.
fn a(g: &G) {
    g.export_secret(&c, derive::LABEL_EPOCH, id, 32);
    g.export_secret(
        &c,
        LABEL_GENERATION,
        id,
        32,
    );
}
