// Fixture (G-M2 source clause): a module directory named target is read, not pruned (Phase 10 review of S2a, F4).
fn leak(group: &MlsGroup) {
    let _ = group.export_group_info();
}
