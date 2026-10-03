// Fixture (G-M2 source clause): a module directory named target is read (review of S2a, F4).
fn leak(group: &MlsGroup) {
    let _ = group.export_group_info(crypto, signer, true);
}
