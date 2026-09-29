// Fixture (G-M2 source clause): the test-only KAT crate replays standalone proposals and may name
// what the shipped crate may not; the gate skips it.
fn replay(group: &mut MlsGroup) {
    group.store_pending_proposal(proposal);
    let _ = openmls_basic_credential::BasicCredential::new(vec![]);
}
