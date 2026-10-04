// Fixture (G-M2 source clause): three forbidden names written the ways a reviewer might miss, and
// three mentions that must not count (a comment, a string, a longer identifier).
use openmls_memory_storage
    ::MemoryStorage;

fn commit(group: &mut MlsGroup) {
    let _ = group
        .commit_builder()
        .build_with_new_signer();
    group.
        store_pending_proposal(proposal);
    // export_group_info in a comment does not count
    let _ = "into_group_info in a string does not count";
    let _ = my_export_group_info_count; // a longer identifier is a different name
}
