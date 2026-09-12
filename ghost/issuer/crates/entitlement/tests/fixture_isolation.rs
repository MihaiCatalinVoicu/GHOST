//! The test schedule key is never a production key (design §19.17 point 1, T8): `Schedule::verify`,
//! the only production entry point, refuses the committed test schedule and its content re-signed
//! with the test key under every network, while the same bytes verify under the explicit test key.

mod common;

use common::fixture::{self, FIXTURE};
use ghost_entitlement::monero::MoneroNetwork;
use ghost_entitlement::{Schedule, ScheduleError};

fn refused_by_production(bytes: &[u8]) -> bool {
    matches!(
        Schedule::verify(bytes),
        Err(ScheduleError::NoPinnedKey | ScheduleError::Signature)
    )
}

#[test]
fn production_verify_refuses_every_test_key_schedule() {
    assert!(refused_by_production(FIXTURE));
    for network in [
        MoneroNetwork::Mainnet,
        MoneroNetwork::Stagenet,
        MoneroNetwork::Regtest,
    ] {
        let mut content = fixture::schedule().content().clone();
        content.network = network;
        let bytes = fixture::resign(&content);
        assert!(Schedule::verify_with_key(&bytes, &fixture::schedule_key()).is_ok());
        assert!(refused_by_production(&bytes), "{network:?}");
    }
}
