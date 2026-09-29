// Fixture (G-M3 rule 5): T36's scenario, a typed key built from a public channel id.
pub fn hint_key(channel_id: &[u8; 32]) -> [u8; 32] {
    derive_epoch_recognition(&EpochExport::from_bytes(*channel_id))
}
