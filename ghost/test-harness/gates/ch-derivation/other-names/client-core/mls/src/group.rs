// Fixture (G-M3 rule 2): the provider's HKDF, keyed by a channel id.
pub fn key(crypto: &impl OpenMlsCrypto, channel_id: &[u8; 32]) -> Vec<u8> {
    crypto.hkdf_expand(channel_id, b"x", 32).unwrap()
}
