// Fixture: a derive_* function and an HKDF outside the typed module.
fn derive_hidden(k: &JoinKey) -> [u8; 32] {
    let h = Hkdf
        ::<Sha256>::new(None, k.as_bytes());
    [0; 32]
}
