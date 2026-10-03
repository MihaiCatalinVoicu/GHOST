// Fixture: the public salt keys a derivation other than the open invite's seal.
pub fn derive_namespace(g: &GenerationSecret) -> [u8; 32] { [0; 32] }
pub fn derive_open_invite_seal_key(salt: &OpenInviteSalt) -> SealKey { x() }
pub fn derive_something_else(salt: &OpenInviteSalt) -> SealKey { x() }
