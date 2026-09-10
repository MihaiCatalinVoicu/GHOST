//! Circuit isolation (ADR-01, ADR-09): every channel namespace and every distinct purpose gets its
//! own Tor isolation token, so requests for two channels never share a circuit and a relay cannot
//! link them by arrival circuit. Tokens are process-local and never persisted.

use arti_client::IsolationToken;
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IsolationScope {
    /// Reads/writes for one channel or inbox namespace.
    Namespace([u8; 32]),
    /// Entitlement issuer traffic (never shares a circuit with any namespace).
    Issuer,
    /// Release manifest / update checks.
    Update,
}

#[derive(Default)]
pub struct Isolations {
    tokens: Mutex<HashMap<IsolationScope, IsolationToken>>,
}

impl Isolations {
    /// Returns the stable token for a scope, creating it on first use.
    pub fn token_for(&self, scope: &IsolationScope) -> IsolationToken {
        let mut map = self.tokens.lock().unwrap();
        *map.entry(scope.clone()).or_insert_with(IsolationToken::new)
    }

    /// Drops every token; the next request for any scope builds fresh circuits (rotation policy).
    pub fn rotate_all(&self) {
        self.tokens.lock().unwrap().clear();
    }

    pub fn len(&self) -> usize {
        self.tokens.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_get_distinct_stable_tokens() {
        let iso = Isolations::default();
        let a = iso.token_for(&IsolationScope::Namespace([1; 32]));
        let b = iso.token_for(&IsolationScope::Namespace([2; 32]));
        let issuer = iso.token_for(&IsolationScope::Issuer);
        assert_ne!(a, b);
        assert_ne!(a, issuer);
        assert_eq!(a, iso.token_for(&IsolationScope::Namespace([1; 32])));
        assert_eq!(iso.len(), 3);
        iso.rotate_all();
        assert!(iso.is_empty());
        assert_ne!(a, iso.token_for(&IsolationScope::Namespace([1; 32])));
    }
}
