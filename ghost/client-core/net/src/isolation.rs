//! Circuit isolation (ADR-01, ADR-09): every channel namespace and every distinct purpose gets its
//! own Tor isolation token, so requests for two channels never share a circuit and a relay cannot
//! link them by arrival circuit. Tokens are process-local and never persisted.
//!
//! Issuer traffic is isolated per flow instance (Phase 8 design §11.7, rule R5; ADR-22 replaces the
//! former single `Issuer` scope): the caller names every flow instance (a purchase step, a trial, a
//! claim, a refresh, a revocation) with 16 fresh random bytes, [`IsolationScope::IssuerFlow`], and
//! ends it with [`TorTransport::end_issuer_flow`](crate::TorTransport::end_issuer_flow) (JNI
//! `nativeEndFlow`), which drops its token. The flow map belongs to one transport and goes with it,
//! and a token is never made twice (`IsolationToken::new` is unequal to every earlier token), so no
//! two flows share a circuit, with each other or with a namespace, also across transports. The map
//! is bounded ([`MAX_ISSUER_FLOWS`]): a flow beyond the bound drops the oldest flow's token, which
//! only gives that flow fresh circuits on its next call, never another flow's.

use arti_client::IsolationToken;
use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, MutexGuard};

/// Issuer flows one transport keeps a token for. The engine runs at most one issuer call per quiet
/// run and ends every flow, so the bound is only reached if flows are never ended.
pub const MAX_ISSUER_FLOWS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IsolationScope {
    /// Reads/writes for one channel or inbox namespace.
    Namespace([u8; 32]),
    /// One issuer flow instance, named by 16 random bytes drawn per flow: never shares a circuit
    /// with another flow or any namespace; its token is dropped when the flow ends.
    IssuerFlow([u8; 16]),
    /// Release manifest / update checks.
    Update,
}

#[derive(Default)]
struct Tokens {
    by_scope: HashMap<IsolationScope, IsolationToken>,
    /// Issuer flows holding a token, oldest first (at most [`MAX_ISSUER_FLOWS`]).
    flows: VecDeque<[u8; 16]>,
}

#[derive(Default)]
pub(crate) struct Isolations {
    tokens: Mutex<Tokens>,
}

impl Isolations {
    fn lock(&self) -> MutexGuard<'_, Tokens> {
        self.tokens.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Returns the token for a scope, creating it on first use (stable until the scope ends or the
    /// circuits rotate).
    pub fn token_for(&self, scope: &IsolationScope) -> IsolationToken {
        let mut t = self.lock();
        if let Some(token) = t.by_scope.get(scope) {
            return *token;
        }
        if let IsolationScope::IssuerFlow(flow) = scope {
            if t.flows.len() >= MAX_ISSUER_FLOWS {
                if let Some(oldest) = t.flows.pop_front() {
                    t.by_scope.remove(&IsolationScope::IssuerFlow(oldest));
                }
            }
            t.flows.push_back(*flow);
        }
        let token = IsolationToken::new();
        t.by_scope.insert(scope.clone(), token);
        token
    }

    /// Ends an issuer flow: its token is dropped, so a later call under the same id gets fresh
    /// circuits. Unknown flows are ignored.
    pub fn end_flow(&self, flow: &[u8; 16]) {
        let mut t = self.lock();
        t.by_scope.remove(&IsolationScope::IssuerFlow(*flow));
        t.flows.retain(|f| f != flow);
    }

    /// Drops every token; the next request for any scope builds fresh circuits (rotation policy).
    pub fn rotate_all(&self) {
        let mut t = self.lock();
        t.by_scope.clear();
        t.flows.clear();
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.lock().by_scope.len()
    }

    #[cfg(test)]
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
        let issuer = iso.token_for(&IsolationScope::IssuerFlow([1; 16]));
        let update = iso.token_for(&IsolationScope::Update);
        assert_ne!(a, b);
        assert_ne!(a, issuer);
        assert_ne!(update, issuer);
        assert_eq!(a, iso.token_for(&IsolationScope::Namespace([1; 32])));
        assert_eq!(iso.len(), 4);
        iso.rotate_all();
        assert!(iso.is_empty());
        assert_ne!(a, iso.token_for(&IsolationScope::Namespace([1; 32])));
        assert_ne!(issuer, iso.token_for(&IsolationScope::IssuerFlow([1; 16])));
    }

    /// A per-transport token source as the issuer calls see it. The flow check below runs against
    /// the production map and against the M4 mutant.
    trait FlowTokens {
        fn token(&self, scope: &IsolationScope) -> IsolationToken;
        fn end_flow(&self, flow: &[u8; 16]);
    }

    impl FlowTokens for Isolations {
        fn token(&self, scope: &IsolationScope) -> IsolationToken {
            self.token_for(scope)
        }
        fn end_flow(&self, flow: &[u8; 16]) {
            Isolations::end_flow(self, flow)
        }
    }

    /// The `IssuerFlow` -> `IsolationToken` properties (design §11.7, §19.17 point 6) for token
    /// sources made by `open`, one per transport (dropping the source closes the transport):
    /// distinct tokens per flow, never a namespace's; stable within a flow; dropped when the flow
    /// ends; never reused after the transport closes.
    fn check_issuer_flows<T: FlowTokens>(open: impl Fn() -> T) -> Result<(), &'static str> {
        let f1 = IsolationScope::IssuerFlow([1; 16]);
        let f2 = IsolationScope::IssuerFlow([2; 16]);
        let first = open();
        let a1 = first.token(&f1);
        let a2 = first.token(&f2);
        if a1 == a2 {
            return Err("two issuer flows share a token");
        }
        if first.token(&f1) != a1 {
            return Err("a flow's token changed within the flow");
        }
        let ns = first.token(&IsolationScope::Namespace([1; 32]));
        if ns == a1 || ns == a2 {
            return Err("an issuer flow shares a namespace token");
        }
        first.end_flow(&[1; 16]);
        let b1 = first.token(&f1);
        if b1 == a1 || b1 == a2 {
            return Err("an ended flow's token was reused");
        }
        if first.token(&f2) != a2 {
            return Err("ending one flow changed another");
        }
        drop(first);
        let second = open();
        for scope in [&f1, &f2] {
            if [a1, a2, b1].contains(&second.token(scope)) {
                return Err("a token was reused after the transport closed");
            }
        }
        Ok(())
    }

    /// The M4 target (design §13.5, §19.17 point 6): stable, runs on every PR.
    #[test]
    fn issuer_flows_get_distinct_tokens_dropped_at_the_end_and_never_reused() {
        assert_eq!(check_issuer_flows(Isolations::default), Ok(()));
    }

    /// Mutant M4 `SharedIssuerScope` (design §13.5): one issuer scope for every flow, the former
    /// unit `Issuer` scope. The check must catch it.
    struct SharedIssuerScope(Isolations);

    impl FlowTokens for SharedIssuerScope {
        fn token(&self, scope: &IsolationScope) -> IsolationToken {
            match scope {
                IsolationScope::IssuerFlow(_) => {
                    self.0.token_for(&IsolationScope::IssuerFlow([0; 16]))
                }
                other => self.0.token_for(other),
            }
        }
        fn end_flow(&self, flow: &[u8; 16]) {
            self.0.end_flow(flow)
        }
    }

    #[test]
    fn mutant_m4_shared_issuer_scope_is_caught() {
        assert_eq!(
            check_issuer_flows(|| SharedIssuerScope(Isolations::default())),
            Err("two issuer flows share a token")
        );
    }

    /// A map whose flow end keeps the token (circuits of an ended flow reused by the next one).
    struct EndKeepsToken(Isolations);

    impl FlowTokens for EndKeepsToken {
        fn token(&self, scope: &IsolationScope) -> IsolationToken {
            self.0.token_for(scope)
        }
        fn end_flow(&self, _flow: &[u8; 16]) {}
    }

    #[test]
    fn a_flow_end_that_keeps_the_token_is_caught() {
        assert_eq!(
            check_issuer_flows(|| EndKeepsToken(Isolations::default())),
            Err("an ended flow's token was reused")
        );
    }

    #[test]
    fn the_flow_map_is_bounded_and_drops_the_oldest_flow() {
        let iso = Isolations::default();
        let flow = |i: usize| IsolationScope::IssuerFlow([i as u8; 16]);
        let ns = iso.token_for(&IsolationScope::Namespace([9; 32]));
        let first: Vec<IsolationToken> = (0..MAX_ISSUER_FLOWS)
            .map(|i| iso.token_for(&flow(i)))
            .collect();
        assert_eq!(iso.len(), MAX_ISSUER_FLOWS + 1);
        // One flow more: the oldest flow loses its token; namespaces are never evicted.
        let extra = iso.token_for(&flow(MAX_ISSUER_FLOWS));
        assert_eq!(iso.len(), MAX_ISSUER_FLOWS + 1);
        assert_eq!(iso.token_for(&IsolationScope::Namespace([9; 32])), ns);
        assert_eq!(iso.token_for(&flow(1)), first[1]);
        // The evicted flow comes back with a token no other flow ever had.
        let again = iso.token_for(&flow(0));
        assert!(!first.contains(&again) && again != extra && again != ns);
        // Ending flows frees room: nothing more is evicted.
        iso.end_flow(&[2; 16]);
        iso.end_flow(&[3; 16]);
        let before = iso.token_for(&flow(4));
        iso.token_for(&flow(200));
        assert_eq!(iso.token_for(&flow(4)), before);
        // Ending an unknown flow is a no-op.
        iso.end_flow(&[0xEE; 16]);
    }
}
