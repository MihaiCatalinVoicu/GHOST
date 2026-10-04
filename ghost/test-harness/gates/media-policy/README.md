# rust-feature-policy.sh fixtures for G-M7's shipped-graph clause (Phase 11 design faza11-media.md §16.1 G-M7, §22.2 row 19(b))

`cargo metadata` excerpts in which `ghost-client-dm` declares `ghost-client-media` (read through the
gate's `GHOST_POLICY_MEDIA_METADATA` hook, against the real shipped graph, which does not hold the
crate before slice S2): as a normal dependency (`linked-normal.json`) and as an optional one left off
(`linked-optional.json`) the gate must fail, since the declaration requires the crate in the shipped
graph; as a dev-dependency (`linked-dev.json`) it requires nothing. The review of S1 found the
self-test reaching this clause only through `GHOST_POLICY_MEDIA_SHIPPED_REQUIRED=1`, which skips the
detection these files exercise.
