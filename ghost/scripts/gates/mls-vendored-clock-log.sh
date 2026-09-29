#!/usr/bin/env bash
# Gate G-M8 (Phase 10 design faza10-forum.md §3.6, §13.1 G-M8; invariants T3, T33; slice S2a): the
# clock, logging, printing and network sites in the compiled library code of the channel crate's
# graph equal a committed, justified baseline (mls-vendored-clock-log.baseline; OpenMLS's clock
# sites of §3.6 among them). One script for both graphs (S0-18): this is
# `dm-vendored-clock-log.sh --graph mls` (the G-R8 method of F9 §16.1); read that file for the scan,
# the baseline rules and the hooks (GHOST_G_R8_BASELINE, GHOST_G_R8_TRIPLES, GHOST_G_R8_PRINT=1).
exec bash "$(dirname "${BASH_SOURCE[0]}")/dm-vendored-clock-log.sh" --graph mls "$@"
