#!/usr/bin/env bash
# Gate G-M7, the G-R8 scan for the media crate (Phase 11 design faza11-media.md §13.1, §16.1 G-M7;
# invariants T3, T33; slice S1): the clock, logging, printing and network sites in the compiled
# library code of `ghost-client-media`'s graph equal a committed, justified baseline
# (media-vendored-clock-log.baseline): the crate itself has none, and its graph is the AEAD, HKDF,
# SHA-2 and zeroize stack the DM crate already ships. One script for the three graphs: this is
# `dm-vendored-clock-log.sh --graph media`; read that file for the scan, the baseline rules and the
# hooks (GHOST_G_R8_BASELINE, GHOST_G_R8_TRIPLES, GHOST_G_R8_PRINT=1).
exec bash "$(dirname "${BASH_SOURCE[0]}")/dm-vendored-clock-log.sh" --graph media "$@"
