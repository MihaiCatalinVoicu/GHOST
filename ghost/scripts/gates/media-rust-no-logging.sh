#!/usr/bin/env bash
# Gate G-M7, G-R4's graph half for the media crate (Phase 11 design faza11-media.md §13.1, §16.1 G-M7;
# invariant T3; slice S1): `ghost-client-media`'s graph brings no logging into the library — no `log`,
# no tracing or logger crate at all, nothing that installs a logger. One script for the three graphs:
# this is `dm-rust-no-logging.sh --graph media`; read that file for the rules, the hooks and what the
# gate does not see. The source half is no-logging.sh (it reads client-core/media with every other
# client-core crate) and media-crate-purity.sh.
exec bash "$(dirname "${BASH_SOURCE[0]}")/dm-rust-no-logging.sh" --graph media "$@"
