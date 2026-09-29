#!/usr/bin/env bash
# Gate G-M4 (Phase 10 design faza10-forum.md §3.6, §13.1 G-M4; invariant T3; slice S2a): the
# channel crate's graph brings no logger into the library — no tracing or logger crate, `log` only
# as a dependency of the vendored crates that declare it (openmls, hpke-rs,
# openmls_memory_storage), nothing that installs a logger. One script for both graphs (S0-18):
# this is `dm-rust-no-logging.sh --graph mls`; read that file for the rules, the hooks and what the
# gate does not see. The source half is no-logging.sh.
exec bash "$(dirname "${BASH_SOURCE[0]}")/dm-rust-no-logging.sh" --graph mls "$@"
