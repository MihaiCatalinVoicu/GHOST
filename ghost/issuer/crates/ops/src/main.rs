//! `ghost-issuer-ops`: the issuer's offline operator tools (Phase 8 design §3.3, §5.1). Commands and
//! their flags are documented in the library (`ghost_issuer_ops`); every line the tools print goes
//! through its `report` module.

use std::process::ExitCode;

fn main() -> ExitCode {
    ghost_issuer_ops::run(std::env::args_os().skip(1))
}
