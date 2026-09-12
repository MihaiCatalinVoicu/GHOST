//! `ghost-issuer --config <file> [--restore] [--restore-wallet]`: the entitlement issuer process (Phase 8 design §5.1,
//! §6.6). Everything lives in [`ghost_issuer::server`]; the process prints nothing and its exit
//! status names the refusal class (ADR-26: the issuer keeps no logs).
#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    ghost_issuer::server::run_cli(&args)
}
