//! CLI: `capture-check --schema <allowed-observables.json> --capture <capture.ndjson>`
//! Exit 0 = capture contains only allowed observables; exit 1 = violations (listed on stderr);
//! exit 2 = usage or I/O error.

use ghost_capture_check::Schema;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut schema_path = None;
    let mut capture_path = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--schema" => schema_path = args.next(),
            "--capture" => capture_path = args.next(),
            _ => {
                eprintln!("usage: capture-check --schema <file> --capture <file>");
                return ExitCode::from(2);
            }
        }
    }
    let (Some(schema_path), Some(capture_path)) = (schema_path, capture_path) else {
        eprintln!("usage: capture-check --schema <file> --capture <file>");
        return ExitCode::from(2);
    };
    let schema_text = match std::fs::read_to_string(&schema_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cannot read schema {schema_path}: {e}");
            return ExitCode::from(2);
        }
    };
    let capture_text = match std::fs::read_to_string(&capture_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cannot read capture {capture_path}: {e}");
            return ExitCode::from(2);
        }
    };
    let schema = match Schema::parse(&schema_text) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let violations = schema.check_capture(&capture_text);
    if violations.is_empty() {
        eprintln!("[capture-check] OK: {capture_path} contains only allowed observables");
        ExitCode::SUCCESS
    } else {
        for v in &violations {
            eprintln!("VIOLATION {v}");
        }
        eprintln!(
            "[capture-check] FAILED: {} violation(s) in {capture_path}",
            violations.len()
        );
        ExitCode::from(1)
    }
}
