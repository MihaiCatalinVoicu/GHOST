// G-R8 scanner fixture: the error stream without a print macro. One site: stderr, line 6.
use std::io::Write;

pub fn seal(input: &[u8]) {
    let n = input.len();
    let _ = writeln!(std::io::stderr(), "sealing {n}");
}
