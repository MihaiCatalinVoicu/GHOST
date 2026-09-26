//! no-logging negative fixture: the print macros' channel without their names. Expected: line 7.

use std::io::Write;

pub fn seal(input: &[u8]) {
    let n = input.len();
    let _ = writeln!(std::io::stderr(), "sealing {n}");
}
