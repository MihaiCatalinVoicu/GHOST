//! no-logging positive fixture: nothing here reaches stdout or stderr (prose only).

use std::fmt;
use std::io::Write;

pub struct Shown(pub u8);

impl fmt::Display for Shown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "shown {}", self.0)
    }
}

pub fn render(out: &mut Vec<u8>) -> std::io::Result<()> {
    writeln!(out, "never to stderr or stdout")
}
