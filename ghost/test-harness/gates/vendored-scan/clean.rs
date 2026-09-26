// G-R8 scanner fixture: no site. The words stdout and stderr in a comment are not tokens.
use std::fmt;
use std::io::Write;

pub struct Shown(pub u8);

impl fmt::Display for Shown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "stderr {}", self.0)
    }
}

pub fn render(out: &mut Vec<u8>) -> std::io::Result<()> {
    writeln!(out, "stdout")
}
