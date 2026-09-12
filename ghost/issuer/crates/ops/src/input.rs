//! Reading the operator's input files. A failure names the flag that gave the path.

use std::path::Path;

use crate::report::{Code, Field, Line};
use crate::Failure;

pub fn io_error(flag: &'static str, reason: &'static str) -> Failure {
    Failure::refused(
        Line::new(Code::IoError)
            .word(Field::Flag, flag)
            .word(Field::Reason, reason),
    )
}

pub fn input_refused(flag: &'static str, reason: &'static str) -> Line {
    Line::new(Code::InputRefused)
        .word(Field::Flag, flag)
        .word(Field::Reason, reason)
}

pub fn read(path: &Path, flag: &'static str) -> Result<Vec<u8>, Failure> {
    std::fs::read(path).map_err(|_| io_error(flag, "read"))
}

pub fn read_text(path: &Path, flag: &'static str) -> Result<String, Failure> {
    String::from_utf8(read(path, flag)?)
        .map_err(|_| Failure::refused(input_refused(flag, "not-utf8")))
}

/// A 32-byte secret file (custody secret, schedule key): exactly 32 bytes.
pub fn read_secret(path: &Path, flag: &'static str) -> Result<[u8; 32], Failure> {
    let mut bytes = read(path, flag)?;
    let secret = <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| Failure::refused(input_refused(flag, "length")));
    bytes.fill(0);
    secret
}
