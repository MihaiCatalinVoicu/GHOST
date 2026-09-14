//! Negative fixture (S12 review GATE-ISSUER-OUTPUT-BRACE): imports hide the path from the call.
//! Lines 3, 4, 5, 8 and 9 are reported; lines 10 and 11 are not (reads and traits only).
use std::fs::{read, write};
use std::io::{stdout as out, Write};
use std::fs::{
    create_dir_all, remove_file,
};
use std::fs as files;
use std::io::*;
use std::fs::{self, File};
use std::io::{self, BufRead};
pub fn leak(path: &std::path::Path) {
    write(path, read(path).unwrap()).unwrap();
    out().write_all(b"line").unwrap();
    create_dir_all(path).unwrap();
    remove_file(path).unwrap();
    files::copy(path, path).unwrap();
    let _ = (fs::metadata(path), File::open(path), io::empty().lines());
}
