//! Negative fixture (design §14.1, §19.17): the report.rs exemption is the operator tools' module
//! only; a report.rs in the issuer service is scanned like every other file.
pub fn status(line: &str) {
    println!("{line}");
}
