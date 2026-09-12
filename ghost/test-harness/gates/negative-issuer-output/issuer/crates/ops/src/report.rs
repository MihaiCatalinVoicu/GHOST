//! Negative fixture: report.rs writes the console (line 3 is allowed) but never a file (line 4).
pub fn emit(line: &str) {
    println!("{line}");
    std::fs::write("report.txt", line).unwrap();
}
