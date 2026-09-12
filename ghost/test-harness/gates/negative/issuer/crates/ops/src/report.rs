//! Negative fixture (design §14.1, §19.17): the report module of the operator tools may print with
//! println!/eprintln! (line 5 is exempt), but dbg! stays banned there (line 6 is reported).
pub fn emit(line: &str, failure: bool) {
    if failure {
        eprintln!("{line}");
        dbg!(line);
    }
}
