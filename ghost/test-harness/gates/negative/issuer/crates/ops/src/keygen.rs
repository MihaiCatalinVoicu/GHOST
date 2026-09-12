//! Negative fixture (design §14.1, §19.17): only report.rs of the operator tools may print.
pub fn created(epoch: u64) {
    println!("key created for epoch {epoch}");
}
