//! A fixture: the media crate must not log or print (design §13.1).
pub fn seal(len: usize) {
    log::info!("sealing {len} bytes");
    println!("sealed");
}
