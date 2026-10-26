//! One live probe of the public Sigsum log: prints the cosigned tree head and the first leaves.
//! Run: cargo run -p ghost-verify --example live -- https://log.sigsum.org 0 4

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let url = args.get(1).map(|s| s.as_str()).unwrap_or("https://log.sigsum.org");
    let start: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
    let end: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(4);
    match ghost_verify::sigsum::get_tree_head_cosigned(url) {
        Ok(h) => println!("HEAD size={} root={} cosigned={}", h.tree_size, hex::encode(h.root_hash), h.cosignatures.len()),
        Err(e) => println!("HEAD failed: {e}"),
    }
    match ghost_verify::sigsum::get_leaves(url, start, end) {
        Ok(leaves) => {
            println!("LEAVES {}", leaves.len());
            for (i, l) in leaves.iter().enumerate() {
                println!("  {} checksum={} key={}", start + i as u64, hex::encode(l.checksum), hex::encode(l.key_hash));
            }
        }
        Err(e) => println!("LEAVES failed: {e}"),
    }
}
