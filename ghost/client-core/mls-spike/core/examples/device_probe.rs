//! On-device probe (V10-10's device half, R-9, §12.11): a native executable built for an Android
//! triple with cargo-ndk, pushed with `adb` and run from `/data/local/tmp`. It runs the same
//! channel world as the host tests over the real OpenMLS 0.9.0 + libcrux provider + GhostKv with
//! value semantics on Android's bionic libc and `getrandom`, and prints results and timings.
//! Evidence tooling, not product code. Usage on the device: `./device_probe [members]`.

use std::time::Instant;

use ghost_mls_spike::ext::{self, CommitAad};
use ghost_mls_spike::harness::*;
use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::*;

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.0
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn main() {
    let threads = ghost_mls_spike::pin_rayon_single_worker();
    let day = host_day();
    println!(
        "device_probe: rayon threads {threads}, host day {day}, arch {}",
        std::env::consts::ARCH
    );

    // (1) A 3-member group through every call: create, admit, post, self-update, remove, add.
    let t = Instant::now();
    let mut w = World::build(3, 2, day);
    let ch = w.channel;
    let post = w.members[1].encrypt(ch, 1, b"hello from bionic").unwrap();
    let pre_aad = match MlsMessageIn::tls_deserialize_exact(&post)
        .unwrap()
        .extract()
    {
        MlsMessageBodyIn::PrivateMessage(pm) => pm.aad().to_vec(),
        _ => vec![],
    };
    let r0 = w.members[0].receive(ch, &post).unwrap();
    let r2 = w.members[2].receive(ch, &post).unwrap();
    assert_eq!(r0.plaintext, b"hello from bionic");
    assert_eq!(r2.plaintext, b"hello from bionic");
    assert_eq!(pre_aad, ext::channel_order(w.members[1].leaf_index(ch), 1));
    w.self_update(2).unwrap();
    let leaf = w.members[1].leaf_index(ch);
    w.remove(0, leaf).unwrap();
    w.add_one(0).unwrap();
    let agree = w.authenticators_agree();
    println!("3-member group: create/admit/post/self-update/remove/add OK, epoch authenticators equal: {agree}, {:.1} ms", ms(t));
    assert!(agree);

    // (2) Timings at N members (blank shape), value semantics, 2 retained past epochs.
    let n: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(20);
    let t = Instant::now();
    let mut w = World::build(n, n - 1, day);
    let ch = w.channel;
    println!("world n={n}: built in {:.1} ms", ms(t));
    for _ in 0..2 {
        let e = w.members[0].epoch(ch);
        let s = CommitSpec {
            refresh_epoch: Some(e),
            force_path: true,
            no_exported_group_info: true,
            ..Default::default()
        };
        let out = w.members[0].commit(ch, &s).unwrap();
        w.members[1].receive(ch, &out.commit).unwrap();
        w.members[0].merge_own(ch).unwrap();
    }
    w.members[0].sweep_past(ch, 2).unwrap();
    w.members[1].sweep_past(ch, 2).unwrap();
    w.members[0].wrap_key = Some([0x42; 32]);
    w.members[1].wrap_key = Some([0x42; 32]);
    let reps = 9;
    let e = w.members[0].epoch(ch);
    let pcs = CommitSpec {
        aad: CommitAad {
            commit_minute: day * 1440,
            ..Default::default()
        },
        refresh_epoch: Some(e),
        force_path: true,
        no_exported_group_info: true,
        ..Default::default()
    };
    let mut v = Vec::new();
    let mut last = None;
    for _ in 0..reps {
        let saved = w.members[0].rows.clone();
        let t = Instant::now();
        last = Some(w.members[0].commit(ch, &pcs).unwrap());
        v.push(ms(t));
        w.members[0].rows = saved;
    }
    let commit = last.unwrap();
    println!(
        "n={n} commit (PCS, with path) {} B: median {:.2} ms",
        commit.commit.len(),
        median(v)
    );
    let mut v = Vec::new();
    for _ in 0..reps {
        let saved = w.members[1].rows.clone();
        let t = Instant::now();
        w.members[1].receive(ch, &commit.commit).unwrap();
        v.push(ms(t));
        w.members[1].rows = saved;
    }
    println!("n={n} settle (process + merge): median {:.2} ms", median(v));
    let post = w.members[0].encrypt(ch, 7, &[0x55; 1000]).unwrap();
    let mut v = Vec::new();
    for _ in 0..reps {
        let saved = w.members[1].rows.clone();
        let t = Instant::now();
        w.members[1].receive(ch, &post).unwrap();
        v.push(ms(t));
        w.members[1].rows = saved;
    }
    println!("n={n} decrypt post (1 000 B): median {:.2} ms", median(v));
    let mut v = Vec::new();
    for _ in 0..reps {
        let saved = w.members[0].rows.clone();
        let t = Instant::now();
        w.members[0].encrypt(ch, 8, &[0x55; 1000]).unwrap();
        v.push(ms(t));
        w.members[0].rows = saved;
    }
    println!("n={n} encrypt post (1 000 B): median {:.2} ms", median(v));
    println!("device_probe: OK");
}
