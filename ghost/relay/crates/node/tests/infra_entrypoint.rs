//! The relay image's entrypoint (`infra/relay/entrypoint.sh`) against design §19.10 point 3
//! (review finding INFRA-3): `--onion-hostname-file` must name the onion this relay's Tor serves.
//! The HiddenServiceDir is mounted from the host with a whole key set, `hostname` included, so a
//! copy taken before Tor has loaded the secret key would compare the ES with a file the operator
//! supplied: the entrypoint removes the mounted `hostname`, lets Tor write it from the secret key
//! and only then copies it for the relay; with `--schedule` a Tor that writes none is a refusal.

use std::path::Path;

fn entrypoint() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../infra/relay/entrypoint.sh");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn the_onion_hostname_is_the_one_tor_wrote_from_the_key_set() {
    let text = entrypoint();
    let code: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    let at = |needle: &str| {
        code.iter()
            .position(|l| l.contains(needle))
            .unwrap_or_else(|| panic!("entrypoint.sh has no line with {needle:?}"))
    };
    let remove = at(r#"rm -f "$HS_DIR/hostname""#);
    let tor = at("tor -f /etc/tor/torrc");
    let copy = at(r#"install -m 0444 "$HS_DIR/hostname""#);
    let relay = at("ghost-relay serve");
    assert!(
        remove < tor,
        "the mounted hostname is removed before Tor starts"
    );
    assert!(tor < copy && copy < relay);
    assert!(
        code[tor..relay].iter().any(|l| l.contains("exit 64")),
        "with --schedule a Tor that wrote no hostname stops the start"
    );
}
