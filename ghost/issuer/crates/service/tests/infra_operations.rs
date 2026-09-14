//! The operator procedures of `infra/issuer/RUNBOOK.md` against the files they run (Phase 8 design
//! §6.3, §6.8, §19.10 point 3, §19.15; review findings INFRA-1 to INFRA-5):
//!
//! - the hourly B1 snapshot (`infra/issuer/snapshot.sh`) restarts only an issuer it stopped
//!   itself, and never touches one inside a maintenance window: I1, R5, B1 restore, K2, K3 and M2
//!   create `$H/maintenance` and wait for a running snapshot (`$H/snapshot.lock`) before they stop
//!   or recreate a container, and remove the file at their end;
//! - the snapshot retention of §19.15 is a maximum: no hourly snapshot outlives 48 h and no daily
//!   one 7 days, whatever the phase of the cron runs;
//! - every one-time start (`GHOST_ISSUER_FLAGS`, `GHOST_RELAY_*_NULLIFIERS`) is followed by its
//!   expected output before the normal start, and no expected output is the tail of a log;
//! - the issuer's Tor writes the onion's `hostname` from the key set it loaded, and the install
//!   step checks that file against the ES only once Tor runs;
//! - `docker compose stop` ends the issuer at once (`init: true`: as PID 1 the issuer ignored
//!   SIGTERM and was killed after 10 s), and the ops tools, which read the snapshot of an issuer
//!   ended so through a recovered private copy (`RedbSnapshot`), have a private tmpfs for it;
//! - the hourly journal prune (`infra/issuer/journal-prune.sh`, §6.3, §6.4) runs
//!   `ghost-issuer-ops journal-prune` on the newest snapshot, under the snapshot lock, outside
//!   maintenance windows, with the journal mounted and `DAC_OVERRIDE` for that run only, silently
//!   unless the tool refuses; cron runs it hourly, at another minute than the snapshot;
//! - the install checks Tor's onion against the schedule's `issuer_onion` through
//!   `ghost-issuer-ops schedule-onions`, not by searching the schedule's bytes.
//!
//! The scripts run under `bash` with `docker` and `flock` replaced on `PATH` by recording doubles.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn infra_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../infra")
        .join(rel)
}

fn infra_file(rel: &str) -> String {
    std::fs::read_to_string(infra_path(rel)).unwrap_or_else(|e| panic!("infra/{rel}: {e}"))
}

fn runbook() -> String {
    infra_file("issuer/RUNBOOK.md")
}

/// The runbook section whose heading line starts with `heading`, through the next heading of the
/// same or a higher level. Code blocks are indented, so a heading is a line starting with `#`.
fn section(text: &str, heading: &str) -> String {
    let mut lines = text.lines();
    let level = loop {
        let line = lines
            .next()
            .unwrap_or_else(|| panic!("no section {heading:?}"));
        if line.starts_with(heading) {
            break line.bytes().take_while(|b| *b == b'#').count();
        }
    };
    let mut out = String::new();
    for line in lines {
        let depth = line.bytes().take_while(|b| *b == b'#').count();
        if depth > 0 && depth <= level && line[depth..].starts_with(' ') {
            break;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// The text between the first `start` and the next `end` after it.
fn between<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
    let from = text.find(start).unwrap_or_else(|| panic!("no {start:?}")) + start.len();
    let to = text[from..]
        .find(end)
        .unwrap_or_else(|| panic!("no {end:?} after {start:?}"));
    &text[from..from + to]
}

// ---------------------------------------------------------------------------------------------
// B1: the snapshot script (INFRA-2).
// ---------------------------------------------------------------------------------------------

/// Records every call in `docker.log`; `ps` answers like `docker compose ps --quiet` for a running
/// issuer; `stop` and `start` move the issuer between the two states; `run` prints a report line
/// like `ghost-issuer-ops`, or with `refuse` present a failure line on stderr and exit status 1.
const DOCKER_DOUBLE: &str = r#"#!/usr/bin/env bash
printf '%s\n' "$*" >> "$DOUBLE_DIR/docker.log"
case " $* " in
  *" run "*)
    if [ -e "$DOUBLE_DIR/refuse" ]; then
      echo "PRUNE_REFUSED reason=snapshot-unverified" >&2
      exit 1
    fi
    echo "JOURNAL_PRUNED removed=1 kept=2 first_seq=4 last_seq=5 applied=4" ;;
  *" ps "*) if [ -e "$DOUBLE_DIR/running" ]; then echo 5b1d0c2f9a3e; fi ;;
  *" stop issuer "*) rm -f "$DOUBLE_DIR/running" ;;
  *" start issuer "*) touch "$DOUBLE_DIR/running" ;;
esac
exit 0
"#;

/// Fails while `held` exists (another process holds the lock).
const FLOCK_DOUBLE: &str = r#"#!/usr/bin/env bash
printf '%s\n' "$*" >> "$DOUBLE_DIR/flock.log"
[ ! -e "$DOUBLE_DIR/held" ]
"#;

/// The issuer host directory and the doubles of one run.
struct Host {
    _dir: tempfile::TempDir,
    host: PathBuf,
    doubles: PathBuf,
}

impl Host {
    /// A host directory with `data/issuer.redb` and `snapshots/`; the issuer runs iff `running`.
    fn new(running: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let host = dir.path().join("host");
        let doubles = dir.path().join("doubles");
        std::fs::create_dir_all(host.join("data")).unwrap();
        std::fs::create_dir_all(host.join("snapshots")).unwrap();
        std::fs::write(host.join("data").join("issuer.redb"), b"issuer database").unwrap();
        std::fs::create_dir_all(doubles.join("bin")).unwrap();
        for (name, text) in [("docker", DOCKER_DOUBLE), ("flock", FLOCK_DOUBLE)] {
            let path = doubles.join("bin").join(name);
            std::fs::write(&path, text).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        if running {
            std::fs::write(doubles.join("running"), b"").unwrap();
        }
        Self {
            _dir: dir,
            host,
            doubles,
        }
    }

    fn snapshot(&self) -> Output {
        self.script("issuer/snapshot.sh")
    }

    fn prune(&self) -> Output {
        self.script("issuer/journal-prune.sh")
    }

    fn script(&self, rel: &str) -> Output {
        let mut paths = vec![self.doubles.join("bin")];
        paths.extend(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        ));
        Command::new("bash")
            .arg(infra_path(rel))
            .env("PATH", std::env::join_paths(paths).unwrap())
            .env("GHOST_ISSUER_HOST_DIR", &self.host)
            .env("DOUBLE_DIR", &self.doubles)
            .output()
            .unwrap_or_else(|e| panic!("bash runs {rel}: {e}"))
    }

    fn add_snapshots(&self, names: &[&str]) {
        for name in names {
            std::fs::write(self.host.join("snapshots").join(name), b"snapshot").unwrap();
        }
    }

    fn running(&self) -> bool {
        self.doubles.join("running").exists()
    }

    /// The `docker` calls, as `stop`, `start`, `ps`, … (the verb after `compose -f <file>`).
    fn docker_calls(&self) -> Vec<String> {
        let log = std::fs::read_to_string(self.doubles.join("docker.log")).unwrap_or_default();
        log.lines()
            .map(|l| {
                let words: Vec<&str> = l.split_whitespace().collect();
                assert!(
                    words.len() >= 4 && words[0] == "compose" && words[1] == "-f",
                    "docker is called as `docker compose -f <file> …`: {l}"
                );
                assert!(
                    words[2].ends_with("docker-compose.stagenet.yml"),
                    "the stagenet compose file: {l}"
                );
                words[3..].join(" ")
            })
            .collect()
    }

    /// `(name, contents)` of every snapshot written.
    fn snapshots(&self) -> Vec<(String, Vec<u8>)> {
        let mut out: Vec<(String, Vec<u8>)> = std::fs::read_dir(self.host.join("snapshots"))
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (
                    e.file_name().to_string_lossy().into_owned(),
                    std::fs::read(e.path()).unwrap(),
                )
            })
            .collect();
        out.sort();
        out
    }
}

fn is_snapshot_name(name: &str) -> bool {
    name.strip_prefix("issuer-")
        .and_then(|n| n.strip_suffix(".redb"))
        .is_some_and(|stamp| stamp.len() == 10 && stamp.bytes().all(|b| b.is_ascii_digit()))
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn the_snapshot_stops_copies_and_restarts_a_running_issuer() {
    let h = Host::new(true);
    let out = h.snapshot();
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        out.stdout.is_empty() && out.stderr.is_empty(),
        "{}",
        stderr(&out)
    );
    assert_eq!(
        h.docker_calls(),
        [
            "ps --status running --quiet issuer",
            "stop issuer",
            "start issuer"
        ]
    );
    assert!(h.running());
    let snapshots = h.snapshots();
    assert_eq!(snapshots.len(), 1, "{snapshots:?}");
    assert!(is_snapshot_name(&snapshots[0].0), "{}", snapshots[0].0);
    assert_eq!(snapshots[0].1, b"issuer database");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(h.host.join("snapshots").join(&snapshots[0].0)).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }
}

/// I1 ("Oprire imediată: $C stop issuer") and every other stop by an operator: the snapshot never
/// starts an issuer it did not stop.
#[test]
fn the_snapshot_never_starts_an_issuer_it_did_not_stop() {
    let h = Host::new(false);
    let out = h.snapshot();
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("the issuer is not running"),
        "{}",
        stderr(&out)
    );
    assert_eq!(h.docker_calls(), ["ps --status running --quiet issuer"]);
    assert!(!h.running());
    assert!(h.snapshots().is_empty());
}

/// R5 (a rescan of up to 6 h), B1 restore (between `mv issuer.redb` and the install of the
/// snapshot), K2, K3, M2 and I1 hold `$H/maintenance`: the snapshot touches nothing, silently.
#[test]
fn the_snapshot_leaves_a_maintenance_window_alone() {
    for running in [true, false] {
        let h = Host::new(running);
        std::fs::write(h.host.join("maintenance"), b"").unwrap();
        let out = h.snapshot();
        assert!(out.status.success(), "{}", stderr(&out));
        assert!(out.stderr.is_empty(), "{}", stderr(&out));
        assert!(h.docker_calls().is_empty(), "{:?}", h.docker_calls());
        assert_eq!(h.running(), running);
        assert!(h.snapshots().is_empty());
    }
}

#[test]
fn the_snapshot_touches_nothing_while_another_holds_the_lock() {
    let h = Host::new(true);
    std::fs::write(h.doubles.join("held"), b"").unwrap();
    let out = h.snapshot();
    assert!(!out.status.success());
    assert!(h.docker_calls().is_empty(), "{:?}", h.docker_calls());
    assert!(h.running());
    assert!(h.snapshots().is_empty());
}

#[test]
fn a_failed_copy_still_restarts_the_issuer_the_snapshot_stopped() {
    let h = Host::new(true);
    std::fs::remove_file(h.host.join("data").join("issuer.redb")).unwrap();
    let out = h.snapshot();
    assert!(!out.status.success());
    assert_eq!(
        h.docker_calls(),
        [
            "ps --status running --quiet issuer",
            "stop issuer",
            "start issuer"
        ]
    );
    assert!(h.running());
    assert!(h.snapshots().is_empty());
}

/// One line of the runbook's cron block: its minute, how often it runs and what.
struct CronLine {
    minute: u8,
    every_minutes: u64,
    command: String,
}

fn cron_lines(text: &str) -> Vec<CronLine> {
    let block = between(text, "```cron\n", "```");
    block
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            assert!(
                f.len() > 6 && f[2..5] == ["*", "*", "*"] && f[5] == "root",
                "{l}"
            );
            let minute: u8 = f[0].parse().unwrap_or_else(|_| panic!("{l}"));
            let every_minutes = match f[1] {
                "*" => 60,
                h if h.parse::<u8>().is_ok() => 1_440,
                _ => panic!("{l}"),
            };
            CronLine {
                minute,
                every_minutes,
                command: f[6..].join(" "),
            }
        })
        .collect()
}

#[test]
fn the_cron_runs_the_snapshot_script_only() {
    let lines = cron_lines(&section(&runbook(), "## 6. B1"));
    let snapshot: Vec<&CronLine> = lines
        .iter()
        .filter(|l| l.command.contains("snapshot.sh"))
        .collect();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].every_minutes, 60);
    assert!(snapshot[0]
        .command
        .contains("GHOST_ISSUER_HOST_DIR=/srv/ghost-issuer"));
    for l in &lines {
        assert!(
            !l.command.contains("docker"),
            "a cron line drives the containers itself: {}",
            l.command
        );
    }
}

// ---------------------------------------------------------------------------------------------
// B1: the journal prune (§6.3, §6.4).
// ---------------------------------------------------------------------------------------------

/// The one `docker` call of a prune run: the ops tool on the newest snapshot, with the journal
/// mounted and `DAC_OVERRIDE` for this run only; returns the `--now` it passed.
fn assert_prune_call(h: &Host, snapshot: &str) -> u64 {
    let calls = h.docker_calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    let prefix = format!(
        "run --rm --cap-add DAC_OVERRIDE -v {}/data/journal:/journal ops journal-prune \
         --database /snapshots/{snapshot} --journal /journal --schedule /etc/ghost/schedule.ghes \
         --now ",
        h.host.display()
    );
    let now = calls[0]
        .strip_prefix(&prefix)
        .unwrap_or_else(|| panic!("{}", calls[0]));
    now.parse().unwrap_or_else(|_| panic!("{}", calls[0]))
}

#[test]
fn the_journal_prune_runs_the_ops_tool_on_the_newest_snapshot_silently() {
    let h = Host::new(true);
    h.add_snapshots(&[
        "issuer-2026092810.redb",
        "issuer-2026092812.redb",
        "issuer-2026092811.redb",
        "issuer-latest.redb",
        "issuer-20260928123.redb",
    ]);
    std::fs::write(h.host.join("snapshots").join("notes.txt"), b"").unwrap();
    let out = h.prune();
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        out.stdout.is_empty() && out.stderr.is_empty(),
        "a pruning run prints nothing: {}{}",
        String::from_utf8_lossy(&out.stdout),
        stderr(&out)
    );
    let now = assert_prune_call(&h, "issuer-2026092812.redb");
    assert!(now > 1_700_000_000, "--now is the host's clock: {now}");
    // The issuer keeps running: the prune never stops or starts a container.
    assert!(h.running());
    let flock = std::fs::read_to_string(h.doubles.join("flock.log")).unwrap();
    assert_eq!(
        flock.trim(),
        "-n 9",
        "the snapshot lock is held for the run"
    );
}

#[test]
fn the_journal_prune_leaves_a_maintenance_window_and_a_held_lock_alone() {
    let h = Host::new(true);
    h.add_snapshots(&["issuer-2026092812.redb"]);
    std::fs::write(h.host.join("maintenance"), b"").unwrap();
    let out = h.prune();
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(out.stderr.is_empty(), "{}", stderr(&out));
    assert!(h.docker_calls().is_empty(), "{:?}", h.docker_calls());

    let h = Host::new(true);
    h.add_snapshots(&["issuer-2026092812.redb"]);
    std::fs::write(h.doubles.join("held"), b"").unwrap();
    let out = h.prune();
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("snapshot.lock is held"),
        "{}",
        stderr(&out)
    );
    assert!(h.docker_calls().is_empty(), "{:?}", h.docker_calls());
}

/// Cron mails what a run prints: a missing snapshot and a refusal of the tool reach it, and the
/// script's status is the tool's.
#[test]
fn the_journal_prune_reports_a_missing_snapshot_and_a_refusal() {
    let h = Host::new(true);
    h.add_snapshots(&["issuer-latest.redb"]);
    let out = h.prune();
    assert!(!out.status.success());
    assert!(stderr(&out).contains("no snapshot"), "{}", stderr(&out));
    assert!(h.docker_calls().is_empty(), "{:?}", h.docker_calls());

    let h = Host::new(true);
    h.add_snapshots(&["issuer-2026092812.redb"]);
    std::fs::write(h.doubles.join("refuse"), b"").unwrap();
    let out = h.prune();
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert!(
        stderr(&out).contains("PRUNE_REFUSED reason=snapshot-unverified"),
        "{}",
        stderr(&out)
    );
    assert_prune_call(&h, "issuer-2026092812.redb");
}

#[test]
fn the_cron_prunes_the_journal_hourly_away_from_the_snapshot() {
    let lines = cron_lines(&section(&runbook(), "## 6. B1"));
    let find = |script: &str| -> Vec<&CronLine> {
        lines
            .iter()
            .filter(|l| l.command.contains(script))
            .collect()
    };
    let prune = find("journal-prune.sh");
    let snapshot = find("snapshot.sh");
    assert_eq!(prune.len(), 1);
    assert_eq!(
        prune[0].every_minutes, 60,
        "the 7-14 day retention needs hourly runs"
    );
    assert!(prune[0]
        .command
        .contains("GHOST_ISSUER_HOST_DIR=/srv/ghost-issuer /srv/ghost-src/ghost/infra/issuer/journal-prune.sh"));
    assert_ne!(
        prune[0].minute, snapshot[0].minute,
        "both take the snapshot lock; the prune runs away from the snapshot's minute"
    );
}

/// The byte offsets of `$C stop|start|restart|up` in `text`: a command that stops, starts or
/// recreates a container of the issuer's compose project.
fn lifecycle_commands(text: &str) -> Vec<usize> {
    text.match_indices("$C ")
        .filter(|(i, m)| {
            let rest = &text[i + m.len()..];
            ["stop ", "start ", "restart ", "up "]
                .iter()
                .any(|verb| rest.starts_with(verb))
        })
        .map(|(i, _)| i)
        .collect()
}

const MAINTENANCE_ON: &str = r#"touch "$H/maintenance""#;
const SNAPSHOT_LOCK: &str = r#"flock "$H/snapshot.lock" true"#;
const MAINTENANCE_OFF: &str = r#"rm "$H/maintenance""#;

#[test]
fn every_procedure_that_stops_the_issuer_holds_a_maintenance_window() {
    let text = runbook();
    for heading in [
        "### 5.2 K2",
        "### 5.3 K3",
        "## 6. B1",
        "## 7. M2",
        "## 11. R5",
        "## 12. I1",
    ] {
        let s = section(&text, heading);
        let commands = lifecycle_commands(&s);
        assert!(!commands.is_empty(), "{heading}: no container command");
        let on = s
            .find(MAINTENANCE_ON)
            .unwrap_or_else(|| panic!("{heading}: no {MAINTENANCE_ON}"));
        let lock = s
            .find(SNAPSHOT_LOCK)
            .unwrap_or_else(|| panic!("{heading}: no {SNAPSHOT_LOCK}"));
        let off = s
            .rfind(MAINTENANCE_OFF)
            .unwrap_or_else(|| panic!("{heading}: no {MAINTENANCE_OFF}"));
        assert!(
            on < lock && lock < commands[0],
            "{heading}: a container command before the maintenance window"
        );
        assert!(
            *commands.last().unwrap() < off,
            "{heading}: a container command after the maintenance window"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// B1: snapshot retention (INFRA-4).
// ---------------------------------------------------------------------------------------------

/// The age in minutes at which the GNU find test of `command` first matches: `-mmin +n` and
/// `-mtime +n` ignore the fractional part, so `+n` needs n + 1 whole minutes or days.
fn find_threshold_minutes(command: &str) -> u64 {
    let words: Vec<&str> = command.split_whitespace().collect();
    for w in words.windows(2) {
        let n = || -> u64 {
            w[1].strip_prefix('+')
                .and_then(|n| n.parse().ok())
                .unwrap_or_else(|| panic!("{command}"))
        };
        match w[0] {
            "-mmin" => return n() + 1,
            "-mtime" => return (n() + 1) * 1_440,
            _ => {}
        }
    }
    panic!("no -mmin or -mtime: {command}")
}

/// S12 review OPS-B1-RETENTION-MAINT (§19.27): both deletion lines keep the newest snapshot. A
/// maintenance window (M2, I1) makes `snapshot.sh` take none while the running issuer may keep
/// deciding transitions; a window longer than the daily retention would otherwise leave B1 nothing
/// to restore from, and the journal cannot stand in for a snapshot (its prefix was pruned after
/// the last one, so an empty database refuses the start with a gap).
#[test]
fn snapshot_deletion_keeps_the_newest_snapshot() {
    let lines = cron_lines(&section(&runbook(), "## 6. B1"));
    let newest = r#"! -name "$(cd /srv/ghost-issuer/snapshots && ls -t issuer-*.redb 2>/dev/null | head -n 1)""#;
    let deletions: Vec<&CronLine> = lines
        .iter()
        .filter(|l| l.command.contains("find ") && l.command.contains("-delete"))
        .collect();
    assert_eq!(
        deletions.len(),
        2,
        "the hourly and the daily retention line"
    );
    for l in deletions {
        assert!(
            l.command.contains(newest),
            "a deletion line that can remove the newest snapshot: {}",
            l.command
        );
    }
}

#[test]
fn no_snapshot_outlives_its_retention() {
    let lines = cron_lines(&section(&runbook(), "## 6. B1"));
    let daily_name = "-name 'issuer-*00.redb'";
    let mut checked = 0;
    for (hourly, bound_minutes) in [(true, 48 * 60), (false, 7 * 1_440)] {
        for l in lines.iter().filter(|l| {
            l.command.contains("find ")
                && l.command.contains(daily_name)
                && l.command.contains(&format!("! {daily_name}")) == hourly
        }) {
            assert!(l.command.contains("-delete"), "{}", l.command);
            // Deleted at the first run after the threshold: at most one period later.
            let max_age = find_threshold_minutes(&l.command) + l.every_minutes;
            assert!(
                max_age <= bound_minutes,
                "a snapshot lives up to {max_age} min, the retention is {bound_minutes}: {}",
                l.command
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 2, "one hourly and one daily retention line");
}

// ---------------------------------------------------------------------------------------------
// One-time starts and expected outputs (INFRA-5).
// ---------------------------------------------------------------------------------------------

fn one_time_flag(line: &str) -> bool {
    line.contains("GHOST_ISSUER_FLAGS=--")
        || (line.contains("GHOST_RELAY_") && line.contains("_NULLIFIERS=--"))
}

#[test]
fn every_one_time_start_is_checked_before_the_normal_start() {
    let text = runbook();
    let mut pending: Option<(usize, String)> = None;
    let mut starts = 0;
    for (i, line) in text.lines().enumerate() {
        let n = i + 1;
        if one_time_flag(line) {
            assert!(
                line.contains(" up -d "),
                "line {n}: a one-time flag outside its start command: {line}"
            );
            assert!(pending.is_none(), "line {n}: two one-time starts in a row");
            let service = line
                .split_whitespace()
                .last()
                .unwrap()
                .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-');
            pending = Some((n, service.to_string()));
            starts += 1;
        } else if line.contains("Așteptat") {
            pending = None;
        } else if let Some((at, service)) = &pending {
            assert!(
                !(line.contains(" up -d ") && line.contains(service.as_str())),
                "line {n}: {service} starts again without the flag before the expected output of \
                 its one-time start (line {at})"
            );
        }
    }
    assert!(
        pending.is_none(),
        "a one-time start without expected output"
    );
    assert!(
        starts >= 4,
        "--restore, --restore-wallet, --nullifiers-init, --nullifiers-reset"
    );
}

#[test]
fn no_expected_output_is_the_tail_of_a_log() {
    for (i, line) in runbook().lines().enumerate() {
        assert!(
            !(line.contains(" logs ") && line.contains("| tail")),
            "line {}: the tail of a log shows whatever logged last (Tor keeps logging): {line}",
            i + 1
        );
    }
}

// ---------------------------------------------------------------------------------------------
// The issuer's onion (INFRA-3) and its stop (INFRA-1).
// ---------------------------------------------------------------------------------------------

#[test]
fn the_issuer_onion_is_checked_on_the_hostname_tor_wrote() {
    let entrypoint = infra_file("issuer/entrypoint.sh");
    let tor_role = between(&entrypoint, "\n  tor)\n", "\n    ;;\n");
    let rm = tor_role
        .find(r#"rm -f "$HS_DIR/hostname""#)
        .expect("the tor role removes a hostname that came with the key set");
    let start = tor_role.find("tor -f /etc/tor/torrc").unwrap();
    assert!(rm < start);
    assert!(
        !tor_role.contains(r#"-s "$HS_DIR/hostname""#),
        "the tor role requires a hostname file next to the secret key"
    );
    let install = section(&runbook(), "## 2. Instalare");
    let up = install
        .find("$C up -d tor")
        .expect("Tor starts in the install");
    let build = install
        .find("$C --profile ops build ops")
        .expect("the install builds the ops tools");
    let onions = install
        .find("$C run --rm ops schedule-onions --schedule /etc/ghost/schedule.ghes")
        .expect("the install prints the schedule's onions");
    let check = install
        .find(
            r#"grep -c -x -F "ISSUER_ONION onion=$(cat "$H/tor/ghost-issuer/hostname") port=443""#,
        )
        .expect("the install checks Tor's onion against the schedule's issuer_onion");
    assert!(
        up < check,
        "the ES check reads a hostname that Tor has not written yet"
    );
    assert!(build < onions && onions < check);
    assert!(
        !install.contains("grep -a"),
        "the schedule's bytes also list the relays' onions with port 443"
    );
}

#[test]
fn stopping_the_issuer_ends_it_at_once() {
    let compose = infra_file("issuer/docker-compose.stagenet.yml");
    let issuer = between(&compose, "\n  issuer:\n", "\n  # The operator tools");
    assert!(
        issuer.lines().any(|l| l.trim() == "init: true"),
        "the issuer runs as PID 1, which ignores SIGTERM"
    );
}

/// The ops service has a read-only root: `RedbSnapshot` copies the snapshot to the temporary
/// directory, which must be a private tmpfs (the copy never reaches a disk and dies with the
/// container).
#[test]
fn the_ops_tools_recover_a_snapshot_copy_on_a_private_tmpfs() {
    let compose = infra_file("issuer/docker-compose.stagenet.yml");
    let ops = between(&compose, "\n  ops:\n", "\nsecrets:");
    let lines: Vec<&str> = ops.lines().map(str::trim).collect();
    assert!(lines.contains(&"read_only: true"));
    assert!(lines.contains(
        &"- ${GHOST_ISSUER_HOST_DIR:?name the issuer host directory}/snapshots:/snapshots:ro"
    ));
    let tmpfs = lines
        .iter()
        .position(|l| *l == "tmpfs:")
        .expect("the ops service mounts a tmpfs");
    assert!(
        lines[tmpfs + 1].starts_with("- /tmp:mode=0700,"),
        "{}",
        lines[tmpfs + 1]
    );
}
