//! V-8 / G-R8 prototype (design §16.1 G-R8, §22.8.10 point 4): lists clock, logging, printing and
//! network sites in the compiled library code of every crate of a package's normal dependency
//! graph for the shipped Android triples.
//!
//! Compiled library code: the `lib` target's module tree only (no `build.rs`, tests, benches or
//! examples), after removing every item, impl item, statement, arm and field whose `#[cfg]`
//! evaluates false for the target (`test`, `debug_assertions`, disabled features, other
//! architectures and operating systems). Comments are not tokens, so they never match. Tokens
//! inside macro invocations and `macro_rules!` bodies are scanned too. `cargo:` directives of
//! build scripts are listed separately (the mechanism G-R3 reads).
//!
//! Usage (scripts/v8-g-r8-baseline.sh runs it per shipped triple):
//!   g_r8_scan <workspace Cargo.toml> <triple> <DM crate tree file> <library features tree file> <shipped tree file>
//! The package set is the `cargo tree -e normal` output of the DM crate for the triple; the enabled
//! features of each package are those of the shipped library (`cargo tree -p ghost-client-net
//! -f '{p}|{f}'`, the same feature resolution as its build).
//! Output: `site <crate>@<version> <file>:<line> <pattern> <kind> [lib|proc-macro] | <source>`,
//! `directive`, `crate` and `note` lines.

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use quote::ToTokens;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use syn::punctuated::Punctuated;
use syn::visit_mut::VisitMut;
use syn::{Attribute, Expr, ImplItem, Item, Lit, Meta, Stmt, Token, TraitItem};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Tri {
    True,
    False,
    Unknown,
}

struct Cfg<'a> {
    arch: &'a str,
    features: &'a BTreeSet<String>,
}

impl Cfg<'_> {
    fn eval(&self, meta: &Meta) -> Tri {
        match meta {
            Meta::Path(p) => match p.get_ident().map(ToString::to_string).as_deref() {
                Some("unix") => Tri::True,
                Some(
                    "windows" | "test" | "debug_assertions" | "doc" | "docsrs" | "miri" | "fuzzing"
                    | "loom" | "kani" | "hax" | "eurydice" | "valgrind_ct_test" | "coverage"
                    | "coverage_nightly",
                ) => Tri::False,
                _ => Tri::Unknown,
            },
            Meta::NameValue(nv) => {
                let name = nv
                    .path
                    .get_ident()
                    .map(ToString::to_string)
                    .unwrap_or_default();
                let value = match &nv.value {
                    Expr::Lit(lit) => match &lit.lit {
                        Lit::Str(s) => s.value(),
                        _ => return Tri::Unknown,
                    },
                    _ => return Tri::Unknown,
                };
                let is = |b: bool| if b { Tri::True } else { Tri::False };
                match name.as_str() {
                    "feature" => is(self.features.contains(&value)),
                    "target_arch" => is(value == self.arch),
                    "target_os" => is(value == "android"),
                    "target_family" => is(value == "unix"),
                    "target_pointer_width" => is(value == "64"),
                    "target_endian" => is(value == "little"),
                    "target_env" => is(value.is_empty()),
                    "target_vendor" => is(value == "unknown"),
                    "panic" => is(value == "unwind"),
                    _ => Tri::Unknown,
                }
            }
            Meta::List(list) => {
                let name = list
                    .path
                    .get_ident()
                    .map(ToString::to_string)
                    .unwrap_or_default();
                let Ok(inner) =
                    list.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
                else {
                    return Tri::Unknown;
                };
                let values: Vec<Tri> = inner.iter().map(|m| self.eval(m)).collect();
                match name.as_str() {
                    "all" => {
                        if values.contains(&Tri::False) {
                            Tri::False
                        } else if values.contains(&Tri::Unknown) {
                            Tri::Unknown
                        } else {
                            Tri::True
                        }
                    }
                    "any" => {
                        if values.contains(&Tri::True) {
                            Tri::True
                        } else if values.contains(&Tri::Unknown) {
                            Tri::Unknown
                        } else {
                            Tri::False
                        }
                    }
                    "not" => match values.first() {
                        Some(Tri::True) => Tri::False,
                        Some(Tri::False) => Tri::True,
                        _ => Tri::Unknown,
                    },
                    _ => Tri::Unknown,
                }
            }
        }
    }

    /// False only when some `#[cfg]` is false; `Unknown` is kept (over-approximation).
    fn keep(&self, attrs: &[Attribute]) -> bool {
        attrs
            .iter()
            .filter(|a| a.path().is_ident("cfg"))
            .all(|a| match a.parse_args::<Meta>() {
                Ok(meta) => self.eval(&meta) != Tri::False,
                Err(_) => true,
            })
    }
}

struct Prune<'a>(&'a Cfg<'a>);

fn item_attrs(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(i) => &i.attrs,
        Item::Enum(i) => &i.attrs,
        Item::ExternCrate(i) => &i.attrs,
        Item::Fn(i) => &i.attrs,
        Item::ForeignMod(i) => &i.attrs,
        Item::Impl(i) => &i.attrs,
        Item::Macro(i) => &i.attrs,
        Item::Mod(i) => &i.attrs,
        Item::Static(i) => &i.attrs,
        Item::Struct(i) => &i.attrs,
        Item::Trait(i) => &i.attrs,
        Item::TraitAlias(i) => &i.attrs,
        Item::Type(i) => &i.attrs,
        Item::Union(i) => &i.attrs,
        Item::Use(i) => &i.attrs,
        _ => &[],
    }
}

fn impl_attrs(item: &ImplItem) -> &[Attribute] {
    match item {
        ImplItem::Const(i) => &i.attrs,
        ImplItem::Fn(i) => &i.attrs,
        ImplItem::Type(i) => &i.attrs,
        ImplItem::Macro(i) => &i.attrs,
        _ => &[],
    }
}

fn trait_attrs(item: &TraitItem) -> &[Attribute] {
    match item {
        TraitItem::Const(i) => &i.attrs,
        TraitItem::Fn(i) => &i.attrs,
        TraitItem::Type(i) => &i.attrs,
        TraitItem::Macro(i) => &i.attrs,
        _ => &[],
    }
}

fn stmt_attrs(stmt: &Stmt) -> &[Attribute] {
    match stmt {
        Stmt::Local(l) => &l.attrs,
        Stmt::Item(i) => item_attrs(i),
        Stmt::Macro(m) => &m.attrs,
        Stmt::Expr(_, _) => &[],
    }
}

impl VisitMut for Prune<'_> {
    fn visit_file_mut(&mut self, f: &mut syn::File) {
        f.items.retain(|i| self.0.keep(item_attrs(i)));
        syn::visit_mut::visit_file_mut(self, f);
    }
    fn visit_item_mod_mut(&mut self, m: &mut syn::ItemMod) {
        if let Some((_, items)) = &mut m.content {
            items.retain(|i| self.0.keep(item_attrs(i)));
        }
        syn::visit_mut::visit_item_mod_mut(self, m);
    }
    fn visit_item_impl_mut(&mut self, i: &mut syn::ItemImpl) {
        i.items.retain(|x| self.0.keep(impl_attrs(x)));
        syn::visit_mut::visit_item_impl_mut(self, i);
    }
    fn visit_item_trait_mut(&mut self, i: &mut syn::ItemTrait) {
        i.items.retain(|x| self.0.keep(trait_attrs(x)));
        syn::visit_mut::visit_item_trait_mut(self, i);
    }
    fn visit_block_mut(&mut self, b: &mut syn::Block) {
        b.stmts.retain(|s| self.0.keep(stmt_attrs(s)));
        syn::visit_mut::visit_block_mut(self, b);
    }
    fn visit_expr_match_mut(&mut self, m: &mut syn::ExprMatch) {
        m.arms.retain(|a| self.0.keep(&a.attrs));
        syn::visit_mut::visit_expr_match_mut(self, m);
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Site {
    file: String,
    line: usize,
    pattern: &'static str,
    kind: &'static str,
}

const CLOCK_LOG: &[(&str, &[&str])] = &[
    ("SystemTime", &["SystemTime"]),
    ("Instant::now", &["Instant", "::", "now"]),
    ("std::time", &["std", "::", "time"]),
    ("chrono", &["chrono"]),
    ("time::", &["time", "::"]),
    ("log::", &["log", "::"]),
    ("tracing::", &["tracing", "::"]),
    ("println!", &["println", "!"]),
    ("eprintln!", &["eprintln", "!"]),
    ("dbg!", &["dbg", "!"]),
    ("print!", &["print", "!"]),
    ("eprint!", &["eprint", "!"]),
];
const NETWORK: &[(&str, &[&str])] = &[
    ("std::net", &["std", "::", "net"]),
    ("TcpStream", &["TcpStream"]),
    ("TcpListener", &["TcpListener"]),
    ("UdpSocket", &["UdpSocket"]),
    ("ToSocketAddrs", &["ToSocketAddrs"]),
];

fn flatten(stream: TokenStream, out: &mut Vec<(String, usize)>) {
    let mut iter = stream.into_iter().peekable();
    while let Some(tt) = iter.next() {
        match tt {
            TokenTree::Group(g) => {
                if g.delimiter() == Delimiter::None {
                    flatten(g.stream(), out);
                } else {
                    out.push(("(".into(), g.span().start().line));
                    flatten(g.stream(), out);
                    out.push((")".into(), g.span().end().line));
                }
            }
            TokenTree::Ident(i) => out.push((i.to_string(), i.span().start().line)),
            TokenTree::Punct(p) => {
                if p.as_char() == ':' {
                    if let Some(TokenTree::Punct(q)) = iter.peek() {
                        if q.as_char() == ':' {
                            iter.next();
                            out.push(("::".into(), p.span().start().line));
                            continue;
                        }
                    }
                }
                out.push((p.as_char().to_string(), p.span().start().line));
            }
            TokenTree::Literal(l) => out.push(("<lit>".into(), l.span().start().line)),
        }
    }
}

fn scan_tokens(stream: TokenStream, file: &str, sites: &mut BTreeSet<Site>) {
    let mut toks = Vec::new();
    flatten(stream, &mut toks);
    for i in 0..toks.len() {
        for (list, kind) in [(CLOCK_LOG, "clock-log"), (NETWORK, "network")] {
            for (name, seq) in list {
                if i + seq.len() <= toks.len()
                    && seq.iter().enumerate().all(|(k, s)| toks[i + k].0 == *s)
                {
                    // `time::` preceded by `std ::` is reported once, as `std::time`.
                    if *name == "time::"
                        && i >= 2
                        && toks[i - 1].0 == "::"
                        && toks[i - 2].0 == "std"
                    {
                        continue;
                    }
                    sites.insert(Site {
                        file: file.to_owned(),
                        line: toks[i].1,
                        pattern: name,
                        kind,
                    });
                }
            }
        }
    }
}

fn scan_module(
    path: &Path,
    child_dir: &Path,
    root: &Path,
    cfg: &Cfg,
    sites: &mut BTreeSet<Site>,
    notes: &mut Vec<String>,
    seen: &mut BTreeSet<PathBuf>,
) {
    if !seen.insert(path.to_path_buf()) {
        return;
    }
    let rel = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    let Ok(text) = std::fs::read_to_string(path) else {
        notes.push(format!("note unreadable {rel}"));
        return;
    };
    let Ok(mut file) = syn::parse_file(&text) else {
        notes.push(format!("note unparsed {rel}"));
        return;
    };
    Prune(cfg).visit_file_mut(&mut file);
    scan_tokens(file.to_token_stream(), &rel, sites);
    let dir = path.parent().unwrap_or(Path::new("."));
    walk_mods(
        &file.items,
        dir,
        child_dir,
        root,
        cfg,
        sites,
        notes,
        seen,
        &rel,
    );
}

#[allow(clippy::too_many_arguments)]
fn walk_mods(
    items: &[Item],
    file_dir: &Path,
    child_dir: &Path,
    root: &Path,
    cfg: &Cfg,
    sites: &mut BTreeSet<Site>,
    notes: &mut Vec<String>,
    seen: &mut BTreeSet<PathBuf>,
    rel: &str,
) {
    for item in items {
        match item {
            Item::Mod(m) => {
                let name = m.ident.to_string().trim_start_matches("r#").to_owned();
                let path_value = |meta: &Meta| match meta {
                    Meta::NameValue(nv) if nv.path.is_ident("path") => match &nv.value {
                        Expr::Lit(l) => match &l.lit {
                            Lit::Str(s) => Some(s.value()),
                            _ => None,
                        },
                        _ => None,
                    },
                    _ => None,
                };
                // `#[path = "…"]`, or `#[cfg_attr(<true predicate>, path = "…")]`.
                let explicit = m.attrs.iter().find_map(|a| {
                    if a.path().is_ident("path") {
                        return path_value(&a.meta);
                    }
                    if a.path().is_ident("cfg_attr") {
                        let parts = a
                            .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
                            .ok()?;
                        let mut iter = parts.iter();
                        let predicate = iter.next()?;
                        if cfg.eval(predicate) == Tri::True {
                            return iter.find_map(path_value);
                        }
                    }
                    None
                });
                match &m.content {
                    Some((_, inner)) => {
                        walk_mods(
                            inner,
                            file_dir,
                            &child_dir.join(&name),
                            root,
                            cfg,
                            sites,
                            notes,
                            seen,
                            rel,
                        );
                    }
                    None => {
                        let candidates: Vec<PathBuf> = match explicit {
                            Some(p) => vec![file_dir.join(p)],
                            None => vec![
                                child_dir.join(format!("{name}.rs")),
                                child_dir.join(&name).join("mod.rs"),
                            ],
                        };
                        match candidates.iter().find(|c| c.is_file()) {
                            Some(found) => {
                                let is_mod_rs = found.file_name().is_some_and(|f| f == "mod.rs");
                                let next_child = if is_mod_rs {
                                    found.parent().unwrap_or(Path::new(".")).to_path_buf()
                                } else {
                                    found.with_extension("")
                                };
                                scan_module(found, &next_child, root, cfg, sites, notes, seen);
                            }
                            None => {
                                notes.push(format!("note missing module {name} declared in {rel}"))
                            }
                        }
                    }
                }
            }
            Item::Macro(mac) if mac.mac.path.is_ident("include") => {
                notes.push(format!("note include! in {rel} not followed"));
            }
            _ => {}
        }
    }
}

fn scan_build_script(path: &Path, root: &Path, out: &mut BTreeSet<String>) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    let rel = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    for (n, line) in text.lines().enumerate() {
        if line.contains("\"cargo:") && !line.trim_start().starts_with("//") {
            out.insert(format!("{rel}:{} | {}", n + 1, line.trim()));
        }
    }
}

fn metadata(manifest: &str, triple: &str) -> Value {
    let output = Command::new("cargo")
        .args([
            "metadata",
            "--format-version",
            "1",
            "--offline",
            "--all-features",
            "--filter-platform",
            triple,
            "--manifest-path",
            manifest,
        ])
        .output()
        .expect("cargo metadata runs");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("metadata json")
}

/// `cargo tree --prefix none -f '{p}'` lines to `name@version` keys.
fn tree_keys(path: &str) -> BTreeSet<String> {
    std::fs::read_to_string(path)
        .expect("tree file")
        .lines()
        .filter_map(|l| {
            let mut parts = l.split_whitespace();
            let name = parts.next()?;
            let version = parts.next()?.trim_start_matches('v');
            Some(format!("{name}@{version}"))
        })
        .collect()
}

/// `cargo tree -p <cdylib> -e normal --target <triple> --prefix none -f '{p}|{f}'` lines: the
/// features each package is built with in that library (resolver 2, the target's graph).
fn tree_features(path: &str) -> BTreeMap<String, BTreeSet<String>> {
    let mut out = BTreeMap::new();
    for line in std::fs::read_to_string(path)
        .expect("features file")
        .lines()
    {
        let Some((package, features)) = line.split_once('|') else {
            continue;
        };
        let mut parts = package.split_whitespace();
        let (Some(name), Some(version)) = (parts.next(), parts.next()) else {
            continue;
        };
        let key = format!("{name}@{}", version.trim_start_matches('v'));
        let set: BTreeSet<String> = features
            .trim_end_matches(" (*)")
            .split(',')
            .map(str::trim)
            .filter(|f| !f.is_empty())
            .map(str::to_owned)
            .collect();
        out.insert(key, set);
    }
    out
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    assert!(
        args.len() == 5,
        "usage: g_r8_scan <workspace Cargo.toml> <triple> <DM crate tree file> <library features tree file> <shipped tree file>"
    );
    let (manifest, triple, tree_file, features_file) = (&args[0], &args[1], &args[2], &args[3]);
    // `cargo tree -e normal,no-proc-macro`: what is linked; the rest runs only at build time.
    let shipped = tree_keys(&args[4]);
    let arch = triple.split('-').next().unwrap_or_default().to_owned();
    let wanted = tree_keys(tree_file);
    let built = tree_features(features_file);
    let meta = metadata(manifest, triple);
    let mut graph: BTreeMap<String, (String, String)> = BTreeMap::new();
    let mut notes = BTreeSet::new();
    for p in meta["packages"].as_array().expect("packages") {
        let name = p["name"].as_str().unwrap_or_default();
        let version = p["version"].as_str().unwrap_or_default();
        let key = format!("{name}@{version}");
        if !wanted.contains(&key) {
            continue;
        }
        let Some(features) = built.get(&key) else {
            notes.insert(format!(
                "note {key} is in the DM tree but not in the library tree"
            ));
            continue;
        };
        let licence = p["license"].as_str().unwrap_or("(license-file)").to_owned();
        let manifest_path = PathBuf::from(p["manifest_path"].as_str().unwrap_or_default());
        let pkg_root = manifest_path
            .parent()
            .unwrap_or(Path::new("."))
            .to_path_buf();
        let mut kind = if shipped.contains(&key) {
            "lib"
        } else {
            "build-time"
        };
        for target in p["targets"].as_array().into_iter().flatten() {
            let kinds: Vec<&str> = target["kind"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            let src = PathBuf::from(target["src_path"].as_str().unwrap_or_default());
            if kinds.contains(&"custom-build") {
                let mut lines = BTreeSet::new();
                scan_build_script(&src, &pkg_root, &mut lines);
                for l in lines {
                    println!("directive {key} {l}");
                }
            } else if kinds
                .iter()
                .any(|k| matches!(*k, "lib" | "rlib" | "cdylib" | "staticlib" | "proc-macro"))
            {
                if kinds.contains(&"proc-macro") {
                    kind = "proc-macro";
                }
                let cfg = Cfg {
                    arch: &arch,
                    features,
                };
                let mut sites = BTreeSet::new();
                let mut local_notes = Vec::new();
                let child = src.parent().unwrap_or(Path::new(".")).to_path_buf();
                scan_module(
                    &src,
                    &child,
                    &pkg_root,
                    &cfg,
                    &mut sites,
                    &mut local_notes,
                    &mut BTreeSet::new(),
                );
                for s in sites {
                    let text = std::fs::read_to_string(pkg_root.join(&s.file))
                        .ok()
                        .and_then(|t| {
                            t.lines()
                                .nth(s.line.saturating_sub(1))
                                .map(|l| l.trim().to_owned())
                        })
                        .unwrap_or_default();
                    println!(
                        "site {key} {}:{} {} {} [{kind}] | {text}",
                        s.file, s.line, s.pattern, s.kind
                    );
                }
                for n in local_notes {
                    notes.insert(format!("{n} ({key})"));
                }
            }
        }
        graph.insert(key, (licence, kind.to_owned()));
    }
    for (key, (licence, kind)) in &graph {
        println!("crate {key} {kind} {licence}");
    }
    for key in wanted.iter().filter(|k| !graph.contains_key(*k)) {
        notes.insert(format!("note {key} from the tree not found in metadata"));
    }
    for n in notes {
        println!("{n}");
    }
}
