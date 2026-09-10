//! Relay-capture validator (privacy invariant T1, ADR-09, threat model §6/§9).
//!
//! A relay running in capture mode writes one JSON object per observable event: everything it
//! could possibly know about that event. This crate checks that every captured object is a
//! subset of the *allowed observables* declared in `allowed-observables.json`:
//!
//! * every key must be declared in the schema;
//! * every value must satisfy the declared shape (fixed-length hex, enum, bucketed integer);
//! * no string value may look like an IP address, a GHOST identity, an e-mail address or free
//!   text — those are the classic ways identity leaks into "harmless" logs.
//!
//! The validator is deliberately strict: an unknown field is a failure, not a warning, because
//! the schema is the normative list of what a relay is permitted to learn.

use serde_json::{Map, Value};
use std::fmt;

/// One violation found in a capture. `line` is 1-based.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub line: usize,
    pub field: String,
    pub message: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "line {}: field `{}`: {}",
            self.line, self.field, self.message
        )
    }
}

/// Parsed allowed-observables schema.
#[derive(Debug, Clone)]
pub struct Schema {
    fields: Map<String, Value>,
    forbidden_substrings: Vec<String>,
}

impl Schema {
    /// Parses the JSON schema document. Fails on structural errors in the schema itself.
    pub fn parse(text: &str) -> Result<Self, String> {
        let root: Value =
            serde_json::from_str(text).map_err(|e| format!("schema is not valid JSON: {e}"))?;
        let version = root
            .get("version")
            .and_then(Value::as_u64)
            .ok_or("schema: missing integer `version`")?;
        if version != 1 {
            return Err(format!("schema: unsupported version {version}"));
        }
        let fields = root
            .get("allowed_fields")
            .and_then(Value::as_object)
            .ok_or("schema: missing object `allowed_fields`")?
            .clone();
        for (name, spec) in &fields {
            let kind = spec
                .get("type")
                .and_then(Value::as_str)
                .ok_or(format!("schema: field `{name}` has no `type`"))?;
            match kind {
                "hex" => {
                    spec.get("len")
                        .and_then(Value::as_u64)
                        .ok_or(format!("schema: hex field `{name}` needs `len`"))?;
                }
                "enum" => {
                    spec.get("values")
                        .and_then(Value::as_array)
                        .ok_or(format!("schema: enum field `{name}` needs `values`"))?;
                }
                "bucketed_int" => {
                    let g = spec
                        .get("granularity")
                        .and_then(Value::as_u64)
                        .ok_or(format!("schema: bucketed_int `{name}` needs `granularity`"))?;
                    if g == 0 {
                        return Err(format!(
                            "schema: bucketed_int `{name}` granularity must be > 0"
                        ));
                    }
                }
                "uint" => {}
                other => return Err(format!("schema: field `{name}` has unknown type `{other}`")),
            }
        }
        let forbidden_substrings = root
            .get("forbidden_substrings")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        Ok(Schema {
            fields,
            forbidden_substrings,
        })
    }

    /// Validates one NDJSON capture document. Returns every violation found (empty = pass).
    pub fn check_capture(&self, ndjson: &str) -> Vec<Violation> {
        let mut out = Vec::new();
        for (idx, raw) in ndjson.lines().enumerate() {
            let line = idx + 1;
            if raw.trim().is_empty() {
                continue;
            }
            let obj: Value = match serde_json::from_str(raw) {
                Ok(v) => v,
                Err(e) => {
                    out.push(Violation {
                        line,
                        field: "<line>".into(),
                        message: format!("not valid JSON: {e}"),
                    });
                    continue;
                }
            };
            let Some(map) = obj.as_object() else {
                out.push(Violation {
                    line,
                    field: "<line>".into(),
                    message: "capture entry must be a JSON object".into(),
                });
                continue;
            };
            for (key, value) in map {
                match self.fields.get(key) {
                    None => out.push(Violation {
                        line,
                        field: key.clone(),
                        message: "field is not an allowed observable".into(),
                    }),
                    Some(spec) => self.check_value(line, key, spec, value, &mut out),
                }
            }
        }
        out
    }

    fn check_value(
        &self,
        line: usize,
        key: &str,
        spec: &Value,
        value: &Value,
        out: &mut Vec<Violation>,
    ) {
        let kind = spec.get("type").and_then(Value::as_str).unwrap_or("");
        match kind {
            "hex" => {
                let want = spec.get("len").and_then(Value::as_u64).unwrap_or(0) as usize;
                match value.as_str() {
                    Some(s)
                        if s.len() == want
                            && s.chars()
                                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) => {}
                    Some(s) => out.push(Violation {
                        line,
                        field: key.into(),
                        message: format!(
                            "expected {want} lowercase hex chars, got {} chars",
                            s.len()
                        ),
                    }),
                    None => out.push(Violation {
                        line,
                        field: key.into(),
                        message: "expected a hex string".into(),
                    }),
                }
            }
            "enum" => {
                let allowed = spec
                    .get("values")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                if !allowed.contains(value) {
                    out.push(Violation {
                        line,
                        field: key.into(),
                        message: format!("value {value} not in allowed set"),
                    });
                }
            }
            "bucketed_int" => {
                let g = spec.get("granularity").and_then(Value::as_u64).unwrap_or(1);
                match value.as_u64() {
                    Some(n) if n % g == 0 => {}
                    Some(n) => out.push(Violation {
                        line,
                        field: key.into(),
                        message: format!("value {n} is not a multiple of granularity {g} (finer timing than permitted)"),
                    }),
                    None => out.push(Violation { line, field: key.into(), message: "expected a non-negative integer".into() }),
                }
            }
            "uint" if value.as_u64().is_none() => out.push(Violation {
                line,
                field: key.into(),
                message: "expected a non-negative integer".into(),
            }),
            _ => {}
        }
        if let Some(reason) = value.as_str().and_then(|s| self.looks_identifying(s)) {
            out.push(Violation {
                line,
                field: key.into(),
                message: reason,
            });
        }
    }

    /// Heuristics for values that must never appear in a relay's view, whatever the field.
    fn looks_identifying(&self, s: &str) -> Option<String> {
        if looks_like_ipv4(s) {
            return Some("value looks like an IPv4 address".into());
        }
        if looks_like_ipv6(s) {
            return Some("value looks like an IPv6 address".into());
        }
        if s.contains('@') && s.contains('.') {
            return Some("value looks like an e-mail address".into());
        }
        for needle in &self.forbidden_substrings {
            if s.to_ascii_lowercase()
                .contains(&needle.to_ascii_lowercase())
            {
                return Some(format!("value contains forbidden substring `{needle}`"));
            }
        }
        if s.chars().any(char::is_whitespace) {
            return Some(
                "value contains whitespace (free text is never an allowed observable)".into(),
            );
        }
        None
    }
}

fn looks_like_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 3
                && p.chars().all(|c| c.is_ascii_digit())
                && p.parse::<u16>().map(|n| n <= 255).unwrap_or(false)
        })
}

fn looks_like_ipv6(s: &str) -> bool {
    let groups = s.split(':').count();
    (3..=8).contains(&groups)
        && s.chars().all(|c| c.is_ascii_hexdigit() || c == ':')
        && s.contains(':')
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEMA: &str = include_str!("../../allowed-observables.json");

    fn schema() -> Schema {
        Schema::parse(SCHEMA).expect("bundled schema must parse")
    }

    #[test]
    fn bundled_schema_parses() {
        let s = schema();
        assert!(s.fields.contains_key("namespace_id"));
        assert!(s.fields.contains_key("size_bucket"));
    }

    #[test]
    fn positive_fixture_passes() {
        let v = schema().check_capture(include_str!("../../fixtures/capture-ok.ndjson"));
        assert!(v.is_empty(), "unexpected violations: {v:?}");
    }

    #[test]
    fn negative_fixture_fails_on_every_line() {
        let text = include_str!("../../fixtures/capture-bad.ndjson");
        let expected_lines = text.lines().filter(|l| !l.trim().is_empty()).count();
        let v = schema().check_capture(text);
        let mut lines: Vec<usize> = v.iter().map(|x| x.line).collect();
        lines.sort_unstable();
        lines.dedup();
        assert_eq!(
            lines.len(),
            expected_lines,
            "every bad line must produce a violation: {v:#?}"
        );
    }

    #[test]
    fn unknown_field_is_a_violation() {
        let v = schema().check_capture(r#"{"op":"store","source_ip":"10.0.0.1"}"#);
        assert!(v.iter().any(|x| x.field == "source_ip"));
    }

    #[test]
    fn fine_grained_timestamp_is_rejected() {
        let v = schema().check_capture(r#"{"op":"store","time_bucket":1757491261}"#);
        assert!(v.iter().any(|x| x.field == "time_bucket"));
        let ok = schema().check_capture(r#"{"op":"store","time_bucket":1757491260}"#);
        assert!(ok.is_empty());
    }

    #[test]
    fn unpadded_size_is_rejected() {
        let v = schema().check_capture(r#"{"op":"store","size_bucket":1337}"#);
        assert!(v.iter().any(|x| x.field == "size_bucket"));
    }

    #[test]
    fn ip_heuristics() {
        assert!(looks_like_ipv4("192.168.1.20"));
        assert!(!looks_like_ipv4("1.2.3"));
        assert!(!looks_like_ipv4("999.1.1.1"));
        assert!(looks_like_ipv6("2001:db8::1"));
        assert!(!looks_like_ipv6("deadbeef"));
    }
}
