//! Kleine Hilfsfunktionen.

use regex::Regex;
use serde_json::{Map, Value as J};
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

pub struct CmdOut {
    pub ok: bool,
    pub stdout: Vec<u8>,
    pub stderr: String,
}

pub fn run(cmd: &str, args: &[&str]) -> CmdOut {
    match Command::new(cmd).args(args).output() {
        Ok(o) => CmdOut {
            ok: o.status.success(),
            stdout: o.stdout,
            stderr: String::from_utf8_lossy(&o.stderr).trim().to_string(),
        },
        Err(e) => CmdOut { ok: false, stdout: vec![], stderr: e.to_string() },
    }
}

pub fn now_iso() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

pub fn uuid_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}").unwrap())
}

fn secret_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?i)password|passwd|secret|token|sharedsecret|pkcs12|privatekey|challenge").unwrap())
}

/// plist -> JSON, Geheimnisse schwärzen, Binärdaten nur als Länge.
pub fn plist_to_json(v: &plist::Value, key: &str) -> J {
    let secret = !key.is_empty() && secret_re().is_match(key);
    match v {
        plist::Value::Dictionary(d) => {
            let mut m = Map::new();
            for (k, x) in d.iter() {
                m.insert(k.clone(), plist_to_json(x, k));
            }
            J::Object(m)
        }
        plist::Value::Array(a) => J::Array(a.iter().map(|x| plist_to_json(x, key)).collect()),
        _ if secret => J::String("‹geschwärzt›".into()),
        plist::Value::Data(b) => J::String(format!("‹{} Bytes›", b.len())),
        plist::Value::String(s) => J::String(s.clone()),
        plist::Value::Boolean(b) => J::Bool(*b),
        plist::Value::Integer(i) => i
            .as_signed()
            .map(|x| J::from(x))
            .or_else(|| i.as_unsigned().map(J::from))
            .unwrap_or(J::Null),
        plist::Value::Real(f) => J::from(*f),
        plist::Value::Date(d) => {
            let st: std::time::SystemTime = (*d).into();
            J::String(chrono::DateTime::<chrono::Local>::from(st).format("%Y-%m-%d %H:%M:%S").to_string())
        }
        plist::Value::Uid(u) => J::String(format!("UID({})", u.get())),
        _ => J::Null,
    }
}

pub fn short_hash(v: &J) -> String {
    // FNV-1a, reicht zum Erkennen von Änderungen
    let s = v.to_string();
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{:016x}", h)
}

pub fn home() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/tmp".into()))
}

/// ~/Library/Application Support/MDMWatch
pub fn app_dir() -> PathBuf {
    let d = home().join("Library/Application Support/MDMWatch");
    let _ = std::fs::create_dir_all(&d);
    d
}

/// Ordner, in den der root-Helfer schreibt (gehört dem Benutzer).
pub fn run_dir() -> PathBuf {
    let d = app_dir().join("run");
    let _ = std::fs::create_dir_all(&d);
    d
}

pub fn json_list(v: &J) -> Vec<String> {
    match v {
        J::Array(a) => a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect(),
        J::String(s) => vec![s.clone()],
        _ => vec![],
    }
}

pub fn fmt_list(v: &[String]) -> String {
    if v.is_empty() { "–".into() } else { v.join(", ") }
}
