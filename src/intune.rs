//! Intune-Agent-Logs (/Library/Logs/Microsoft/Intune) lesen und verfolgen.

use regex::Regex;
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub const DAEMON_DIR: &str = "/Library/Logs/Microsoft/Intune";

#[derive(Clone, Debug)]
pub struct Event {
    pub t: String,
    pub lvl: char,
    pub cat: String,
    pub msg: String,
    pub src: &'static str,
    pub policy: Option<String>,
}

struct Res {
    line: Regex,
    policy: Regex,
    name: Regex,
    domain: Regex,
}

fn re() -> &'static Res {
    static R: OnceLock<Res> = OnceLock::new();
    R.get_or_init(|| Res {
        line: Regex::new(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d:\d+) \| ([^|]+?) \| (\w) \| (\d+) \| ([^|]+?) \| (.*)$").unwrap(),
        policy: Regex::new(r"PolicyID: ([0-9a-fA-F-]{36})").unwrap(),
        name: Regex::new(r"(?:AppName|ScriptName|PolicyName): ([^,]+)").unwrap(),
        domain: Regex::new(r"Domain: (\w+)").unwrap(),
    })
}

pub fn parse(line: &str, src: &'static str) -> Option<Event> {
    let r = re();
    let m = r.line.captures(line.trim_end())?;
    let msg = m[6].to_string();
    Some(Event {
        t: m[1].chars().take(19).collect(),
        lvl: m[3].chars().next().unwrap_or('I'),
        cat: m[5].trim().to_string(),
        policy: r.policy.captures(&msg).map(|p| p[1].to_lowercase()),
        msg,
        src,
    })
}

#[derive(Clone, Debug, Default)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub domain: String,
    pub errors: usize,
    pub warnings: usize,
    pub last: String,
    pub last_msg: String,
    pub last_error: String,
}

#[derive(Default)]
pub struct Policies {
    pub p: HashMap<String, Policy>,
}

impl Policies {
    pub fn feed(&mut self, e: &Event) {
        let Some(id) = &e.policy else { return };
        let r = re();
        let x = self.p.entry(id.clone()).or_insert_with(|| Policy { id: id.clone(), ..Default::default() });
        if let Some(n) = r.name.captures(&e.msg) {
            x.name = n[1].trim().to_string();
        }
        if let Some(d) = r.domain.captures(&e.msg) {
            x.domain = d[1].to_string();
        }
        if x.domain.is_empty() {
            if e.cat.starts_with("App") {
                x.domain = "apps".into();
            } else if e.cat.starts_with("Script") {
                x.domain = "scripts".into();
            }
        }
        x.last = e.t.clone();
        x.last_msg = e.msg.chars().take(300).collect();
        match e.lvl {
            'E' => {
                x.errors += 1;
                x.last_error = format!("{}: {}", e.t, e.msg.chars().take(300).collect::<String>());
            }
            'W' => x.warnings += 1,
            _ => {}
        }
    }
}

fn list(dir: &Path, prefix: &str) -> Vec<PathBuf> {
    let mut v: Vec<(std::time::SystemTime, PathBuf)> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| {
                    let n = e.file_name().to_string_lossy().to_string();
                    n.starts_with(prefix) && n.ends_with(".log")
                })
                .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v.into_iter().map(|x| x.1).collect()
}

/// Verfolgt die neuesten Logdateien.
#[derive(Default)]
pub struct Tailer {
    pos: HashMap<PathBuf, u64>,
    initial_done: bool,
}

impl Tailer {
    /// Gibt neue Ereignisse zurück. Beim ersten Aufruf die letzten Dateien komplett.
    pub fn poll(&mut self) -> Result<Vec<Event>, String> {
        let daemon = list(Path::new(DAEMON_DIR), "IntuneMDMDaemon");
        let agent = list(&crate::util::home().join("Library/Logs/Microsoft/Intune"), "IntuneMDMAgent");
        if daemon.is_empty() && agent.is_empty() {
            return Err(format!("keine Logs in {DAEMON_DIR}"));
        }
        let take = if self.initial_done { 1 } else { 3 };
        let mut targets: Vec<(PathBuf, &'static str)> = vec![];
        for f in daemon.iter().rev().take(take).rev() {
            targets.push((f.clone(), "Daemon"));
        }
        for f in agent.iter().rev().take(take.min(2)).rev() {
            targets.push((f.clone(), "Agent"));
        }
        let mut out = vec![];
        for (f, src) in targets {
            let Ok(mut fh) = std::fs::File::open(&f) else { continue };
            let size = fh.metadata().map(|m| m.len()).unwrap_or(0);
            let mut p = *self.pos.get(&f).unwrap_or(&0);
            if size < p {
                p = 0;
            }
            if size == p {
                continue;
            }
            if fh.seek(SeekFrom::Start(p)).is_err() {
                continue;
            }
            let mut buf = Vec::new();
            let _ = fh.read_to_end(&mut buf);
            // nur vollständige Zeilen
            let end = buf.iter().rposition(|b| *b == b'\n').map(|i| i + 1).unwrap_or(0);
            self.pos.insert(f.clone(), p + end as u64);
            for line in String::from_utf8_lossy(&buf[..end]).lines() {
                if let Some(e) = parse(line, src) {
                    out.push(e);
                }
            }
        }
        self.initial_done = true;
        Ok(out)
    }
}
