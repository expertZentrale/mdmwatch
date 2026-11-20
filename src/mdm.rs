//! MDM-Log (mdmclient) auswerten.

use regex::Regex;
use serde_json::Value as J;
use std::collections::{HashMap, VecDeque};
use std::sync::OnceLock;

pub const PREDICATE: &str =
    r#"process == "mdmclient" OR subsystem == "com.apple.ManagedClient" OR process == "ManagedClient""#;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Command,
    Send,
    Response,
    Error,
    Other,
}

#[derive(Clone, Debug)]
pub struct Event {
    pub t: String,
    pub cat: String,
    pub mtype: String,
    pub msg: String,
    pub kind: Kind,
    pub command: Option<String>,
    pub target: Option<String>,
    pub uuid: Option<String>,
    pub status: Option<String>,
    pub http: Option<u16>,
    pub error: Option<String>,
    pub scope: Option<String>,
    pub important: bool,
}

struct Res {
    processing: Regex,
    sending: Regex,
    response: Regex,
    errchain: Regex,
    scope: Regex,
    important: Regex,
}

fn re() -> &'static Res {
    static R: OnceLock<Res> = OnceLock::new();
    R.get_or_init(|| Res {
        processing: Regex::new(r"Processing server request: (\w+) for: <([^>]+)>\s*\(([0-9A-Fa-f-]{36})\)").unwrap(),
        sending: Regex::new(r"Sending HTTP request \((\w+)\) \[(\w+)(?:\((\w+)\))?(?::([0-9A-Fa-f-]{36}))?\]").unwrap(),
        response: Regex::new(r"Received HTTP response \((\d+)\) \[(\w+)(?:\((\w+)\))?(?::([0-9A-Fa-f-]{36}))?\]").unwrap(),
        errchain: Regex::new(r"\[ErrorChain\.\d+\] \((\w+)\) \[([\w.]+:-?\d+)\] (.*?)>?$").unwrap(),
        scope: Regex::new(r"\[(\d+):(MDMAgent|MDMDaemon)").unwrap(),
        important: Regex::new(
            r"(?i)Processing server request|Sending HTTP request|Received HTTP response|\[ERROR\]|ErrorChain|InstallProfile|RemoveProfile|Installed configuration|Removed configuration|Declarative|Push notification|TokenUpdate|failed",
        )
        .unwrap(),
    })
}

/// Eine Zeile aus `log … --style ndjson`.
pub fn parse(v: &J) -> Option<Event> {
    let msg = v.get("eventMessage")?.as_str()?.to_string();
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let ts = s("timestamp");
    let mut e = Event {
        t: ts.chars().take(23).collect(),
        cat: s("category"),
        mtype: s("messageType"),
        msg,
        kind: Kind::Other,
        command: None,
        target: None,
        uuid: None,
        status: None,
        http: None,
        error: None,
        scope: None,
        important: false,
    };
    let r = re();
    if let Some(m) = r.scope.captures(&e.msg) {
        e.scope = Some(if &m[1] == "0" { "Gerät".into() } else { format!("Benutzer {}", &m[1]) });
    }
    if let Some(m) = r.processing.captures(&e.msg) {
        e.kind = Kind::Command;
        e.command = Some(m[1].into());
        e.target = Some(m[2].into());
        e.uuid = Some(m[3].to_uppercase());
    } else if let Some(m) = r.sending.captures(&e.msg) {
        e.kind = Kind::Send;
        e.status = Some(m[2].into());
        e.command = m.get(3).map(|x| x.as_str().into());
        e.uuid = m.get(4).map(|x| x.as_str().to_uppercase());
    } else if let Some(m) = r.response.captures(&e.msg) {
        e.kind = Kind::Response;
        e.http = m[1].parse().ok();
        e.status = Some(m[2].into());
        e.command = m.get(3).map(|x| x.as_str().into());
        e.uuid = m.get(4).map(|x| x.as_str().to_uppercase());
    } else if let Some(m) = r.errchain.captures(&e.msg) {
        e.kind = Kind::Error;
        e.command = Some(m[1].into());
        e.error = Some(m[3].trim().into());
    } else if e.msg.contains("[ERROR]") || e.mtype == "Error" || e.mtype == "Fault" {
        e.kind = Kind::Error;
    }
    e.important = e.kind != Kind::Other || r.important.is_match(&e.msg);
    Some(e)
}

#[derive(Clone, Debug, Default)]
pub struct Command {
    pub uuid: String,
    pub t: String,
    pub command: String,
    pub target: String,
    pub scope: String,
    pub status: String,
    pub http: Option<u16>,
    pub errors: Vec<String>,
}

impl Command {
    pub fn failed(&self) -> bool {
        self.status == "Error" || !self.errors.is_empty()
    }
}

#[derive(Default)]
pub struct Tracker {
    pub cmds: HashMap<String, Command>,
    order: VecDeque<String>,
    last_by_scope: HashMap<String, String>,
    pub checkins: Vec<String>,
    pub max: usize,
}

impl Tracker {
    pub fn new(max: usize) -> Self {
        Tracker { max, ..Default::default() }
    }

    fn entry(&mut self, uuid: &str, t: &str) -> &mut Command {
        if !self.cmds.contains_key(uuid) {
            self.order.push_back(uuid.to_string());
            self.cmds.insert(uuid.to_string(), Command { uuid: uuid.into(), t: t.into(), ..Default::default() });
            while self.order.len() > self.max {
                if let Some(old) = self.order.pop_front() {
                    self.cmds.remove(&old);
                }
            }
        }
        self.cmds.get_mut(uuid).unwrap()
    }

    pub fn feed(&mut self, e: &Event) {
        let scope = e.scope.clone().unwrap_or_default();
        match e.kind {
            Kind::Command => {
                let u = e.uuid.clone().unwrap_or_default();
                let c = self.entry(&u, &e.t);
                c.t = e.t.clone();
                c.command = e.command.clone().unwrap_or_default();
                c.target = e.target.clone().unwrap_or_default();
                c.scope = scope.clone();
                self.last_by_scope.insert(scope, u);
            }
            Kind::Send | Kind::Response => {
                if let Some(u) = e.uuid.clone() {
                    let c = self.entry(&u, &e.t);
                    if e.kind == Kind::Send {
                        c.status = e.status.clone().unwrap_or_default();
                        if c.command.is_empty() {
                            c.command = e.command.clone().unwrap_or_default();
                        }
                    } else {
                        c.http = e.http;
                    }
                } else if e.kind == Kind::Send && e.status.as_deref() == Some("Idle") {
                    self.checkins.push(e.t.clone());
                    if self.checkins.len() > 500 {
                        self.checkins.remove(0);
                    }
                }
            }
            Kind::Error => {
                if let Some(u) = self.last_by_scope.get(&scope).cloned() {
                    if let Some(c) = self.cmds.get_mut(&u) {
                        if e.command.as_deref().map(|x| x == c.command).unwrap_or(true) {
                            let err = e.error.clone().unwrap_or_else(|| e.msg.clone());
                            if !c.errors.contains(&err) {
                                c.errors.push(err);
                            }
                        }
                    }
                }
            }
            Kind::Other => {}
        }
    }

    /// Neueste zuerst
    pub fn list(&self) -> Vec<&Command> {
        self.order.iter().rev().filter_map(|u| self.cmds.get(u)).collect()
    }
}

pub struct Summary {
    pub by_command: Vec<(String, usize)>,
    pub repeated_errors: Vec<(String, String, usize)>,
    pub failed: usize,
}

pub fn summarize(t: &Tracker) -> Summary {
    let mut by: HashMap<String, usize> = HashMap::new();
    let mut errs: HashMap<(String, String), usize> = HashMap::new();
    let mut failed = 0;
    for c in t.cmds.values() {
        *by.entry(if c.command.is_empty() { "?".into() } else { c.command.clone() }).or_default() += 1;
        if c.failed() {
            failed += 1;
        }
        for e in &c.errors {
            let norm = crate::util::uuid_re().replace_all(e, "‹uuid›").to_string();
            *errs.entry((c.command.clone(), norm)).or_default() += 1;
        }
    }
    let mut by_command: Vec<_> = by.into_iter().collect();
    by_command.sort_by(|a, b| b.1.cmp(&a.1));
    let mut repeated_errors: Vec<_> = errs.into_iter().map(|((c, e), n)| (c, e, n)).collect();
    repeated_errors.sort_by(|a, b| b.2.cmp(&a.2));
    Summary { by_command, repeated_errors, failed }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ev(msg: &str) -> Event {
        parse(&serde_json::json!({"timestamp":"2026-11-19 01:14:41.846","messageType":"Default","category":"MDMAgent","eventMessage":msg})).unwrap()
    }
    #[test]
    fn command_flow() {
        let mut t = Tracker::new(100);
        let u = "FFE25F5D-24CA-49CD-8C26-7F423DB9023E";
        t.feed(&ev(&format!("[*] [502:MDMAgent:<0xed41e7>] Processing server request: RemoveProfile for: <User: 502> ({u}) PowerNap: no")));
        t.feed(&ev("[ERROR]#[502:MDMAgent:<0xf208eb>] [ErrorChain.0] (RemoveProfile) [MDMClientError:89] Profile with identifier 'com.example.vpn' not found.>"));
        t.feed(&ev(&format!("[*] [502:MDMAgent:HTTPUtil:<0xed41e7>] >>>>> Sending HTTP request (PUT) [Error(RemoveProfile):{u}] >>>>>")));
        t.feed(&ev(&format!("[*] [502:MDMAgent:HTTPUtil:<0xed41e7>] <<<<< Received HTTP response (200) [Error(RemoveProfile):{u}] <<<<<")));
        t.feed(&ev("[*] [0:MDMDaemon:HTTPUtil:<0x1>] >>>>> Sending HTTP request (PUT) [Idle] >>>>>"));
        let c = &t.cmds[u];
        assert_eq!(c.command, "RemoveProfile");
        assert_eq!(c.status, "Error");
        assert_eq!(c.http, Some(200));
        assert_eq!(c.scope, "Benutzer 502");
        assert_eq!(c.errors, vec!["Profile with identifier 'com.example.vpn' not found."]);
        assert_eq!(t.checkins.len(), 1);
        let s = summarize(&t);
        assert_eq!(s.failed, 1);
    }
}
