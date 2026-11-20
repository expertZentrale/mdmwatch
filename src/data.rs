//! Profile, Netzwerk-Erweiterungen (VPN), DNS, Enrollment.

use crate::util::{self, json_list, plist_to_json, run, short_hash};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as J};
use std::time::Duration;

pub const NE_PLIST: &str = "/Library/Preferences/com.apple.networkextension.plist";
const APPLE_EPOCH: i64 = 978_307_200;

// ------------------------------------------------------------------ enrollment

pub fn enrollment() -> Vec<(String, String)> {
    let o = run("profiles", &["status", "-type", "enrollment"]);
    let text = String::from_utf8_lossy(&o.stdout).to_string();
    let mut v = vec![];
    for line in text.lines() {
        if let Some((k, val)) = line.split_once(':') {
            v.push((k.trim().to_string(), val.trim().to_string()));
        }
    }
    if v.is_empty() {
        v.push(("Status".into(), if o.stderr.is_empty() { text } else { o.stderr }));
    }
    v
}

// ------------------------------------------------------------------ profiles

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Payload {
    pub ptype: String,
    pub identifier: String,
    pub uuid: String,
    pub name: String,
    pub content: J,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Profile {
    pub scope: String,
    pub identifier: String,
    pub name: String,
    pub uuid: String,
    pub organization: String,
    pub install_date: String,
    pub removal_disallowed: bool,
    pub verified: String,
    pub payloads: Vec<Payload>,
    pub hash: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProfilesResult {
    pub profiles: Vec<Profile>,
    pub errors: Vec<String>,
    /// true = enthält Geräte-Profile (vom root-Helfer)
    pub full: bool,
    pub time: String,
}

fn pstr(d: &plist::Dictionary, k: &str) -> String {
    match d.get(k) {
        Some(plist::Value::String(s)) => s.clone(),
        Some(plist::Value::Date(dt)) => {
            let st: std::time::SystemTime = (*dt).into();
            chrono::DateTime::<chrono::Local>::from(st).format("%Y-%m-%d %H:%M:%S").to_string()
        }
        Some(plist::Value::Integer(i)) => i.to_string(),
        Some(plist::Value::Boolean(b)) => b.to_string(),
        _ => String::new(),
    }
}

fn collect(v: &plist::Value, scope: &str, out: &mut Vec<(String, plist::Dictionary)>) {
    match v {
        plist::Value::Dictionary(d) => {
            if d.contains_key("ProfileIdentifier") && (d.contains_key("ProfileItems") || d.contains_key("ProfileDisplayName")) {
                out.push((scope.to_string(), d.clone()));
                return;
            }
            for (k, x) in d.iter() {
                let s = if k == "_computerlevel" {
                    "Gerät".to_string()
                } else if matches!(x, plist::Value::Array(_)) && !k.starts_with("Profile") && scope == "?" {
                    format!("Benutzer {k}")
                } else {
                    scope.to_string()
                };
                collect(x, &s, out);
            }
        }
        plist::Value::Array(a) => a.iter().for_each(|x| collect(x, scope, out)),
        _ => {}
    }
}

/// Profile lesen. `root` = auch Geräteebene (nur als root möglich).
pub fn get_profiles(root: bool) -> ProfilesResult {
    let mut errors = vec![];
    let mut raw = vec![];
    let mut cmds: Vec<Vec<&str>> = vec![];
    if root {
        cmds.push(vec!["show", "-all", "-output", "stdout-xml"]);
        cmds.push(vec!["show", "-output", "stdout-xml"]);
    }
    cmds.push(vec!["show", "-type", "configuration", "-output", "stdout-xml"]);
    let mut full = false;
    for (i, args) in cmds.iter().enumerate() {
        let o = run("profiles", args);
        if !o.ok || !o.stdout.starts_with(b"<?xml") {
            errors.push(format!("profiles {}: {}", args.join(" "), if o.stderr.is_empty() { "keine XML-Ausgabe".into() } else { o.stderr }));
            continue;
        }
        match plist::Value::from_reader_xml(std::io::Cursor::new(&o.stdout)) {
            Ok(v) => {
                collect(&v, "?", &mut raw);
                if !raw.is_empty() {
                    full = root && i < 2;
                    break;
                }
            }
            Err(e) => errors.push(format!("profiles {}: {e}", args.join(" "))),
        }
    }
    let mut profiles = vec![];
    let mut seen = std::collections::HashSet::new();
    for (scope, d) in raw {
        let id = pstr(&d, "ProfileIdentifier");
        let scope = if scope == "?" { "Benutzer".to_string() } else { scope };
        if !seen.insert((scope.clone(), id.clone())) {
            continue;
        }
        let mut payloads = vec![];
        if let Some(plist::Value::Array(items)) = d.get("ProfileItems") {
            for it in items {
                if let plist::Value::Dictionary(p) = it {
                    payloads.push(Payload {
                        ptype: pstr(p, "PayloadType"),
                        identifier: pstr(p, "PayloadIdentifier"),
                        uuid: pstr(p, "PayloadUUID"),
                        name: pstr(p, "PayloadDisplayName"),
                        content: p.get("PayloadContent").map(|c| plist_to_json(c, "")).unwrap_or(J::Null),
                    });
                }
            }
        }
        // macOS liefert die Payloads in wechselnder Reihenfolge -> sortieren
        payloads.sort_by(|a, b| (&a.ptype, &a.identifier, &a.uuid).cmp(&(&b.ptype, &b.identifier, &b.uuid)));
        let hash = short_hash(&serde_json::to_value(&payloads).unwrap_or(J::Null));
        let rd = pstr(&d, "ProfileRemovalDisallowed").to_lowercase();
        profiles.push(Profile {
            scope,
            name: pstr(&d, "ProfileDisplayName"),
            uuid: pstr(&d, "ProfileUUID"),
            organization: pstr(&d, "ProfileOrganization"),
            install_date: pstr(&d, "ProfileInstallDate"),
            removal_disallowed: rd == "true" || rd == "1",
            verified: pstr(&d, "ProfileVerificationState"),
            identifier: id,
            payloads,
            hash,
        });
    }
    profiles.sort_by(|a, b| (a.scope.clone(), a.name.to_lowercase()).cmp(&(b.scope.clone(), b.name.to_lowercase())));
    if !profiles.is_empty() {
        errors.clear();
    }
    ProfilesResult { profiles, errors, full, time: util::now_iso() }
}

// ------------------------------------------------------------------ network extension configs

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Dns {
    pub servers: Vec<String>,
    pub match_domains: Vec<String>,
    pub match_no_search: bool,
    pub domain_name: String,
    pub search_domains: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct ProfRef {
    pub identifier: String,
    pub uuid: String,
    pub payload_uuid: String,
    pub ingested: String,
    pub system_version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NeConfig {
    pub uuid: String,
    pub name: String,
    pub kinds: Vec<String>,
    pub enabled: Option<bool>,
    pub server: String,
    pub username: String,
    pub password_saved: bool,
    pub dns: Option<Dns>,
    pub profile: Option<ProfRef>,
    pub raw: J,
}

#[derive(Clone, Debug, Default)]
pub struct NeResult {
    pub configs: Vec<NeConfig>,
    pub error: Option<String>,
    pub generation: Option<i64>,
    pub mtime: String,
}

fn ns_resolve(objs: &[plist::Value], v: &plist::Value, depth: usize) -> J {
    let v = match v {
        plist::Value::Uid(u) => match objs.get(u.get() as usize) {
            Some(x) => x,
            None => return J::Null,
        },
        x => x,
    };
    if depth > 30 {
        return J::String("…".into());
    }
    match v {
        plist::Value::String(s) if s == "$null" => J::Null,
        plist::Value::Dictionary(d) => {
            if let (Some(plist::Value::Array(ks)), Some(plist::Value::Array(vs))) = (d.get("NS.keys"), d.get("NS.objects")) {
                let mut m = Map::new();
                for (k, x) in ks.iter().zip(vs.iter()) {
                    let key = match ns_resolve(objs, k, depth + 1) {
                        J::String(s) => s,
                        other => other.to_string(),
                    };
                    m.insert(key, ns_resolve(objs, x, depth + 1));
                }
                return J::Object(m);
            }
            if let Some(plist::Value::Array(vs)) = d.get("NS.objects") {
                return J::Array(vs.iter().map(|x| ns_resolve(objs, x, depth + 1)).collect());
            }
            if let Some(plist::Value::String(s)) = d.get("NS.string") {
                return J::String(s.clone());
            }
            if let Some(plist::Value::Data(b)) = d.get("NS.uuidbytes") {
                let h: String = b.iter().map(|x| format!("{:02X}", x)).collect();
                if h.len() == 32 {
                    return J::String(format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32]));
                }
            }
            if let Some(t) = d.get("NS.time").and_then(|x| x.as_real()) {
                let secs = t as i64 + APPLE_EPOCH;
                return J::String(
                    chrono::DateTime::from_timestamp(secs, 0)
                        .map(|d| d.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M:%S").to_string())
                        .unwrap_or_default(),
                );
            }
            if let Some(plist::Value::Data(b)) = d.get("NS.data") {
                return J::String(format!("‹{} Bytes›", b.len()));
            }
            let mut m = Map::new();
            for (k, x) in d.iter() {
                if k != "$class" {
                    m.insert(k.clone(), ns_resolve(objs, x, depth + 1));
                }
            }
            J::Object(m)
        }
        plist::Value::Data(b) => J::String(format!("‹{} Bytes›", b.len())),
        other => plist_to_json(other, ""),
    }
}

fn prune(v: J) -> J {
    match v {
        J::Object(m) => {
            let mut o = Map::new();
            for (k, x) in m {
                let x = prune(x);
                let empty = matches!(&x, J::Null) || matches!(&x, J::Object(o) if o.is_empty()) || matches!(&x, J::Array(a) if a.is_empty());
                if !empty {
                    o.insert(k, x);
                }
            }
            J::Object(o)
        }
        J::Array(a) => J::Array(a.into_iter().map(prune).collect()),
        x => x,
    }
}

fn js(v: &J, k: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
}

pub fn get_ne_configs() -> NeResult {
    let mtime = std::fs::metadata(NE_PLIST)
        .and_then(|m| m.modified())
        .map(|t| chrono::DateTime::<chrono::Local>::from(t).format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_default();
    let v = match plist::Value::from_file(NE_PLIST) {
        Ok(v) => v,
        Err(e) => return NeResult { error: Some(e.to_string()), mtime, ..Default::default() },
    };
    let Some(root) = v.as_dictionary() else {
        return NeResult { error: Some("unerwartetes Format".into()), mtime, ..Default::default() };
    };
    let empty = vec![];
    let objs = root.get("$objects").and_then(|o| o.as_array()).unwrap_or(&empty);
    let Some(top) = root.get("$top").and_then(|t| t.as_dictionary()) else {
        return NeResult { error: Some("$top fehlt".into()), mtime, ..Default::default() };
    };
    let generation = top.get("Generation").and_then(|g| g.as_signed_integer());
    let mut configs = vec![];
    for (key, r) in top.iter() {
        if !util::uuid_re().is_match(key) || key.len() != 36 {
            continue;
        }
        let c = ns_resolve(objs, r, 0);
        if !c.is_object() {
            continue;
        }
        let kinds: Vec<String> = ["VPN", "AppVPN", "AlwaysOnVPN", "ContentFilter", "DNSProxy", "DNSSettings", "PathController", "AppPush", "Relay", "URLFilter", "Hotspot"]
            .iter()
            .filter(|k| c.get(**k).map(|x| !x.is_null()).unwrap_or(false))
            .map(|k| k.to_string())
            .collect();
        let vpn = c.get("VPN").filter(|x| !x.is_null()).or_else(|| c.get("AppVPN").filter(|x| !x.is_null())).cloned().unwrap_or(J::Null);
        let proto = vpn.get("Protocol").cloned().unwrap_or(J::Null);
        let dnsv = proto.get("DNSSettings").cloned().unwrap_or(J::Null);
        let dns = if dnsv.is_object() {
            Some(Dns {
                servers: json_list(dnsv.get("Servers").unwrap_or(&J::Null)),
                match_domains: json_list(dnsv.get("matchDomains").unwrap_or(&J::Null)),
                match_no_search: dnsv.get("matchDomainsNoSearch").and_then(|x| x.as_bool()).unwrap_or(false),
                domain_name: js(&dnsv, "domainName"),
                search_domains: json_list(dnsv.get("SearchDomains").unwrap_or(&J::Null)),
            })
        } else {
            None
        };
        let pw = proto.get("Password").cloned().unwrap_or(J::Null);
        let pinfo = c.get("ProfileInfo").cloned().unwrap_or(J::Null);
        let profile = if pinfo.is_object() {
            Some(ProfRef {
                identifier: js(&pinfo, "ProfileIdentifier"),
                uuid: js(&pinfo, "ProfileUUID"),
                payload_uuid: js(&pinfo, "PayloadUUID"),
                ingested: js(&pinfo, "profileIngestionDate"),
                system_version: js(&pinfo, "systemVersion"),
            })
        } else {
            None
        };
        configs.push(NeConfig {
            uuid: key.clone(),
            name: js(&c, "Name"),
            kinds,
            enabled: vpn.get("Enabled").and_then(|x| x.as_bool()),
            server: js(&proto, "ServerAddress"),
            username: js(&proto, "Username"),
            password_saved: pw.get("PersistentReference").map(|x| !x.is_null()).unwrap_or(false),
            dns,
            profile,
            raw: prune(c),
        });
    }
    configs.sort_by_key(|c| (if c.kinds.iter().any(|k| k.contains("VPN")) { 0 } else { 1 }, c.name.clone()));
    NeResult { configs, error: None, generation, mtime }
}

// ------------------------------------------------------------------ drift

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Level {
    Info,
    Warn,
    Error,
}

#[derive(Clone, Debug)]
pub struct Issue {
    pub level: Level,
    pub text: String,
}

fn norm(v: &[String]) -> Vec<String> {
    let mut x: Vec<String> = v.iter().map(|s| s.to_lowercase()).collect();
    x.sort();
    x
}

/// Vergleicht VPN-Verbindungen mit dem Profil, aus dem sie stammen.
pub fn check_drift(profiles: &ProfilesResult, ne: &[NeConfig]) -> Vec<(String, Vec<Issue>)> {
    let mut out = vec![];
    for c in ne {
        if !c.kinds.iter().any(|k| k == "VPN" || k == "AppVPN") {
            continue;
        }
        let mut issues = vec![];
        match &c.profile {
            None => issues.push(Issue { level: Level::Info, text: "Manuell angelegt (kein Profil)".into() }),
            Some(pr) if pr.identifier.is_empty() => issues.push(Issue { level: Level::Info, text: "Manuell angelegt (kein Profil)".into() }),
            Some(pr) => match profiles.profiles.iter().find(|p| p.identifier == pr.identifier) {
                None => issues.push(Issue {
                    level: Level::Error,
                    text: format!("Verwaist: Profil „{}“ ist nicht (mehr) installiert – Intune erreicht diese Verbindung nicht", pr.identifier),
                }),
                Some(p) => {
                    let payload = p
                        .payloads
                        .iter()
                        .filter(|pl| pl.ptype.starts_with("com.apple.vpn.managed"))
                        .max_by_key(|pl| pl.uuid == pr.payload_uuid);
                    if let Some(pl) = payload {
                        let pdns = pl.content.get("DNS").cloned().unwrap_or(J::Null);
                        let cd = c.dns.clone().unwrap_or_default();
                        let pairs: [(&str, Vec<String>, &str, Vec<String>, Level); 4] = [
                            ("SupplementalMatchDomains", json_list(pdns.get("SupplementalMatchDomains").unwrap_or(&J::Null)), "matchDomains", cd.match_domains.clone(), Level::Error),
                            ("DomainName", json_list(pdns.get("DomainName").unwrap_or(&J::Null)), "domainName", if cd.domain_name.is_empty() { vec![] } else { vec![cd.domain_name.clone()] }, Level::Warn),
                            ("ServerAddresses", json_list(pdns.get("ServerAddresses").unwrap_or(&J::Null)), "servers", cd.servers.clone(), Level::Warn),
                            ("SearchDomains", json_list(pdns.get("SearchDomains").unwrap_or(&J::Null)), "searchDomains", cd.search_domains.clone(), Level::Warn),
                        ];
                        for (pk, pv, ck, cv, lvl) in pairs {
                            if norm(&pv) != norm(&cv) {
                                issues.push(Issue {
                                    level: lvl,
                                    text: format!("DNS-Abweichung: Profil {pk} = {}, Verbindung {ck} = {}", util::fmt_list(&pv), util::fmt_list(&cv)),
                                });
                            }
                        }
                    }
                }
            },
        }
        if c.password_saved && c.profile.as_ref().map(|p| !p.identifier.is_empty()).unwrap_or(false) {
            issues.push(Issue {
                level: Level::Warn,
                text: "Passwort lokal gespeichert – Bearbeiten in den Systemeinstellungen kann DNS-Domänen aus der verwalteten Verbindung entfernen".into(),
            });
        }
        out.push((c.uuid.clone(), issues));
    }
    out
}

// ------------------------------------------------------------------ DNS

#[derive(Clone, Debug, Default)]
pub struct Resolver {
    pub n: u32,
    pub scoped: bool,
    pub domain: String,
    pub nameservers: Vec<String>,
    pub search: Vec<String>,
    pub interface: String,
}

pub fn get_dns() -> Vec<Resolver> {
    let o = run("scutil", &["--dns"]);
    let text = String::from_utf8_lossy(&o.stdout);
    let mut out: Vec<Resolver> = vec![];
    let mut scoped = false;
    for line in text.lines() {
        if line.starts_with("DNS configuration (for scoped") {
            scoped = true;
            continue;
        }
        if let Some(n) = line.strip_prefix("resolver #") {
            out.push(Resolver { n: n.trim().parse().unwrap_or(0), scoped, ..Default::default() });
            continue;
        }
        let Some(cur) = out.last_mut() else { continue };
        let Some((k, v)) = line.split_once(':') else { continue };
        let k = k.trim();
        let v = v.trim().to_string();
        if k.starts_with("nameserver") {
            cur.nameservers.push(v);
        } else if k.starts_with("search domain") {
            cur.search.push(v);
        } else if k == "domain" {
            cur.domain = v;
        } else if k == "if_index" {
            cur.interface = v;
        }
    }
    out
}

#[derive(Clone, Debug)]
pub struct HostResult {
    pub host: String,
    pub ok: bool,
    pub text: String,
    pub ms: u128,
}

pub fn resolve_host(host: &str) -> HostResult {
    use std::net::ToSocketAddrs;
    let (tx, rx) = std::sync::mpsc::channel();
    let h = host.to_string();
    let t = std::time::Instant::now();
    std::thread::spawn(move || {
        let r = (h.as_str(), 0).to_socket_addrs().map(|it| {
            let mut v: Vec<String> = it.map(|a| a.ip().to_string()).collect();
            v.sort();
            v.dedup();
            v
        });
        let _ = tx.send(r);
    });
    match rx.recv_timeout(Duration::from_secs(4)) {
        Ok(Ok(addrs)) => HostResult { host: host.into(), ok: true, text: addrs.join(", "), ms: t.elapsed().as_millis() },
        Ok(Err(e)) => HostResult { host: host.into(), ok: false, text: e.to_string(), ms: t.elapsed().as_millis() },
        Err(_) => HostResult { host: host.into(), ok: false, text: "Zeitüberschreitung".into(), ms: t.elapsed().as_millis() },
    }
}
