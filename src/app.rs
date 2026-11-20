//! Zustand, Hintergrund-Threads und Oberfläche.

use crate::data::{self, HostResult, Issue, Level, NeResult, ProfilesResult, Resolver};
use crate::{intune, mdm, util};
use eframe::egui::{self, Color32, RichText};
use egui_extras::{Column, TableBuilder};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value as J};
use std::collections::VecDeque;
use std::io::{BufRead, Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_EVENTS: usize = 20_000;

// ======================================================================= state

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Change {
    pub t: String,
    pub area: String,
    pub action: String,
    pub key: String,
    pub name: String,
    pub details: Vec<(String, String, String)>,
}

#[derive(Default, Clone)]
pub struct HelperState {
    pub running: bool,
    pub state: String,
    pub msg: String,
    pub started: String,
    pub starting: bool,
    pub error: String,
}

pub struct History {
    pub minutes: u32,
    pub total: usize,
    pub tracker: mdm::Tracker,
    pub events: Vec<mdm::Event>,
}

pub struct Shared {
    pub mdm_events: VecDeque<mdm::Event>,
    pub tracker: mdm::Tracker,
    pub intune_events: VecDeque<intune::Event>,
    pub policies: intune::Policies,
    pub intune_status: String,
    pub profiles: ProfilesResult,
    pub ne: NeResult,
    pub drift: Vec<(String, Vec<Issue>)>,
    pub dns: Vec<Resolver>,
    pub enrollment: Vec<(String, String)>,
    pub hosts: Vec<String>,
    pub host_results: Vec<HostResult>,
    pub changes: Vec<Change>,
    pub last_scan: String,
    pub helper: HelperState,
    pub history: Option<History>,
    pub history_busy: bool,
    pub history_msg: String,
}

impl Default for Shared {
    fn default() -> Self {
        Shared {
            mdm_events: VecDeque::new(),
            tracker: mdm::Tracker::new(5000),
            intune_events: VecDeque::new(),
            policies: Default::default(),
            intune_status: "startet …".into(),
            profiles: Default::default(),
            ne: Default::default(),
            drift: vec![],
            dns: vec![],
            enrollment: vec![],
            hosts: vec![],
            host_results: vec![],
            changes: vec![],
            last_scan: String::new(),
            helper: Default::default(),
            history: None,
            history_busy: false,
            history_msg: String::new(),
        }
    }
}

type S = Arc<Mutex<Shared>>;

// ======================================================================= persistence

fn load_changes() -> Vec<Change> {
    let p = util::app_dir().join("changes.jsonl");
    std::fs::read_to_string(p)
        .map(|s| s.lines().filter_map(|l| serde_json::from_str(l).ok()).collect())
        .unwrap_or_default()
}

fn append_change(c: &Change) {
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(util::app_dir().join("changes.jsonl")) {
        let _ = writeln!(f, "{}", serde_json::to_string(c).unwrap_or_default());
    }
}

fn load_hosts() -> Vec<String> {
    std::fs::read_to_string(util::app_dir().join("hosts.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_hosts(h: &[String]) {
    let _ = std::fs::write(util::app_dir().join("hosts.json"), serde_json::to_string_pretty(h).unwrap_or_default());
}

// ======================================================================= snapshot & diff

fn snapshot(p: &ProfilesResult, ne: &NeResult, enr: &[(String, String)]) -> J {
    let mut profs = Map::new();
    for x in &p.profiles {
        profs.insert(
            format!("{}|{}", x.scope, x.identifier),
            json!({"name": x.name, "installDate": x.install_date, "payloads":
                x.payloads.iter().map(|p| (format!("{} {}", p.ptype, p.identifier), json!({"name": p.name, "uuid": p.uuid, "content": p.content}))).collect::<Map<String, J>>()}),
        );
    }
    let mut nes = Map::new();
    for c in &ne.configs {
        nes.insert(
            c.uuid.clone(),
            json!({"name": c.name, "kinds": c.kinds, "enabled": c.enabled, "server": c.server,
                   "passwordSaved": c.password_saved, "dns": c.dns, "profile": c.profile}),
        );
    }
    let enr: Map<String, J> = enr.iter().map(|(k, v)| (k.clone(), J::String(v.clone()))).collect();
    json!({"full": p.full, "profiles": profs, "ne": nes, "enrollment": enr})
}

fn short(v: &J) -> String {
    let s = match v {
        J::Null => "–".to_string(),
        J::String(s) => s.clone(),
        other => other.to_string(),
    };
    if s.chars().count() > 400 { format!("{}…", s.chars().take(400).collect::<String>()) } else { s }
}

fn diff(a: &J, b: &J, path: &str, out: &mut Vec<(String, String, String)>) {
    match (a, b) {
        (J::Object(x), J::Object(y)) => {
            let mut keys: Vec<&String> = x.keys().chain(y.keys()).collect();
            keys.sort();
            keys.dedup();
            for k in keys {
                let p = if path.is_empty() { k.clone() } else { format!("{path}.{k}") };
                diff(x.get(k).unwrap_or(&J::Null), y.get(k).unwrap_or(&J::Null), &p, out);
            }
        }
        _ if a != b => out.push((path.to_string(), short(a), short(b))),
        _ => {}
    }
}

fn compare(old: &J, new: &J) -> Vec<Change> {
    let t = util::now_iso();
    let mut out = vec![];
    let same_view = old.get("full") == new.get("full");
    for (area, label) in [("profiles", "Profil"), ("ne", "Netzwerk-Konfiguration")] {
        let empty = Map::new();
        let o = old.get(area).and_then(|x| x.as_object()).unwrap_or(&empty);
        let n = new.get(area).and_then(|x| x.as_object()).unwrap_or(&empty);
        let name = |v: &J| v.get("name").and_then(|x| x.as_str()).unwrap_or("").to_string();
        // Wenn sich nur die Sicht (mit/ohne root) geändert hat, keine Profile als neu/entfernt melden.
        let report_add_remove = area != "profiles" || same_view;
        if report_add_remove {
            for (k, v) in n.iter().filter(|(k, _)| !o.contains_key(*k)) {
                out.push(Change { t: t.clone(), area: label.into(), action: "hinzugefügt".into(), key: k.clone(), name: name(v), details: vec![] });
            }
            for (k, v) in o.iter().filter(|(k, _)| !n.contains_key(*k)) {
                out.push(Change { t: t.clone(), area: label.into(), action: "entfernt".into(), key: k.clone(), name: name(v), details: vec![] });
            }
        }
        for (k, v) in n.iter() {
            if let Some(ov) = o.get(k) {
                if ov != v {
                    let mut d = vec![];
                    diff(ov, v, "", &mut d);
                    d.truncate(60);
                    out.push(Change { t: t.clone(), area: label.into(), action: "geändert".into(), key: k.clone(), name: name(v), details: d });
                }
            }
        }
    }
    let (eo, en) = (old.get("enrollment").cloned().unwrap_or(J::Null), new.get("enrollment").cloned().unwrap_or(J::Null));
    if eo != en && !eo.is_null() {
        let mut d = vec![];
        diff(&eo, &en, "", &mut d);
        out.push(Change { t, area: "Enrollment".into(), action: "geändert".into(), key: "enrollment".into(), name: "MDM-Enrollment".into(), details: d });
    }
    out
}

// ======================================================================= workers

fn helper_alive(pid: i32) -> bool {
    if pid <= 1 {
        return false;
    }
    let r = unsafe { libc::kill(pid, 0) };
    r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn read_helper_state() -> HelperState {
    let p = util::run_dir().join("helper.json");
    let Ok(s) = std::fs::read_to_string(p) else { return HelperState { state: "nicht gestartet".into(), ..Default::default() } };
    let v: J = serde_json::from_str(&s).unwrap_or(J::Null);
    let pid = v.get("pid").and_then(|x| x.as_i64()).unwrap_or(0) as i32;
    let state = v.get("state").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let running = state == "running" && helper_alive(pid);
    HelperState {
        running,
        state: if running { "aktiv".into() } else if state == "running" { "beendet".into() } else { state },
        msg: v.get("msg").and_then(|x| x.as_str()).unwrap_or("").into(),
        started: v.get("started").and_then(|x| x.as_str()).unwrap_or("").into(),
        ..Default::default()
    }
}

fn scanner(s: S, ctx: egui::Context, rescan: Arc<AtomicBool>) {
    let snap_path = util::app_dir().join("snapshot.json");
    let mut last: Option<J> = std::fs::read_to_string(&snap_path).ok().and_then(|x| serde_json::from_str(&x).ok());
    loop {
        let hs = read_helper_state();
        let mut profiles = None;
        if hs.running {
            let p = util::run_dir().join("profiles.json");
            let fresh = std::fs::metadata(&p).and_then(|m| m.modified()).map(|t| t.elapsed().unwrap_or_default() < Duration::from_secs(120)).unwrap_or(false);
            if fresh {
                profiles = std::fs::read_to_string(&p).ok().and_then(|x| serde_json::from_str::<ProfilesResult>(&x).ok());
            }
        }
        let profiles = match profiles {
            Some(mut full) => {
                // profiles -all (root) liefert nur Geräteprofile -> Benutzerprofile ergänzen
                let user = data::get_profiles(false);
                for p in user.profiles {
                    if !full.profiles.iter().any(|x| x.identifier == p.identifier) {
                        full.profiles.push(p);
                    }
                }
                full.profiles.sort_by(|a, b| (a.scope.clone(), a.name.to_lowercase()).cmp(&(b.scope.clone(), b.name.to_lowercase())));
                full
            }
            None => data::get_profiles(false),
        };
        let ne = data::get_ne_configs();
        let drift = data::check_drift(&profiles, &ne.configs);
        let dns = data::get_dns();
        let enr = data::enrollment();
        let hosts = s.lock().unwrap().hosts.clone();
        let host_results: Vec<HostResult> = hosts.iter().map(|h| data::resolve_host(h)).collect();
        let snap = snapshot(&profiles, &ne, &enr);
        let changes = last.as_ref().map(|o| compare(o, &snap)).unwrap_or_default();
        for c in &changes {
            append_change(c);
        }
        let _ = std::fs::write(&snap_path, snap.to_string());
        last = Some(snap);
        {
            let mut g = s.lock().unwrap();
            let starting = g.helper.starting;
            let err = g.helper.error.clone();
            g.helper = hs;
            if starting && !g.helper.running {
                g.helper.starting = true;
            }
            g.helper.error = err;
            g.profiles = profiles;
            g.ne = ne;
            g.drift = drift;
            g.dns = dns;
            g.enrollment = enr;
            g.host_results = host_results;
            g.changes.extend(changes);
            g.last_scan = util::now_iso();
        }
        ctx.request_repaint();
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(30) {
            if rescan.swap(false, Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(Duration::from_millis(300));
            // Helferstatus öfter prüfen
            if start.elapsed().as_millis() % 3000 < 300 {
                let hs = read_helper_state();
                let mut g = s.lock().unwrap();
                if hs.running != g.helper.running {
                    g.helper.running = hs.running;
                    g.helper.state = hs.state;
                    g.helper.starting = false;
                    drop(g);
                    ctx.request_repaint();
                    break;
                }
            }
        }
    }
}

fn intune_worker(s: S, ctx: egui::Context) {
    let mut t = intune::Tailer::default();
    loop {
        match t.poll() {
            Ok(evs) => {
                let mut g = s.lock().unwrap();
                g.intune_status = "läuft".into();
                let n = evs.len();
                for e in evs {
                    g.policies.feed(&e);
                    g.intune_events.push_back(e);
                }
                while g.intune_events.len() > MAX_EVENTS {
                    g.intune_events.pop_front();
                }
                drop(g);
                if n > 0 {
                    ctx.request_repaint();
                }
            }
            Err(e) => s.lock().unwrap().intune_status = e,
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn mdm_worker(s: S, ctx: egui::Context) {
    let path = util::run_dir().join("mdm.ndjson");
    let mut pos: u64 = 0;
    let mut ino: u64 = 0;
    loop {
        if let Ok(mut f) = std::fs::File::open(&path) {
            use std::os::unix::fs::MetadataExt;
            let m = f.metadata().ok();
            let (size, inode) = m.map(|m| (m.len(), m.ino())).unwrap_or((0, 0));
            if inode != ino || size < pos {
                ino = inode;
                pos = 0;
            }
            if size > pos && f.seek(SeekFrom::Start(pos)).is_ok() {
                let mut buf = Vec::new();
                let _ = f.read_to_end(&mut buf);
                let end = buf.iter().rposition(|b| *b == b'\n').map(|i| i + 1).unwrap_or(0);
                pos += end as u64;
                let mut g = s.lock().unwrap();
                let mut n = 0;
                for line in buf[..end].lines().map_while(Result::ok) {
                    if let Ok(v) = serde_json::from_str::<J>(&line) {
                        if let Some(e) = mdm::parse(&v) {
                            g.tracker.feed(&e);
                            g.mdm_events.push_back(e);
                            n += 1;
                        }
                    }
                }
                while g.mdm_events.len() > MAX_EVENTS {
                    g.mdm_events.pop_front();
                }
                drop(g);
                if n > 0 {
                    ctx.request_repaint();
                }
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn shq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn start_helper(s: S, ctx: egui::Context) {
    std::thread::spawn(move || {
        {
            let mut g = s.lock().unwrap();
            g.helper.starting = true;
            g.helper.error.clear();
        }
        let res = (|| -> Result<(), String> {
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            let dir = util::run_dir();
            let _ = std::fs::remove_file(dir.join("stop"));
            let uid = unsafe { libc::getuid() };
            let cmd = format!(
                "{} --helper --dir {} --parent {} --uid {} >/dev/null 2>&1 &",
                shq(&exe.to_string_lossy()),
                shq(&dir.to_string_lossy()),
                std::process::id(),
                uid
            );
            let script = format!(
                "do shell script \"{}\" with administrator privileges with prompt \"MDM Watch möchte das MDM-Log und die Geräte-Profile lesen.\"",
                cmd.replace('\\', "\\\\").replace('"', "\\\"")
            );
            let o = std::process::Command::new("/usr/bin/osascript").arg("-e").arg(script).output().map_err(|e| e.to_string())?;
            if !o.status.success() {
                let e = String::from_utf8_lossy(&o.stderr).to_string();
                return Err(if e.contains("-128") { "abgebrochen".into() } else { e.trim().to_string() });
            }
            Ok(())
        })();
        let mut g = s.lock().unwrap();
        if let Err(e) = res {
            g.helper.starting = false;
            g.helper.error = e;
        }
        drop(g);
        ctx.request_repaint();
    });
}

fn stop_helper() {
    let _ = std::fs::write(util::run_dir().join("stop"), b"1");
}

fn request_history(s: S, ctx: egui::Context, minutes: u32) {
    std::thread::spawn(move || {
        let dir = util::run_dir();
        {
            let mut g = s.lock().unwrap();
            if g.history_busy {
                return;
            }
            g.history_busy = true;
            g.history_msg = format!("lade {} … (log show läuft, kann dauern)", fmt_minutes(minutes));
        }
        ctx.request_repaint();
        let _ = std::fs::remove_file(dir.join("history.done"));
        let _ = std::fs::write(dir.join("history.req"), minutes.to_string());
        let t0 = Instant::now();
        let mut done = None;
        while t0.elapsed() < Duration::from_secs(20 * 60) {
            if let Ok(s) = std::fs::read_to_string(dir.join("history.done")) {
                done = serde_json::from_str::<J>(&s).ok();
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        let mut g = s.lock().unwrap();
        g.history_busy = false;
        let Some(info) = done else {
            g.history_msg = "keine Antwort vom Helfer (läuft er noch?)".into();
            return;
        };
        if let Some(e) = info.get("error") {
            g.history_msg = format!("Fehler: {e}");
            return;
        }
        let mut tracker = mdm::Tracker::new(100_000);
        let mut events = vec![];
        if let Ok(text) = std::fs::read_to_string(dir.join("history.ndjson")) {
            for line in text.lines() {
                if let Ok(v) = serde_json::from_str::<J>(line) {
                    if let Some(e) = mdm::parse(&v) {
                        tracker.feed(&e);
                        events.push(e);
                    }
                }
            }
        }
        let total = info.get("total").and_then(|x| x.as_u64()).unwrap_or(0) as usize;
        g.history_msg = format!("{} Log-Einträge, {} Befehle, {} Check-ins · {} s", total, tracker.cmds.len(), tracker.checkins.len(), t0.elapsed().as_secs());
        g.history = Some(History { minutes, total, tracker, events });
        drop(g);
        ctx.request_repaint();
    });
}

fn fmt_minutes(m: u32) -> String {
    if m % 1440 == 0 { format!("{} Tag(e)", m / 1440) } else if m % 60 == 0 { format!("{} Stunde(n)", m / 60) } else { format!("{m} Minuten") }
}

// ======================================================================= UI

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Overview,
    Commands,
    MdmLog,
    Intune,
    Profiles,
    Vpn,
    Changes,
    History,
}

pub struct App {
    s: S,
    rescan: Arc<AtomicBool>,
    tab: Tab,
    cmd_filter: String,
    cmd_hide_routine: bool,
    cmd_only_err: bool,
    log_filter: String,
    log_important: bool,
    log_pause: bool,
    log_frozen: Option<Vec<mdm::Event>>,
    int_filter: String,
    int_level: u8,
    int_hide_noise: bool,
    prof_filter: String,
    hosts_input: String,
    hist_minutes: u32,
    shots: Option<Shots>,
}

// ---------------------------------------------------------------- Farben & Stil

#[derive(Clone, Copy)]
struct Pal {
    err: Color32,
    warn: Color32,
    ok: Color32,
    info: Color32,
    accent: Color32,
    muted: Color32,
    card: Color32,
    line: Color32,
    text: Color32,
}

fn pal(ui: &egui::Ui) -> Pal {
    if ui.visuals().dark_mode {
        Pal {
            err: Color32::from_rgb(248, 113, 113),
            warn: Color32::from_rgb(251, 191, 36),
            ok: Color32::from_rgb(74, 222, 128),
            info: Color32::from_rgb(148, 163, 184),
            accent: Color32::from_rgb(96, 165, 250),
            muted: Color32::from_rgb(140, 150, 165),
            card: Color32::from_rgb(30, 34, 40),
            line: Color32::from_rgb(52, 58, 68),
            text: Color32::from_rgb(228, 232, 238),
        }
    } else {
        Pal {
            err: Color32::from_rgb(200, 40, 40),
            warn: Color32::from_rgb(180, 100, 0),
            ok: Color32::from_rgb(22, 128, 61),
            info: Color32::from_rgb(90, 104, 122),
            accent: Color32::from_rgb(37, 99, 235),
            muted: Color32::from_rgb(110, 118, 130),
            card: Color32::WHITE,
            line: Color32::from_rgb(226, 230, 235),
            text: Color32::from_rgb(28, 32, 38),
        }
    }
}

fn setup_style(ctx: &egui::Context) {
    // macOS-Systemschrift, falls vorhanden
    let mut fonts = egui::FontDefinitions::default();
    for (name, path, fam) in [
        ("sf", "/System/Library/Fonts/SFNS.ttf", egui::FontFamily::Proportional),
        ("sfmono", "/System/Library/Fonts/SFNSMono.ttf", egui::FontFamily::Monospace),
    ] {
        if let Ok(b) = std::fs::read(path) {
            fonts.font_data.insert(name.into(), Arc::new(egui::FontData::from_owned(b)));
            if let Some(v) = fonts.families.get_mut(&fam) {
                v.insert(0, name.into());
            }
        }
    }
    ctx.set_fonts(fonts);
    ctx.all_styles_mut(|st| {
        use egui::{FontFamily as F, FontId, TextStyle as T};
        st.text_styles = [
            (T::Heading, FontId::new(18.0, F::Proportional)),
            (T::Body, FontId::new(13.0, F::Proportional)),
            (T::Button, FontId::new(13.0, F::Proportional)),
            (T::Small, FontId::new(11.0, F::Proportional)),
            (T::Monospace, FontId::new(11.5, F::Monospace)),
        ]
        .into();
        st.spacing.item_spacing = egui::vec2(8.0, 6.0);
        st.spacing.button_padding = egui::vec2(10.0, 4.0);
        st.spacing.interact_size.y = 24.0;
        st.visuals.widgets.inactive.corner_radius = 6.0.into();
        st.visuals.widgets.hovered.corner_radius = 6.0.into();
        st.visuals.widgets.active.corner_radius = 6.0.into();
        st.visuals.widgets.noninteractive.corner_radius = 6.0.into();
        st.visuals.indent_has_left_vline = false;
    });
    ctx.style_mut_of(egui::Theme::Light, |st| {
        st.visuals.panel_fill = Color32::from_rgb(245, 246, 248);
        st.visuals.window_fill = Color32::WHITE;
        st.visuals.extreme_bg_color = Color32::WHITE;
        st.visuals.faint_bg_color = Color32::from_rgb(247, 248, 250);
        st.visuals.selection.bg_fill = Color32::from_rgb(219, 232, 254);
        st.visuals.selection.stroke.color = Color32::from_rgb(29, 78, 216);
        st.visuals.widgets.inactive.weak_bg_fill = Color32::from_rgb(236, 238, 242);
        st.visuals.widgets.noninteractive.bg_stroke.color = Color32::from_rgb(226, 230, 235);
    });
    ctx.style_mut_of(egui::Theme::Dark, |st| {
        st.visuals.panel_fill = Color32::from_rgb(20, 23, 28);
        st.visuals.extreme_bg_color = Color32::from_rgb(26, 30, 36);
        st.visuals.faint_bg_color = Color32::from_rgb(28, 32, 38);
        st.visuals.selection.bg_fill = Color32::from_rgb(30, 58, 110);
        st.visuals.widgets.noninteractive.bg_stroke.color = Color32::from_rgb(52, 58, 68);
    });
}

// ---------------------------------------------------------------- Bausteine

fn pill(ui: &mut egui::Ui, text: &str, color: Color32) -> egui::Response {
    egui::Frame::new()
        .fill(color.gamma_multiply(0.14))
        .corner_radius(9.0)
        .inner_margin(egui::Margin::symmetric(7, 1))
        .show(ui, |ui| {
            ui.label(RichText::new(text).color(color).size(11.0).strong());
        })
        .response
}

fn level_pill(ui: &mut egui::Ui, l: Level) {
    let p = pal(ui);
    match l {
        Level::Error => pill(ui, "Fehler", p.err),
        Level::Warn => pill(ui, "Warnung", p.warn),
        Level::Info => pill(ui, "Info", p.info),
    };
}

fn status_pill(ui: &mut egui::Ui, st: &str) {
    let p = pal(ui);
    let c = match st {
        "Acknowledged" => p.ok,
        "Error" => p.err,
        "NotNow" => p.warn,
        _ => p.info,
    };
    pill(ui, st, c);
}

/// Karte mit optionalem Titel und Inhalt rechts im Titel.
fn card<R>(ui: &mut egui::Ui, title: &str, right: impl FnOnce(&mut egui::Ui), body: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let p = pal(ui);
    egui::Frame::new()
        .fill(p.card)
        .stroke(egui::Stroke::new(1.0, p.line))
        .corner_radius(8.0)
        .inner_margin(egui::Margin::same(12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            if !title.is_empty() {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(title).strong().size(13.5));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), right);
                });
                ui.add_space(4.0);
            }
            body(ui)
        })
        .inner
}

fn muted(ui: &mut egui::Ui, t: impl Into<String>) {
    let c = pal(ui).muted;
    ui.label(RichText::new(t.into()).color(c));
}

/// "2026-11-20 12:34:09.488" -> "11-20 12:34:09"
fn short_t(t: &str) -> String {
    if t.len() >= 19 { t[5..19].to_string() } else { t.to_string() }
}

fn cell(ui: &mut egui::Ui, text: RichText, hover: &str) {
    let r = ui.add(egui::Label::new(text).truncate());
    if !hover.is_empty() {
        r.on_hover_text(hover);
    }
}

/// Bereich mit fester Höhe (damit Tabellen nicht in Nachbarbereiche zeichnen).
fn fixed_height<R>(ui: &mut egui::Ui, h: f32, f: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let w = ui.available_width();
    ui.allocate_ui(egui::vec2(w, h), |ui| {
        ui.set_min_size(egui::vec2(w, h));
        ui.set_max_height(h);
        ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Truncate);
        f(ui)
    })
    .inner
}

fn kv_grid(ui: &mut egui::Ui, id: &str, rows: &[(&str, String)]) {
    let m = pal(ui).muted;
    egui::Grid::new(id).num_columns(2).spacing([18.0, 5.0]).show(ui, |ui| {
        for (k, v) in rows {
            ui.label(RichText::new(*k).color(m));
            ui.add(egui::Label::new(RichText::new(v)).selectable(true).wrap());
            ui.end_row();
        }
    });
}

/// Virtualisierte Log-Ansicht. line(i) -> (Zeit, Quelle, Text, Farbe)
fn log_view(ui: &mut egui::Ui, id: &str, n: usize, line: impl Fn(usize) -> (String, String, String, Option<Color32>)) {
    let p = pal(ui);
    let row_h = ui.text_style_height(&egui::TextStyle::Monospace) + 4.0;
    egui::Frame::new()
        .fill(p.card)
        .stroke(egui::Stroke::new(1.0, p.line))
        .corner_radius(8.0)
        .inner_margin(egui::Margin::symmetric(10, 6))
        .show(ui, |ui| {
            if n == 0 {
                muted(ui, "Keine Einträge.");
            }
            egui::ScrollArea::vertical().id_salt(id).stick_to_bottom(true).auto_shrink(false).show_rows(ui, row_h, n, |ui, range| {
                ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Truncate);
                for i in range {
                    let (t, src, text, col) = line(i);
                    let mono = egui::TextStyle::Monospace.resolve(ui.style());
                    let mut job = egui::text::LayoutJob::default();
                    job.append(&format!("{t}  "), 0.0, egui::TextFormat { font_id: mono.clone(), color: p.muted, ..Default::default() });
                    if !src.is_empty() {
                        job.append(&format!("{src}  "), 0.0, egui::TextFormat { font_id: mono.clone(), color: p.accent.gamma_multiply(0.85), ..Default::default() });
                    }
                    job.append(&text, 0.0, egui::TextFormat { font_id: mono, color: col.unwrap_or(p.text), ..Default::default() });
                    job.wrap.max_rows = 1;
                    job.wrap.break_anywhere = true;
                    job.wrap.max_width = ui.available_width();
                    ui.add(egui::Label::new(job).truncate()).on_hover_text(format!("{t}  {src}\n{text}"));
                }
            });
        });
}

// ---------------------------------------------------------------- App

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        setup_style(&cc.egui_ctx);
        let s: S = Arc::new(Mutex::new(Shared::default()));
        {
            let mut g = s.lock().unwrap();
            g.changes = load_changes();
            g.hosts = load_hosts();
            g.helper = read_helper_state();
        }
        let rescan = Arc::new(AtomicBool::new(false));
        let ctx = cc.egui_ctx.clone();
        {
            let (s, c, r) = (s.clone(), ctx.clone(), rescan.clone());
            std::thread::spawn(move || scanner(s, c, r));
        }
        {
            let (s, c) = (s.clone(), ctx.clone());
            std::thread::spawn(move || intune_worker(s, c));
        }
        {
            let (s, c) = (s.clone(), ctx.clone());
            std::thread::spawn(move || mdm_worker(s, c));
        }
        let hosts_input = s.lock().unwrap().hosts.join(", ");
        App {
            s,
            rescan,
            tab: Tab::Overview,
            cmd_filter: String::new(),
            cmd_hide_routine: true,
            cmd_only_err: false,
            log_filter: String::new(),
            log_important: true,
            log_pause: false,
            log_frozen: None,
            int_filter: String::new(),
            int_level: 0,
            int_hide_noise: true,
            prof_filter: String::new(),
            hosts_input,
            hist_minutes: 1440,
            shots: std::env::var("MDMWATCH_SHOTS").ok().map(|d| {
                let dir = std::path::PathBuf::from(d);
                let _ = std::fs::create_dir_all(&dir);
                Shots { dir, idx: 0, frames: 0, waiting: Arc::new(AtomicBool::new(false)), started: Instant::now() }
            }),
        }
    }

    // ------------------------------------------------------------ Kopfzeile
    fn header(&mut self, ui: &mut egui::Ui, g: &Shared) {
        let p = pal(ui);
        ui.horizontal(|ui| {
            ui.label(RichText::new("MDM Watch").size(19.0).strong());
            ui.add_space(6.0);
            muted(ui, format!("Stand {}", if g.last_scan.is_empty() { "…".into() } else { short_t(&g.last_scan) }));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Neu scannen").clicked() {
                    self.rescan.store(true, Ordering::SeqCst);
                    let _ = std::fs::write(util::run_dir().join("rescan"), b"1");
                }
                ui.add_space(4.0);
                if g.helper.running {
                    if ui.button("Admin beenden").on_hover_text("Beendet den root-Helfer").clicked() {
                        stop_helper();
                        self.rescan.store(true, Ordering::SeqCst);
                    }
                    pill(ui, "Admin-Zugriff aktiv", p.ok).on_hover_text(format!("seit {} · {}", g.helper.started, g.helper.msg));
                } else if g.helper.starting {
                    ui.spinner();
                    pill(ui, "Admin-Zugriff wird gestartet", p.warn);
                } else {
                    if ui
                        .add(egui::Button::new(RichText::new("Admin-Zugriff aktivieren").color(Color32::WHITE)).fill(p.accent))
                        .on_hover_text("Fragt nach einem Admin-Passwort und startet einen Helfer, der das MDM-Log und die Geräte-Profile liest.")
                        .clicked()
                    {
                        start_helper(self.s.clone(), ui.ctx().clone());
                    }
                    if !g.helper.error.is_empty() {
                        ui.label(RichText::new(&g.helper.error).color(p.err).small());
                    }
                }
                ui.add_space(4.0);
                let ic = if g.intune_status == "läuft" { p.ok } else { p.warn };
                pill(ui, &format!("Intune-Log {}", g.intune_status), ic);
            });
        });
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 4.0;
            let failed = g.tracker.cmds.values().filter(|c| c.failed()).count();
            let pol_err = g.policies.p.values().filter(|p| p.errors > 0).count();
            let warn_n = Self::warnings(g).iter().filter(|w| w.0 != Level::Info).count();
            let tabs: [(Tab, &str, String, bool); 8] = [
                (Tab::Overview, "Übersicht", if warn_n > 0 { warn_n.to_string() } else { String::new() }, warn_n > 0),
                (Tab::Commands, "MDM-Befehle", if failed > 0 { format!("{failed} Fehler") } else { g.tracker.cmds.len().to_string() }, failed > 0),
                (Tab::MdmLog, "MDM-Log", String::new(), false),
                (Tab::Intune, "Intune-Agent", if pol_err > 0 { format!("{pol_err} Fehler") } else { g.policies.p.len().to_string() }, pol_err > 0),
                (Tab::Profiles, "Profile", g.profiles.profiles.len().to_string(), false),
                (Tab::Vpn, "VPN & DNS", String::new(), g.drift.iter().any(|d| d.1.iter().any(|i| i.level == Level::Error))),
                (Tab::Changes, "Änderungen", g.changes.len().to_string(), false),
                (Tab::History, "Verlauf", String::new(), false),
            ];
            for (t, label, count, alert) in tabs {
                let sel = self.tab == t;
                let mut job = egui::text::LayoutJob::default();
                let body = egui::TextStyle::Button.resolve(ui.style());
                job.append(label, 0.0, egui::TextFormat { font_id: body.clone(), color: if sel { p.accent } else { p.text }, ..Default::default() });
                if !count.is_empty() {
                    job.append(&count, 6.0, egui::TextFormat { font_id: egui::FontId::proportional(11.0), color: if alert { p.err } else { p.muted }, ..Default::default() });
                } else if alert {
                    job.append("●", 6.0, egui::TextFormat { font_id: egui::FontId::proportional(9.0), color: p.err, ..Default::default() });
                }
                if ui.add(egui::Button::selectable(sel, job)).clicked() {
                    self.tab = t;
                }
            }
        });
    }

    // ------------------------------------------------------------ Übersicht
    fn warnings(g: &Shared) -> Vec<(Level, &'static str, String)> {
        let mut w = vec![];
        if !g.helper.running {
            w.push((Level::Info, "Rechte", "Ohne Admin-Zugriff: kein MDM-Log und keine Geräte-Profile. Oben „Admin-Zugriff aktivieren“.".to_string()));
        }
        for (uuid, issues) in &g.drift {
            let name = g.ne.configs.iter().find(|c| &c.uuid == uuid).map(|c| c.name.clone()).unwrap_or_default();
            for i in issues.iter().filter(|i| i.level != Level::Info) {
                w.push((i.level, "VPN", format!("{name}: {}", i.text)));
            }
        }
        let sum = mdm::summarize(&g.tracker);
        for (cmd, err, n) in sum.repeated_errors.iter().filter(|x| x.2 >= 2) {
            w.push((Level::Warn, "MDM", format!("{cmd} schlägt wiederholt fehl ({n}×): {err}")));
        }
        let mut pols: Vec<_> = g.policies.p.values().filter(|p| p.errors > 0).collect();
        pols.sort_by(|a, b| b.errors.cmp(&a.errors));
        for p in pols {
            w.push((
                if p.errors >= 3 { Level::Error } else { Level::Warn },
                "Intune",
                format!("{} ({}): {} Fehler, zuletzt {}", if p.name.is_empty() { &p.id } else { &p.name }, p.domain, p.errors, p.last_error),
            ));
        }
        for e in &g.profiles.errors {
            w.push((Level::Info, "Profile", e.clone()));
        }
        w.sort_by(|a, b| b.0.cmp(&a.0));
        w
    }

    fn overview(&mut self, ui: &mut egui::Ui, g: &Shared) {
        let p = pal(ui);
        let tiles: Vec<(String, &str, Option<Color32>)> = vec![
            (g.profiles.profiles.len().to_string(), if g.profiles.full { "Profile gesamt" } else { "Profile (nur Benutzer)" }, None),
            (g.profiles.profiles.iter().filter(|p| p.scope == "Gerät").count().to_string(), "Geräte-Profile", None),
            (g.ne.configs.iter().filter(|c| c.kinds.iter().any(|k| k == "VPN")).count().to_string(), "VPN-Verbindungen", None),
            (g.tracker.cmds.len().to_string(), "MDM-Befehle seit Start", None),
            (g.tracker.cmds.values().filter(|c| c.failed()).count().to_string(), "davon fehlgeschlagen", Some(p.err)),
            (g.policies.p.values().filter(|x| x.errors > 0).count().to_string(), "Intune-Richtlinien mit Fehlern", Some(p.err)),
            (g.tracker.checkins.last().map(|t| t.chars().skip(11).take(8).collect()).unwrap_or("–".into()), "letzter Check-in", None),
        ];
        let avail = ui.available_width();
        let gap = 10.0;
        let cols = ((avail + gap) / 190.0).floor().clamp(1.0, tiles.len() as f32) as usize;
        let tw = ((avail - gap * (cols as f32 - 1.0)) / cols as f32).floor();
        for chunk in tiles.chunks(cols) {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = gap;
                for (n, l, c) in chunk {
                    ui.allocate_ui_with_layout(egui::vec2(tw, 74.0), egui::Layout::top_down(egui::Align::Min), |ui| {
                        egui::Frame::new()
                            .fill(p.card)
                            .stroke(egui::Stroke::new(1.0, p.line))
                            .corner_radius(8.0)
                            .inner_margin(egui::Margin::symmetric(14, 10))
                            .show(ui, |ui| {
                                ui.set_width(tw - 30.0);
                                let col = if n != "0" { c.unwrap_or(p.text) } else { p.text };
                                ui.label(RichText::new(n.as_str()).size(24.0).strong().color(col));
                                ui.add(egui::Label::new(RichText::new(*l).color(p.muted).size(11.5)).truncate());
                            });
                    });
                }
            });
            ui.add_space(gap - 6.0);
        }
        ui.add_space(12.0);
        let w = Self::warnings(g);
        card(ui, "Auffälligkeiten", |ui| muted(ui, format!("{}", w.len())), |ui| {
            if w.is_empty() {
                muted(ui, "Keine Auffälligkeiten.");
            }
            for (i, (l, area, text)) in w.iter().enumerate() {
                if i > 0 {
                    ui.separator();
                }
                ui.horizontal(|ui| {
                    ui.allocate_ui_with_layout(egui::vec2(140.0, 20.0), egui::Layout::left_to_right(egui::Align::Center), |ui| {
                        level_pill(ui, *l);
                        pill(ui, area, p.info);
                    });
                    ui.add(egui::Label::new(text).wrap());
                });
            }
        });
        ui.add_space(12.0);
        card(ui, "Enrollment", |_| {}, |ui| {
            let rows: Vec<(&str, String)> = g.enrollment.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
            kv_grid(ui, "enr", &rows);
        });
    }

    // ------------------------------------------------------------ Befehle
    fn commands_table(ui: &mut egui::Ui, id: &str, rows: &[&mdm::Command], height: f32) {
        let p = pal(ui);
        fixed_height(ui, height, |ui| {
            TableBuilder::new(ui)
                .id_salt(id)
                .striped(true)
                .resizable(false)
                .auto_shrink(false)
                .column(Column::exact(110.0))
                .column(Column::exact(200.0))
                .column(Column::exact(100.0))
                .column(Column::exact(130.0))
                .column(Column::remainder().clip(true))
                .header(24.0, |mut h| {
                    for t in ["Zeit", "Befehl", "Ebene", "Antwort", "Fehler / Details"] {
                        h.col(|ui| {
                            ui.label(RichText::new(t).color(p.muted).size(11.5).strong());
                        });
                    }
                })
                .body(|body| {
                    body.rows(26.0, rows.len(), |mut row| {
                        let c = rows[row.index()];
                        row.col(|ui| cell(ui, RichText::new(short_t(&c.t)).color(p.muted), &c.t));
                        row.col(|ui| cell(ui, RichText::new(if c.command.is_empty() { "?" } else { &c.command }).strong(), &format!("UUID {}", c.uuid)));
                        row.col(|ui| cell(ui, RichText::new(if c.scope.is_empty() { &c.target } else { &c.scope }), ""));
                        row.col(|ui| {
                            if !c.status.is_empty() {
                                status_pill(ui, &c.status);
                            }
                            if let Some(h) = c.http {
                                if h != 200 {
                                    ui.label(RichText::new(format!("HTTP {h}")).color(p.err).small());
                                }
                            }
                        });
                        row.col(|ui| {
                            let e = c.errors.join(" · ");
                            cell(ui, RichText::new(&e).color(p.err), &e);
                        });
                    });
                });
        });
    }

    fn commands(&mut self, ui: &mut egui::Ui, g: &Shared) {
        let p = pal(ui);
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.cmd_filter).hint_text("Filter: Befehl, Status, Fehler …").desired_width(280.0));
            ui.checkbox(&mut self.cmd_hide_routine, "Routine-Abfragen ausblenden");
            ui.checkbox(&mut self.cmd_only_err, "nur Fehler");
        });
        ui.add_space(4.0);
        if !g.helper.running && g.tracker.cmds.is_empty() {
            ui.label(RichText::new("Kein MDM-Log – oben „Admin-Zugriff aktivieren“.").color(p.warn));
        }
        let f = self.cmd_filter.to_lowercase();
        let routine = ["ProfileList", "DeviceInformation", "SecurityInfo", "InstalledApplicationList", "CertificateList", "ProvisioningProfileList", "ManagedApplicationList", "DeclarativeManagement"];
        let rows: Vec<&mdm::Command> = g
            .tracker
            .list()
            .into_iter()
            .filter(|c| !(self.cmd_hide_routine && routine.contains(&c.command.as_str()) && !c.failed()))
            .filter(|c| !self.cmd_only_err || c.failed())
            .filter(|c| f.is_empty() || format!("{} {} {} {} {}", c.command, c.status, c.scope, c.errors.join(" "), c.uuid).to_lowercase().contains(&f))
            .collect();
        let sum = mdm::summarize(&g.tracker);
        card(
            ui,
            "Empfangene MDM-Befehle",
            |ui| muted(ui, format!("{} angezeigt · {} gesamt · {} fehlgeschlagen", rows.len(), g.tracker.cmds.len(), sum.failed)),
            |ui| {
                let h = ui.available_height() - 30.0;
                Self::commands_table(ui, "cmds", &rows, h.max(200.0));
                muted(ui, "Acknowledged = ausgeführt · Error = fehlgeschlagen · NotNow = später (z. B. Bildschirm gesperrt) · Sync im Unternehmensportal löst einen Check-in aus");
            },
        );
    }

    // ------------------------------------------------------------ MDM-Log
    fn mdm_log(&mut self, ui: &mut egui::Ui, g: &Shared) {
        let p = pal(ui);
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.log_filter).hint_text("Filter").desired_width(280.0));
            ui.checkbox(&mut self.log_important, "nur wichtige");
            if ui.checkbox(&mut self.log_pause, "Pause").changed() {
                self.log_frozen = if self.log_pause { Some(g.mdm_events.iter().cloned().collect()) } else { None };
            }
            muted(ui, format!("{} Einträge", g.mdm_events.len()));
        });
        ui.add_space(4.0);
        if !g.helper.running && g.mdm_events.is_empty() {
            ui.label(RichText::new("Kein MDM-Log – oben „Admin-Zugriff aktivieren“.").color(p.warn));
        }
        let f = self.log_filter.to_lowercase();
        let src: Vec<&mdm::Event> = match &self.log_frozen {
            Some(v) => v.iter().collect(),
            None => g.mdm_events.iter().collect(),
        };
        let rows: Vec<&mdm::Event> = src
            .into_iter()
            .filter(|e| !self.log_important || e.important)
            .filter(|e| f.is_empty() || e.msg.to_lowercase().contains(&f))
            .collect();
        log_view(ui, "mdmlog", rows.len(), |i| {
            let e = rows[i];
            let col = if e.kind == mdm::Kind::Error || e.mtype == "Error" || e.mtype == "Fault" {
                Some(p.err)
            } else if e.important {
                None
            } else {
                Some(p.muted)
            };
            (short_t(&e.t), e.cat.clone(), e.msg.clone(), col)
        });
    }

    // ------------------------------------------------------------ Intune
    fn intune(&mut self, ui: &mut egui::Ui, g: &Shared) {
        let p = pal(ui);
        let mut pols: Vec<&intune::Policy> = g.policies.p.values().collect();
        pols.sort_by(|a, b| b.errors.cmp(&a.errors).then(b.last.cmp(&a.last)));
        let mut clicked: Option<String> = None;
        let h = (ui.available_height() * 0.36).clamp(150.0, 360.0);
        card(ui, "Richtlinien (Apps / Skripte)", |ui| muted(ui, "Klick auf einen Namen filtert den Log"), |ui| {
            fixed_height(ui, h, |ui| {
                TableBuilder::new(ui)
                    .id_salt("pols")
                    .striped(true)
                    .resizable(false)
                    .auto_shrink(false)
                    .column(Column::exact(260.0))
                    .column(Column::exact(70.0))
                    .column(Column::exact(60.0))
                    .column(Column::exact(60.0))
                    .column(Column::exact(110.0))
                    .column(Column::remainder().clip(true))
                    .header(24.0, |mut hr| {
                        for t in ["Name", "Bereich", "Fehler", "Warn.", "Zuletzt", "Letzte Meldung"] {
                            hr.col(|ui| {
                                ui.label(RichText::new(t).color(p.muted).size(11.5).strong());
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(26.0, pols.len(), |mut row| {
                            let x = pols[row.index()];
                            row.col(|ui| {
                                let name = if x.name.is_empty() { format!("{}…", &x.id[..8.min(x.id.len())]) } else { x.name.clone() };
                                let r = ui.add(egui::Label::new(RichText::new(name).strong().color(p.accent)).truncate().sense(egui::Sense::click()));
                                if r.on_hover_text(&x.id).clicked() {
                                    clicked = Some(x.id.clone());
                                }
                            });
                            row.col(|ui| cell(ui, RichText::new(&x.domain).color(p.muted), ""));
                            row.col(|ui| {
                                if x.errors > 0 { pill(ui, &x.errors.to_string(), p.err); } else { muted(ui, "0") }
                            });
                            row.col(|ui| {
                                if x.warnings > 0 { pill(ui, &x.warnings.to_string(), p.warn); } else { muted(ui, "0") }
                            });
                            row.col(|ui| cell(ui, RichText::new(short_t(&x.last)).color(p.muted), &x.last));
                            row.col(|ui| {
                                if x.last_error.is_empty() {
                                    cell(ui, RichText::new(&x.last_msg), &x.last_msg)
                                } else {
                                    cell(ui, RichText::new(&x.last_error).color(p.err), &x.last_error)
                                }
                            });
                        });
                    });
            });
        });
        if let Some(id) = clicked {
            self.int_filter = id;
        }
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.int_filter).hint_text("Filter: Text, PolicyID …").desired_width(300.0));
            if !self.int_filter.is_empty() && ui.small_button("×").clicked() {
                self.int_filter.clear();
            }
            egui::ComboBox::from_id_salt("lvl")
                .selected_text(["alle Stufen", "Warnung + Fehler", "nur Fehler"][self.int_level as usize])
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.int_level, 0, "alle Stufen");
                    ui.selectable_value(&mut self.int_level, 1, "Warnung + Fehler");
                    ui.selectable_value(&mut self.int_level, 2, "nur Fehler");
                });
            ui.checkbox(&mut self.int_hide_noise, "Routine ausblenden");
        });
        ui.add_space(4.0);
        let noise = ["ExecutionClock", "ObserveNetworkInterface", "SyncActivityTracer", "SyncActivityRunner", "CheckForLoggedInUsers", "RepeatableTaskRunner", "HealthCheckWorkflow"];
        let f = self.int_filter.to_lowercase();
        let rows: Vec<&intune::Event> = g
            .intune_events
            .iter()
            .filter(|e| match self.int_level {
                1 => e.lvl != 'I',
                2 => e.lvl == 'E',
                _ => true,
            })
            .filter(|e| !self.int_hide_noise || e.lvl != 'I' || !noise.contains(&e.cat.as_str()))
            .filter(|e| f.is_empty() || e.msg.to_lowercase().contains(&f) || e.cat.to_lowercase().contains(&f))
            .collect();
        log_view(ui, "intlog", rows.len(), |i| {
            let e = rows[i];
            let col = match e.lvl {
                'E' => Some(p.err),
                'W' => Some(p.warn),
                _ => None,
            };
            (short_t(&e.t), e.cat.clone(), e.msg.clone(), col)
        });
    }

    // ------------------------------------------------------------ Profile
    fn profiles(&mut self, ui: &mut egui::Ui, g: &Shared) {
        let p = pal(ui);
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.prof_filter).hint_text("Filter: Name, Identifier, Payload-Typ …").desired_width(300.0));
            muted(ui, if g.profiles.full { "Gerät + Benutzer" } else { "nur Benutzer-Profile – Geräte-Profile brauchen Admin-Zugriff" });
        });
        ui.add_space(4.0);
        for e in &g.profiles.errors {
            ui.label(RichText::new(e).color(p.warn));
        }
        let f = self.prof_filter.to_lowercase();
        let list: Vec<&data::Profile> = g
            .profiles
            .profiles
            .iter()
            .filter(|x| f.is_empty() || format!("{} {} {}", x.name, x.identifier, x.payloads.iter().map(|y| y.ptype.as_str()).collect::<Vec<_>>().join(" ")).to_lowercase().contains(&f))
            .collect();
        let n_list = list.len();
        card(ui, "Installierte Profile", |ui| muted(ui, format!("{n_list} angezeigt")), |ui| {
            egui::ScrollArea::vertical().id_salt("profs").auto_shrink(false).show(ui, |ui| {
                let mut last_scope = String::new();
                for x in list {
                    if x.scope != last_scope {
                        ui.add_space(6.0);
                        ui.label(RichText::new(&x.scope).color(p.muted).size(11.5).strong());
                        last_scope = x.scope.clone();
                    }
                    let id = ui.make_persistent_id(format!("p-{}-{}", x.scope, x.identifier));
                    egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, false)
                        .show_header(ui, |ui| {
                            ui.label(RichText::new(&x.name).strong());
                            if x.removal_disallowed {
                                pill(ui, "gesperrt", p.info);
                            }
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.label(RichText::new(&x.install_date).color(p.muted).monospace());
                                ui.label(RichText::new(format!("{} Payload(s)", x.payloads.len())).color(p.muted).small());
                            });
                        })
                        .body(|ui| {
                            kv_grid(ui, &format!("pg-{}", x.identifier), &[
                                ("Identifier", x.identifier.clone()),
                                ("UUID", x.uuid.clone()),
                                ("Organisation", x.organization.clone()),
                                ("Installiert", x.install_date.clone()),
                                ("Prüfstatus", x.verified.clone()),
                                ("Entfernen gesperrt", if x.removal_disallowed { "ja".into() } else { "nein".into() }),
                            ]);
                            for pl in &x.payloads {
                                egui::CollapsingHeader::new(RichText::new(format!("{}  ·  {}", pl.ptype, pl.name)).monospace())
                                    .id_salt(format!("pl-{}-{}", x.identifier, pl.uuid))
                                    .show(ui, |ui| {
                                        muted(ui, &pl.identifier);
                                        let mut txt = serde_json::to_string_pretty(&pl.content).unwrap_or_default();
                                        ui.add(egui::TextEdit::multiline(&mut txt).code_editor().desired_width(f32::INFINITY).desired_rows(4));
                                    });
                            }
                        });
                }
            });
        });
    }

    // ------------------------------------------------------------ VPN & DNS
    fn vpn(&mut self, ui: &mut egui::Ui, g: &Shared) {
        let p = pal(ui);
        egui::ScrollArea::vertical().id_salt("vpn").auto_shrink(false).show(ui, |ui| {
            let vpns: Vec<&data::NeConfig> = g.ne.configs.iter().filter(|c| c.kinds.iter().any(|k| k.contains("VPN"))).collect();
            let others: Vec<&data::NeConfig> = g.ne.configs.iter().filter(|c| !c.kinds.iter().any(|k| k.contains("VPN"))).collect();
            card(ui, "VPN-Verbindungen", |ui| muted(ui, format!("Datei geändert {}", short_t(&g.ne.mtime))), |ui| {
                if let Some(e) = &g.ne.error {
                    ui.label(RichText::new(e).color(p.err));
                }
                if vpns.is_empty() {
                    muted(ui, "Keine VPN-Verbindungen.");
                }
                for (i, c) in vpns.iter().enumerate() {
                    if i > 0 {
                        ui.separator();
                    }
                    let issues = g.drift.iter().find(|d| d.0 == c.uuid).map(|d| d.1.as_slice()).unwrap_or(&[]);
                    let worst = issues.iter().map(|i| i.level).max();
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&c.name).strong().size(14.0));
                        match worst {
                            Some(Level::Error) => pill(ui, "Problem", p.err),
                            Some(Level::Warn) => pill(ui, "Hinweis", p.warn),
                            _ => pill(ui, "ok", p.ok),
                        };
                        muted(ui, &c.server);
                    });
                    for is in issues.iter().filter(|i| i.level != Level::Info) {
                        ui.horizontal(|ui| {
                            level_pill(ui, is.level);
                            ui.add(egui::Label::new(&is.text).wrap());
                        });
                    }
                    let d = c.dns.clone().unwrap_or_default();
                    let mut rows = vec![
                        ("Benutzer", c.username.clone()),
                        ("Passwort gespeichert", if c.password_saved { "ja".into() } else { "nein".into() }),
                        ("DNS-Server", util::fmt_list(&d.servers)),
                        ("Match-Domänen", util::fmt_list(&d.match_domains)),
                        ("Domäne", if d.domain_name.is_empty() { "–".into() } else { d.domain_name.clone() }),
                        ("Suchdomänen", util::fmt_list(&d.search_domains)),
                    ];
                    match &c.profile {
                        Some(pr) if !pr.identifier.is_empty() => {
                            rows.push(("aus Profil", pr.identifier.clone()));
                            rows.push(("eingespielt", format!("{} · {}", pr.ingested, pr.system_version)));
                        }
                        _ => rows.push(("aus Profil", "– (manuell angelegt)".into())),
                    }
                    rows.push(("UUID", c.uuid.clone()));
                    kv_grid(ui, &format!("neg-{}", c.uuid), &rows);
                    egui::CollapsingHeader::new("Rohdaten").id_salt(format!("raw-{}", c.uuid)).show(ui, |ui| {
                        let mut txt = serde_json::to_string_pretty(&c.raw).unwrap_or_default();
                        ui.add(egui::TextEdit::multiline(&mut txt).code_editor().desired_width(f32::INFINITY));
                    });
                }
            });
            ui.add_space(10.0);
            card(ui, "Weitere Netzwerk-Erweiterungen", |ui| muted(ui, "Filter, Firewall, Datenschutz"), |ui| {
                egui::Grid::new("others").striped(true).num_columns(2).spacing([18.0, 4.0]).show(ui, |ui| {
                    for c in others {
                        ui.label(&c.name);
                        muted(ui, c.kinds.join(", "));
                        ui.end_row();
                    }
                });
            });
            ui.add_space(10.0);
            card(ui, "DNS-Resolver", |ui| muted(ui, "werden für normale Anfragen benutzt"), |ui| {
                muted(ui, "Fehlt hier ein Eintrag für eure interne Domäne (z. B. firma.example → VPN-DNS), gehen Anfragen an den Standard-DNS.");
                egui::Grid::new("dns").striped(true).num_columns(4).spacing([18.0, 4.0]).show(ui, |ui| {
                    for t in ["Domäne", "Nameserver", "Interface", "Suchdomänen"] {
                        ui.label(RichText::new(t).color(p.muted).small().strong());
                    }
                    ui.end_row();
                    for r in g.dns.iter().filter(|r| !r.scoped) {
                        ui.label(RichText::new(if r.domain.is_empty() { "(Standard)" } else { &r.domain }).monospace());
                        ui.label(RichText::new(util::fmt_list(&r.nameservers)).monospace());
                        muted(ui, &r.interface);
                        ui.label(RichText::new(util::fmt_list(&r.search)).monospace());
                        ui.end_row();
                    }
                });
                egui::CollapsingHeader::new("Scoped Resolver (nur für an ein Interface gebundene Anfragen)").show(ui, |ui| {
                    for r in g.dns.iter().filter(|r| r.scoped) {
                        ui.label(RichText::new(format!("{}   {}   {}", r.interface, util::fmt_list(&r.nameservers), util::fmt_list(&r.search))).monospace());
                    }
                });
            });
            ui.add_space(10.0);
            card(ui, "Namensauflösung testen", |_| {}, |ui| {
                ui.horizontal(|ui| {
                    ui.add(egui::TextEdit::singleline(&mut self.hosts_input).hint_text("z. B. intranet.example.com, wiki.example.com").desired_width(440.0));
                    if ui.button("Speichern & testen").clicked() {
                        let hosts: Vec<String> = self
                            .hosts_input
                            .split(|c: char| c == ',' || c == ';' || c.is_whitespace())
                            .filter(|x| !x.is_empty() && x.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-'))
                            .map(|x| x.to_string())
                            .take(50)
                            .collect();
                        save_hosts(&hosts);
                        self.s.lock().map(|mut g| g.hosts = hosts).ok();
                        self.rescan.store(true, Ordering::SeqCst);
                    }
                });
                egui::Grid::new("hosts").striped(true).num_columns(4).spacing([18.0, 4.0]).show(ui, |ui| {
                    for r in &g.host_results {
                        ui.label(RichText::new(&r.host).monospace());
                        if r.ok { pill(ui, "aufgelöst", p.ok); } else { pill(ui, "nicht aufgelöst", p.err); }
                        ui.label(RichText::new(&r.text).monospace());
                        muted(ui, format!("{} ms", r.ms));
                        ui.end_row();
                    }
                });
            });
        });
    }

    // ------------------------------------------------------------ Änderungen
    fn changes(&mut self, ui: &mut egui::Ui, g: &Shared) {
        let p = pal(ui);
        card(ui, "Erkannte Änderungen", |ui| muted(ui, "Profile, VPN-Konfigurationen, Enrollment · Scan alle 30 s"), |ui| {
            if g.changes.is_empty() {
                muted(ui, "Noch keine Änderungen. Der erste Scan legt den Ausgangszustand fest.");
            }
            egui::ScrollArea::vertical().id_salt("chg").auto_shrink(false).show(ui, |ui| {
                for (i, c) in g.changes.iter().enumerate().rev() {
                    let col = match c.action.as_str() {
                        "entfernt" => p.err,
                        "hinzugefügt" => p.ok,
                        _ => p.warn,
                    };
                    let id = ui.make_persistent_id(format!("chg-{i}"));
                    egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, false)
                        .show_header(ui, |ui| {
                            ui.label(RichText::new(short_t(&c.t)).color(p.muted));
                            pill(ui, &c.action, col);
                            pill(ui, &c.area, p.info);
                            ui.label(RichText::new(if c.name.is_empty() { &c.key } else { &c.name }).strong());
                            if !c.details.is_empty() {
                                muted(ui, format!("{} Feld(er)", c.details.len()));
                            }
                        })
                        .body(|ui| {
                            muted(ui, &c.key);
                            if !c.details.is_empty() {
                                egui::Grid::new(format!("chgd-{i}")).striped(true).num_columns(3).spacing([14.0, 4.0]).show(ui, |ui| {
                                    for t in ["Feld", "vorher", "nachher"] {
                                        ui.label(RichText::new(t).color(p.muted).small().strong());
                                    }
                                    ui.end_row();
                                    for (path, o, n) in &c.details {
                                        ui.label(RichText::new(path).monospace());
                                        ui.add(egui::Label::new(RichText::new(o).monospace().color(p.err)).wrap());
                                        ui.add(egui::Label::new(RichText::new(n).monospace().color(p.ok)).wrap());
                                        ui.end_row();
                                    }
                                });
                            }
                        });
                }
            });
        });
    }

    // ------------------------------------------------------------ Verlauf
    fn history(&mut self, ui: &mut egui::Ui, g: &Shared) {
        let p = pal(ui);
        ui.horizontal(|ui| {
            ui.label("Zeitraum");
            egui::ComboBox::from_id_salt("hist").selected_text(fmt_minutes(self.hist_minutes)).show_ui(ui, |ui| {
                for m in [120u32, 720, 1440, 4320, 10080] {
                    ui.selectable_value(&mut self.hist_minutes, m, fmt_minutes(m));
                }
            });
            let enabled = g.helper.running && !g.history_busy;
            if ui.add_enabled(enabled, egui::Button::new("Aus Unified Log laden")).clicked() {
                request_history(self.s.clone(), ui.ctx().clone(), self.hist_minutes);
            }
            if g.history_busy {
                ui.spinner();
            }
            muted(ui, if !g.helper.running { "braucht Admin-Zugriff" } else { &g.history_msg });
        });
        ui.add_space(6.0);
        let Some(h) = &g.history else {
            card(ui, "", |_| {}, |ui| muted(ui, "Lädt die MDM-Befehle der gewählten Zeitspanne aus dem Unified Log und fasst wiederholte Fehler zusammen."));
            return;
        };
        let sum = mdm::summarize(&h.tracker);
        ui.horizontal_wrapped(|ui| {
            for (k, n) in &sum.by_command {
                egui::Frame::new().fill(p.card).stroke(egui::Stroke::new(1.0, p.line)).corner_radius(8.0).inner_margin(egui::Margin::symmetric(12, 8)).show(ui, |ui| {
                    ui.label(RichText::new(n.to_string()).size(20.0).strong());
                    ui.label(RichText::new(k).color(p.muted).small());
                });
            }
        });
        ui.add_space(8.0);
        card(ui, "Wiederholte Fehler", |ui| muted(ui, format!("{} · {} Log-Einträge", fmt_minutes(h.minutes), h.total)), |ui| {
            if sum.repeated_errors.is_empty() {
                muted(ui, "Keine.");
            }
            for (cmd, err, n) in sum.repeated_errors.iter().take(20) {
                ui.horizontal(|ui| {
                    pill(ui, &format!("{n}×"), p.err);
                    ui.label(RichText::new(cmd).strong());
                    ui.add(egui::Label::new(err).wrap());
                });
            }
        });
        ui.add_space(8.0);
        let rows = h.tracker.list();
        card(ui, "Befehle", |ui| muted(ui, format!("{}", rows.len())), |ui| {
            let hh = (ui.available_height() - 10.0).max(220.0);
            Self::commands_table(ui, "histcmds", &rows, hh);
        });
    }
}

// ======================================================================= Selbst-Screenshots (Test)

pub struct Shots {
    dir: std::path::PathBuf,
    idx: usize,
    frames: u32,
    waiting: Arc<AtomicBool>,
    started: Instant,
}

const SHOT_TABS: [(Tab, &str); 8] = [
    (Tab::Overview, "overview"),
    (Tab::Commands, "commands"),
    (Tab::MdmLog, "mdmlog"),
    (Tab::Intune, "intune"),
    (Tab::Profiles, "profiles"),
    (Tab::Vpn, "vpn"),
    (Tab::Changes, "changes"),
    (Tab::History, "history"),
];

fn save_png(path: &std::path::Path, img: &egui::ColorImage) {
    let Ok(f) = std::fs::File::create(path) else { return };
    let mut enc = png::Encoder::new(std::io::BufWriter::new(f), img.size[0] as u32, img.size[1] as u32);
    enc.set_color(png::ColorType::Rgba);
    enc.set_depth(png::BitDepth::Eight);
    if let Ok(mut w) = enc.write_header() {
        let data: Vec<u8> = img.pixels.iter().flat_map(|c| c.to_array()).collect();
        let _ = w.write_image_data(&data);
    }
}

impl App {
    fn drive_shots(&mut self, ctx: &egui::Context) {
        let Some(sh) = &mut self.shots else { return };
        ctx.request_repaint();
        if sh.started.elapsed() < Duration::from_secs(8) || sh.waiting.load(Ordering::SeqCst) {
            return;
        }
        if sh.idx >= SHOT_TABS.len() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        let (tab, name) = SHOT_TABS[sh.idx];
        if self.tab != tab {
            self.tab = tab;
            sh.frames = 0;
            return;
        }
        sh.frames += 1;
        if sh.frames < 10 {
            return;
        }
        sh.waiting.store(true, Ordering::SeqCst);
        let path = sh.dir.join(format!("{}-{name}.png", sh.idx));
        let w = sh.waiting.clone();
        let c = ctx.clone();
        sh.idx += 1;
        ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::ScreenshotCallback::new(move |img| {
            save_png(&path, &img);
            w.store(false, Ordering::SeqCst);
            c.request_repaint();
        })));
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.drive_shots(&ui.ctx().clone());
        let shared = self.s.clone();
        let g = shared.lock().unwrap();
        let p = pal(ui);
        egui::Panel::top("top")
            .frame(egui::Frame::new().fill(p.card).inner_margin(egui::Margin { left: 16, right: 16, top: 10, bottom: 8 }).stroke(egui::Stroke::new(1.0, p.line)))
            .show(ui, |ui| self.header(ui, &g));
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(ui.visuals().panel_fill).inner_margin(egui::Margin::same(16)))
            .show(ui, |ui| match self.tab {
                Tab::Overview => egui::ScrollArea::vertical().id_salt("ov").auto_shrink(false).show(ui, |ui| self.overview(ui, &g)).inner,
                Tab::Commands => self.commands(ui, &g),
                Tab::MdmLog => self.mdm_log(ui, &g),
                Tab::Intune => self.intune(ui, &g),
                Tab::Profiles => self.profiles(ui, &g),
                Tab::Vpn => self.vpn(ui, &g),
                Tab::Changes => self.changes(ui, &g),
                Tab::History => egui::ScrollArea::vertical().id_salt("hi").auto_shrink(false).show(ui, |ui| self.history(ui, &g)).inner,
            });
        drop(g);
        ui.ctx().request_repaint_after(Duration::from_secs(2));
    }
}

pub fn run() -> eframe::Result {
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1320.0, 860.0]).with_min_inner_size([820.0, 520.0]).with_title("MDM Watch"),
        ..Default::default()
    };
    eframe::run_native("MDM Watch", opts, Box::new(|cc| Ok(Box::new(App::new(cc)))))
}
