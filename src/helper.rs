//! Privilegierter Helfer. Läuft als root (über die macOS-Admin-Abfrage gestartet),
//! liest das MDM-Log und die Geräte-Profile und schreibt die Ergebnisse in den
//! Ordner des Benutzers. Alle Dateizugriffe laufen relativ zu einem einmal
//! geöffneten Verzeichnis-Handle (openat/renameat), ohne Symlinks zu folgen.
//! Beendet sich, wenn die App beendet wird.

use crate::{data, mdm};
use serde_json::{json, Value as J};
use std::ffi::CString;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_LOG: u64 = 50 * 1024 * 1024;

struct Dir {
    fd: RawFd,
    uid: libc::uid_t,
}

impl Dir {
    fn open(path: &str, uid: libc::uid_t) -> Result<Dir, String> {
        let c = CString::new(path).map_err(|e| e.to_string())?;
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(format!("Ordner {path} nicht zu öffnen"));
        }
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st) } != 0 {
            return Err("fstat fehlgeschlagen".into());
        }
        if st.st_uid != uid || (st.st_mode & 0o022) != 0 {
            unsafe { libc::close(fd) };
            return Err(format!("Ordner {path} gehört nicht dem Benutzer oder ist für andere schreibbar"));
        }
        Ok(Dir { fd, uid })
    }

    fn cname(name: &str) -> CString {
        CString::new(name).unwrap()
    }

    fn unlink(&self, name: &str) {
        let c = Self::cname(name);
        unsafe { libc::unlinkat(self.fd, c.as_ptr(), 0) };
    }

    /// Neue Datei exklusiv anlegen (folgt keinen Symlinks), dem Benutzer übergeben.
    fn create(&self, name: &str) -> Result<File, String> {
        self.unlink(name);
        let c = Self::cname(name);
        let fd = unsafe {
            libc::openat(self.fd, c.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_APPEND, 0o600 as libc::c_uint)
        };
        if fd < 0 {
            return Err(format!("{name} nicht anlegbar"));
        }
        unsafe { libc::fchown(fd, self.uid, u32::MAX as libc::gid_t) };
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn write_atomic(&self, name: &str, data: &[u8]) {
        let tmp = format!(".{name}.tmp");
        if let Ok(mut f) = self.create(&tmp) {
            let _ = f.write_all(data);
            drop(f);
            let a = Self::cname(&tmp);
            let b = Self::cname(name);
            unsafe { libc::renameat(self.fd, a.as_ptr(), self.fd, b.as_ptr()) };
        }
    }

    fn read_small(&self, name: &str) -> Option<String> {
        let c = Self::cname(name);
        let fd = unsafe { libc::openat(self.fd, c.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK) };
        if fd < 0 {
            return None;
        }
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        unsafe { libc::fstat(fd, &mut st) };
        let mut f = unsafe { File::from_raw_fd(fd) };
        if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return None;
        }
        let mut s = String::new();
        let _ = (&mut f).take(64).read_to_string(&mut s);
        Some(s)
    }

    fn exists(&self, name: &str) -> bool {
        let c = Self::cname(name);
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        unsafe { libc::fstatat(self.fd, c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) == 0 }
    }
}

fn arg(args: &[String], k: &str) -> Option<String> {
    args.iter().position(|a| a == k).and_then(|i| args.get(i + 1).cloned())
}

fn alive(pid: i32) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}

/// Nur die nötigen Felder einer ndjson-Zeile behalten.
fn compact(line: &str) -> Option<String> {
    if !line.starts_with('{') {
        return None;
    }
    let v: J = serde_json::from_str(line).ok()?;
    v.get("eventMessage")?;
    Some(
        json!({
            "timestamp": v.get("timestamp"),
            "messageType": v.get("messageType"),
            "category": v.get("category"),
            "eventMessage": v.get("eventMessage"),
        })
        .to_string(),
    )
}

fn status(dir: &Dir, state: &str, started: &str, msg: &str) {
    let s = json!({"pid": std::process::id(), "state": state, "started": started, "msg": msg, "t": crate::util::now_iso()});
    dir.write_atomic("helper.json", s.to_string().as_bytes());
}

pub fn run(args: &[String]) -> i32 {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("Helfer muss als root laufen");
        return 1;
    }
    let (Some(path), Some(parent), Some(uid)) = (arg(args, "--dir"), arg(args, "--parent"), arg(args, "--uid")) else {
        eprintln!("Argumente fehlen");
        return 2;
    };
    let parent: i32 = parent.parse().unwrap_or(0);
    let uid: libc::uid_t = uid.parse().unwrap_or(u32::MAX);
    if parent <= 1 || uid == u32::MAX || uid == 0 {
        return 2;
    }
    let dir = match Dir::open(&path, uid) {
        Ok(d) => Arc::new(d),
        Err(e) => {
            eprintln!("{e}");
            return 3;
        }
    };
    let started = crate::util::now_iso();
    dir.unlink("stop");
    status(&dir, "running", &started, "läuft");

    // --- log stream
    let log = match dir.create("mdm.ndjson") {
        Ok(f) => Arc::new(Mutex::new(f)),
        Err(e) => {
            status(&dir, "error", &started, &e);
            return 4;
        }
    };
    let mut child = match Command::new("/usr/bin/log")
        .args(["stream", "--style", "ndjson", "--level", "info", "--predicate", mdm::PREDICATE])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            status(&dir, "error", &started, &e.to_string());
            return 5;
        }
    };
    let out = child.stdout.take().unwrap();
    {
        let log = log.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                if let Some(c) = compact(&line) {
                    let mut f = log.lock().unwrap();
                    if f.metadata().map(|m| m.len() > MAX_LOG).unwrap_or(false) {
                        let _ = f.set_len(0);
                    }
                    let _ = writeln!(f, "{c}");
                }
            }
        });
    }

    // --- Hauptschleife
    let history_busy = Arc::new(Mutex::new(false));
    let mut last_profiles = Instant::now() - Duration::from_secs(3600);
    loop {
        if !alive(parent) || dir.exists("stop") {
            break;
        }
        if let Ok(Some(_)) = child.try_wait() {
            status(&dir, "error", &started, "log stream wurde beendet");
            break;
        }
        if last_profiles.elapsed() > Duration::from_secs(30) || dir.exists("rescan") {
            dir.unlink("rescan");
            let p = data::get_profiles(true);
            dir.write_atomic("profiles.json", serde_json::to_string(&p).unwrap_or_default().as_bytes());
            last_profiles = Instant::now();
            status(&dir, "running", &started, "läuft");
        }
        if let Some(req) = dir.read_small("history.req") {
            dir.unlink("history.req");
            let busy = history_busy.clone();
            let mut b = busy.lock().unwrap();
            if !*b {
                *b = true;
                drop(b);
                let minutes: u32 = req.trim().parse::<u32>().unwrap_or(60).clamp(1, 10080);
                let d = dir.clone();
                std::thread::spawn(move || {
                    history(&d, minutes);
                    *busy.lock().unwrap() = false;
                });
            }
        }
        std::thread::sleep(Duration::from_millis(700));
    }
    let _ = child.kill();
    status(&dir, "stopped", &started, "beendet");
    0
}

fn history(dir: &Dir, minutes: u32) {
    dir.unlink("history.done");
    let child = Command::new("/usr/bin/log")
        .args(["show", "--last", &format!("{minutes}m"), "--style", "ndjson", "--info", "--predicate", mdm::PREDICATE])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let Ok(mut child) = child else {
        dir.write_atomic("history.done", b"{\"error\":\"log show nicht startbar\"}");
        return;
    };
    let out = child.stdout.take().unwrap();
    let mut buf = String::new();
    let mut total = 0usize;
    let mut kept = 0usize;
    for line in BufReader::new(out).lines().map_while(Result::ok) {
        let Some(c) = compact(&line) else { continue };
        total += 1;
        // nur relevante Zeilen behalten
        if let Ok(v) = serde_json::from_str::<J>(&c) {
            if let Some(e) = mdm::parse(&v) {
                if e.kind != mdm::Kind::Other || e.mtype == "Error" || e.mtype == "Fault" {
                    buf.push_str(&c);
                    buf.push('\n');
                    kept += 1;
                }
            }
        }
        if buf.len() > 80 * 1024 * 1024 {
            break;
        }
    }
    let _ = child.wait();
    dir.write_atomic("history.ndjson", buf.as_bytes());
    dir.write_atomic("history.done", json!({"total": total, "kept": kept, "minutes": minutes}).to_string().as_bytes());
}
