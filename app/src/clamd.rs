//! Starts a private, per-user `clamd` so the ClamAV mode works with no system service and no root.
//! A copy of ClamAV ships with the app (`clamav/`); a system installation is the fallback.
//! The processes belong to the app: `clamd` is stopped when the window closes.
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, SystemTime},
};
const SYSTEM_DATABASE_DIR: &str = "/var/lib/clamav";
const REFRESH_AFTER: Duration = Duration::from_secs(24 * 60 * 60);
pub struct Clamd(Child, PathBuf);
impl Clamd {
    pub fn running(&mut self) -> bool {
        matches!(self.0.try_wait(), Ok(None))
    }
}
impl Drop for Clamd {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        // A killed clamd leaves its socket file behind, which would look like a live daemon.
        let _ = fs::remove_file(&self.1);
    }
}
/// Where the bundled ClamAV lives: `$STRAZH_CLAMAV`, the install dir, or the project folder.
fn bundle() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let mut candidates: Vec<PathBuf> = std::env::var_os("STRAZH_CLAMAV")
        .map(PathBuf::from)
        .into_iter()
        .collect();
    for up in [2, 3] {
        if let Some(dir) = exe.ancestors().nth(up) {
            candidates.push(dir.join("clamav"));
        }
    }
    candidates
        .into_iter()
        .find(|dir| dir.join("bin/clamd").is_file())
}
fn newest_database(dir: &Path) -> Option<SystemTime> {
    fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            name.ends_with(".cvd") || name.ends_with(".cld")
        })
        .filter_map(|e| e.metadata().ok()?.modified().ok())
        .max()
}
fn in_path(program: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(program))
        .find(|p| p.is_file())
}
fn command(program: &Path, bundle: Option<&Path>) -> Command {
    let mut cmd = Command::new(program);
    if let Some(bundle) = bundle {
        cmd.env("LD_LIBRARY_PATH", bundle.join("lib"));
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd
}
/// Quietly refreshes the bundled database in the background when it is older than a day.
/// Offline or failing updates are harmless; the running `clamd` reloads on its self-check.
fn refresh(bundle: &Path, runtime: &Path) {
    let db = bundle.join("db");
    let stale =
        newest_database(&db).is_none_or(|t| t.elapsed().is_ok_and(|age| age > REFRESH_AFTER));
    if !stale {
        return;
    }
    let config = runtime.join("strazh-freshclam.conf");
    let text = format!(
        "DatabaseDirectory {}\nDatabaseMirror database.clamav.net\nConnectTimeout 10\nReceiveTimeout 30\n",
        db.display()
    );
    if fs::write(&config, text).is_err() {
        return;
    }
    if let Ok(mut child) = command(&bundle.join("bin/freshclam"), Some(bundle))
        .arg("--config-file")
        .arg(&config)
        .arg("--quiet")
        .spawn()
    {
        std::thread::spawn(move || {
            let _ = child.wait();
        });
    }
}
/// Returns `None` when a daemon is already reachable, ClamAV is unavailable,
/// or no signature database exists.
pub fn start() -> Option<Clamd> {
    let socket = scan_engine::user_clam_socket()?;
    let runtime = socket.parent()?.to_path_buf();
    let bundle = bundle();
    // Keep the database fresh even when an opt-in login service already runs clamd.
    if let Some(dir) = &bundle {
        refresh(dir, &runtime);
    }
    if scan_engine::detect_clam().is_some() {
        return None;
    }
    let (program, database) = match &bundle {
        Some(dir) => {
            let own = dir.join("db");
            let database = if newest_database(&own).is_some() {
                own
            } else {
                PathBuf::from(SYSTEM_DATABASE_DIR)
            };
            (dir.join("bin/clamd"), database)
        }
        None => (in_path("clamd")?, PathBuf::from(SYSTEM_DATABASE_DIR)),
    };
    newest_database(&database)?;
    // clamd spools each stream to disk; the runtime dir is a small RAM disk.
    let spool = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))?
        .join("strazh/clamd-tmp");
    fs::create_dir_all(&spool).ok()?;
    let config = runtime.join("strazh-clamd.conf");
    let text = format!(
        "DatabaseDirectory {}\nLocalSocket {}\nLocalSocketMode 600\nForeground yes\n\
         TemporaryDirectory {}\nStreamMaxLength 4G\nMaxFileSize 0\nMaxScanSize 0\nMaxRecursion 64\nMaxFiles 0\nMaxThreads 4\n\
         SelfCheck 3600\n",
        database.display(),
        socket.display(),
        spool.display()
    );
    fs::write(&config, text).ok()?;
    let _ = fs::remove_file(&socket);
    command(&program, bundle.as_deref())
        .arg("--config-file")
        .arg(&config)
        .spawn()
        .ok()
        .map(|child| Clamd(child, socket))
}
