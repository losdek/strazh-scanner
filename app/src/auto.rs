use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
        Arc,
    },
    time::{Duration, Instant, SystemTime},
};
/// A file must stay unchanged this long before it is scanned.
const SETTLE: Duration = Duration::from_secs(10);
pub struct Auto {
    pub files: Receiver<Vec<PathBuf>>,
    cancel: Arc<AtomicBool>,
}
impl Drop for Auto {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}
fn partial(p: &Path) -> bool {
    let s = p
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase();
    [
        ".part",
        ".crdownload",
        ".tmp",
        ".!qb",
        ".download",
        ".aria2",
    ]
    .iter()
    .any(|e| s.ends_with(e))
        || {
            let mut sidecar = p.as_os_str().to_os_string();
            sidecar.push(".aria2");
            Path::new(&sidecar).exists()
        }
}
fn visit(root: &Path, out: &mut Vec<PathBuf>, depth: usize) {
    if depth > 32 || out.len() >= 10000 {
        return;
    }
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for e in entries.flatten() {
        if out.len() >= 10000 {
            break;
        }
        let Ok(kind) = e.file_type() else { continue };
        if kind.is_dir() {
            visit(&e.path(), out, depth + 1);
        } else if kind.is_file() && !partial(&e.path()) {
            out.push(e.path());
        }
    }
}
impl Auto {
    pub fn start(root: PathBuf) -> std::io::Result<Self> {
        Self::watch(root, SETTLE)
    }
    fn watch(root: PathBuf, settle: Duration) -> std::io::Result<Self> {
        let cancel = Arc::new(AtomicBool::new(false));
        let flag = cancel.clone();
        let (tx, rx) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("download-monitor".into())
            .spawn(move || {
                let mut known: HashMap<PathBuf, ((u64, SystemTime), Instant, bool)> =
                    HashMap::new();
                // Files already in the folder are the baseline, not new downloads.
                let mut baseline = true;
                while !flag.load(Ordering::Relaxed) {
                    let mut paths = Vec::new();
                    visit(&root, &mut paths, 0);
                    let mut current = std::collections::HashSet::new();
                    let mut ready = Vec::new();
                    for path in paths {
                        let Ok(m) = fs::metadata(&path) else { continue };
                        let Ok(time) = m.modified() else { continue };
                        current.insert(path.clone());
                        let stamp = (m.len(), time);
                        // Something written in the last few seconds may still be downloading.
                        let settled = baseline && time.elapsed().is_ok_and(|age| age >= settle);
                        let e =
                            known
                                .entry(path.clone())
                                .or_insert((stamp, Instant::now(), settled));
                        if e.0 != stamp {
                            *e = (stamp, Instant::now(), false);
                        }
                        if !e.2 && e.1.elapsed() >= settle && ready.len() < 32 {
                            ready.push(path);
                        }
                    }
                    known.retain(|p, _| current.contains(p));
                    baseline = false;
                    if !ready.is_empty() {
                        match tx.try_send(ready.clone()) {
                            Ok(()) => {
                                for path in ready {
                                    if let Some(e) = known.get_mut(&path) {
                                        e.2 = true;
                                    }
                                }
                            }
                            Err(mpsc::TrySendError::Disconnected(_)) => return,
                            Err(_) => (),
                        }
                    }
                    for _ in 0..30 {
                        if flag.load(Ordering::Relaxed) {
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
            })?;
        Ok(Self { files: rx, cancel })
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn aria2_sidecar_preserves_filename_case() {
        let dir = std::env::temp_dir().join(format!("strazh-partial-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("Download.ISO");
        let sidecar = dir.join("Download.ISO.aria2");
        std::fs::write(&sidecar, b"in progress").unwrap();
        assert!(super::partial(&file));
        std::fs::remove_file(sidecar).unwrap();
        assert!(!super::partial(&file));
        std::fs::remove_dir(dir).unwrap();
    }
    #[test]
    fn existing_files_are_baseline_but_fresh_ones_are_scanned() {
        use std::time::{Duration, SystemTime};
        let dir = std::env::temp_dir().join(format!("strazh-auto-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let old = dir.join("old.zip");
        std::fs::write(&old, b"downloaded last week").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&old)
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(3600))
            .unwrap();
        let fresh = dir.join("fresh.zip");
        std::fs::write(&fresh, b"still arriving").unwrap();
        let auto = super::Auto::watch(dir.clone(), Duration::from_secs(1)).unwrap();
        let batch = auto.files.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(batch, vec![fresh]);
        drop(auto);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn partials() {
        assert!(super::partial(std::path::Path::new("x.crdownload")));
        assert!(!super::partial(std::path::Path::new("x.pdf")));
    }
}
