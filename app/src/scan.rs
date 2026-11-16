use scan_engine::{Config, Report, Status, BUFFER_SIZE};
use std::{
    fs::{self, ReadDir},
    io,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, Receiver, SyncSender},
        Arc, Mutex,
    },
    thread,
    time::Instant,
};
#[derive(Default)]
pub struct Counters {
    pub done: AtomicU64,
    pub bytes: AtomicU64,
    pub matches: AtomicU64,
    pub reviews: AtomicU64,
    pub errors: AtomicU64,
    pub skipped: AtomicU64,
}
pub enum Event {
    Row(Report),
    Done,
}
pub struct Session {
    pub cancel: Arc<AtomicBool>,
    pub counters: Arc<Counters>,
    pub events: Receiver<Event>,
    pub started: Instant,
    pub workers: usize,
}
fn send(report: Report, tx: &SyncSender<Event>, counts: &Counters) -> bool {
    counts.done.fetch_add(1, Ordering::Relaxed);
    match report.status {
        Status::Match => {
            counts.matches.fetch_add(1, Ordering::Relaxed);
        }
        Status::Review => {
            counts.reviews.fetch_add(1, Ordering::Relaxed);
        }
        _ => (),
    }
    if report.incomplete {
        counts.errors.fetch_add(1, Ordering::Relaxed);
    }
    tx.send(Event::Row(report)).is_ok()
}
fn enumerate(
    roots: Vec<PathBuf>,
    jobs: &SyncSender<PathBuf>,
    events: &SyncSender<Event>,
    cancel: &AtomicBool,
    counts: &Counters,
) {
    // Keep directory iterators, not a list of every descendant in memory.
    let mut roots = roots.into_iter();
    let mut stack: Vec<ReadDir> = Vec::new();
    loop {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let path = if let Some(dir) = stack.last_mut() {
            match dir.next() {
                Some(Ok(e)) => e.path(),
                Some(Err(e)) => {
                    if !send(
                        Report::error(PathBuf::from("Directory entry"), e),
                        events,
                        counts,
                    ) {
                        break;
                    }
                    continue;
                }
                None => {
                    stack.pop();
                    continue;
                }
            }
        } else if let Some(root) = roots.next() {
            root
        } else {
            break;
        };
        match fs::symlink_metadata(&path) {
            Ok(m) if m.is_dir() => {
                if stack.len() >= 128 {
                    let _ = send(
                        Report::error(path, "Directory nesting exceeds 128; subtree skipped"),
                        events,
                        counts,
                    );
                    continue;
                }
                match fs::read_dir(&path) {
                    Ok(dir) => stack.push(dir),
                    Err(e) => {
                        if !send(Report::error(path, e), events, counts) {
                            break;
                        }
                    }
                }
            }
            Ok(m) if m.is_file() => {
                // Blocks while the workers are busy. On cancel they keep draining
                // the queue, so this returns promptly instead of polling.
                if jobs.send(path).is_err() {
                    return;
                }
            }
            Ok(_) => {
                counts.skipped.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                if !send(Report::error(path, e), events, counts) {
                    break;
                }
            }
        }
    }
}
pub fn start(paths: Vec<PathBuf>, config: Config, workers: usize) -> io::Result<Session> {
    let workers = workers.clamp(1, 4);
    let cancel = Arc::new(AtomicBool::new(false));
    let counters = Arc::new(Counters::default());
    let (events_tx, events_rx) = mpsc::sync_channel(64);
    let flag = cancel.clone();
    let counts = counters.clone();
    thread::Builder::new()
        .name("scan-dispatch".into())
        .spawn(move || {
            let (jobs_tx, jobs_rx) = mpsc::sync_channel::<PathBuf>(32);
            let jobs = Mutex::new(jobs_rx);
            thread::scope(|scope| {
                for _ in 0..workers {
                    let jobs = &jobs;
                    let flag = &flag;
                    let counts = &counts;
                    let events = &events_tx;
                    let config = &config;
                    scope.spawn(move || {
                        let mut buffer = vec![0u8; BUFFER_SIZE];
                        loop {
                            let job = jobs.lock().unwrap_or_else(|e| e.into_inner()).recv();
                            let Ok(path) = job else { break };
                            // After cancel, drop queued jobs so the enumerator never
                            // blocks on a full queue; it stops at its next check.
                            if flag.load(Ordering::Relaxed) {
                                continue;
                            }
                            let result = scan_engine::inspect(
                                &path,
                                config,
                                flag,
                                &counts.bytes,
                                &mut buffer,
                            );
                            let report = match result {
                                Ok(r) => r,
                                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                                Err(e) => Report::error(path, e),
                            };
                            if !send(report, events, counts) {
                                // Nobody is listening any more: stop the whole scan.
                                flag.store(true, Ordering::Relaxed);
                            }
                        }
                    });
                }
                enumerate(paths, &jobs_tx, &events_tx, &flag, &counts);
                drop(jobs_tx);
            });
            let _ = events_tx.send(Event::Done);
        })?;
    Ok(Session {
        cancel,
        counters,
        events: events_rx,
        started: Instant::now(),
        workers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[test]
    fn bounded_queue_cancel_and_directory_errors() {
        let path = std::env::temp_dir().join(format!("vt-queue-test-{}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        for i in 0..200 {
            fs::write(path.join(format!("{i}.txt")), b"hello").unwrap();
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(&path, path.join("loop")).unwrap();
        let session = start(vec![path.clone()], Config::default(), 2).unwrap();
        let mut rows = 0;
        while let Event::Row(_) = session.events.recv_timeout(Duration::from_secs(5)).unwrap() {
            rows += 1;
        }
        assert_eq!(rows, 200);
        #[cfg(unix)]
        assert_eq!(session.counters.skipped.load(Ordering::Relaxed), 1);
        let session = start(vec![path.clone()], Config::default(), 4).unwrap();
        // Fill both the result queue and the work queue before cancelling.
        thread::sleep(Duration::from_millis(100));
        session.cancel.store(true, Ordering::Relaxed);
        loop {
            if matches!(
                session.events.recv_timeout(Duration::from_secs(3)).unwrap(),
                Event::Done
            ) {
                break;
            }
        }
        let missing = start(vec![path.join("missing")], Config::default(), 1).unwrap();
        loop {
            if matches!(
                missing.events.recv_timeout(Duration::from_secs(3)).unwrap(),
                Event::Done
            ) {
                break;
            }
        }
        assert_eq!(missing.counters.errors.load(Ordering::Relaxed), 1);
        fs::remove_dir_all(path).unwrap();
    }
}
