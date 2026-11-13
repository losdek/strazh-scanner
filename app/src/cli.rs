use crate::{json, scan};
use scan_engine::{Config, Mode};
use std::{
    ffi::OsString,
    path::PathBuf,
    sync::{atomic::Ordering, Arc},
};
pub fn run(args: impl IntoIterator<Item = OsString>) -> Result<i32, String> {
    let mut args = args.into_iter();
    let mut config = Config::default();
    let mut workers = 2;
    let mut paths = Vec::new();
    let mut quiet = false;
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--scan") => (),
            Some("--mode") => {
                let arg = args.next().ok_or("Missing mode")?;
                config.mode = Mode::parse(&arg.to_string_lossy())
                    .ok_or("Mode must be hashes, static, or clam")?;
            }
            Some("--workers") => {
                workers = args
                    .next()
                    .ok_or("Missing worker count")?
                    .to_string_lossy()
                    .parse::<usize>()
                    .map_err(|_| "Invalid worker count")?;
                if !(1..=4).contains(&workers) {
                    return Err("Workers must be between 1 and 4".into());
                }
            }
            Some("--signatures") => {
                let path = args.next().ok_or("Missing signature-list path")?;
                let mut db = (*scan_engine::bundled_database()).clone();
                db.extend(
                    scan_engine::load_database(&PathBuf::from(path)).map_err(|e| e.to_string())?,
                );
                config.database = Arc::new(db);
            }
            Some("--quiet") => quiet = true,
            Some("--help") => {
                println!("vt-scan [--scan] [--mode hashes|static|clam] [--workers 1..4] [--signatures SHA256_LIST] [--quiet] PATH...\nOutputs JSON lines. Exit: 0 no findings, 1 match/review, 2 incomplete/error. Clam mode requires a local clamd daemon.");
                return Ok(0);
            }
            Some("--") => {
                paths.extend(args.map(PathBuf::from));
                break;
            }
            Some(s) if s.starts_with('-') => return Err(format!("Unknown option: {s}")),
            _ => paths.push(PathBuf::from(arg)),
        }
    }
    if paths.is_empty() {
        return Err("Choose at least one file/folder. Use --help for options.".into());
    }
    if config.mode == Mode::Clam && config.clam_socket.is_none() {
        return Err("ClamAV is not available: start a local clamd daemon (Linux: VIRUSTOTAL_CLAMD_SOCKET=unix socket; Windows: VIRUSTOTAL_CLAMD_TCP=127.0.0.1:port).".into());
    }
    let session = scan::start(paths, config, workers).map_err(|e| e.to_string())?;
    while let Ok(event) = session.events.recv() {
        match event {
            scan::Event::Row(r) => {
                if !quiet {
                    println!("{}", json::report(&r));
                }
            }
            scan::Event::Done => break,
        }
    }
    println!("{}", json::snapshot(&session, true, &[]));
    Ok(if session.counters.errors.load(Ordering::Relaxed) > 0 {
        2
    } else if session.counters.matches.load(Ordering::Relaxed)
        + session.counters.reviews.load(Ordering::Relaxed)
        > 0
    {
        1
    } else {
        0
    })
}
pub fn main() {
    match run(std::env::args_os().skip(1)) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2)
        }
    }
}
