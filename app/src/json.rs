use scan_engine::Report;
use std::sync::atomic::Ordering;
pub fn string(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < ' ' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
pub fn report(r: &Report) -> String {
    format!(
        "{{\"path\":{},\"size\":{},\"kind\":{},\"hash\":{},\"status\":{},\"incomplete\":{},\"details\":[{}]}}",
        string(&r.path.to_string_lossy()),
        r.bytes,
        string(scan_engine::file_type(r.kind)),
        string(&r.hash),
        string(r.status.as_str()),
        r.incomplete,
        r.details
            .iter()
            .map(|s| string(s))
            .collect::<Vec<_>>()
            .join(",")
    )
}
pub fn snapshot(session: &crate::scan::Session, done: bool, rows: &[String]) -> String {
    let c = &session.counters;
    format!("{{\"event\":\"scan\",\"done\":{done},\"cancelled\":{},\"files\":{},\"bytes\":{},\"matches\":{},\"reviews\":{},\"errors\":{},\"skipped\":{},\"seconds\":{:.3},\"workers\":{},\"rows\":[{}]}}",session.cancel.load(Ordering::Relaxed),c.done.load(Ordering::Relaxed),c.bytes.load(Ordering::Relaxed),c.matches.load(Ordering::Relaxed),c.reviews.load(Ordering::Relaxed),c.errors.load(Ordering::Relaxed),c.skipped.load(Ordering::Relaxed),session.started.elapsed().as_secs_f64(),session.workers,rows.join(","))
}
#[cfg(test)]
mod tests {
    #[test]
    fn escaping() {
        assert_eq!(super::string("a\"\\\n\0é"), "\"a\\\"\\\\\\n\\u0000é\"");
    }
}
