//! Only the view remains HTML; file access and analysis run in native Rust.
pub fn html() -> String {
    include_str!("../ui/index.html")
        .replace(
            "<!--STYLES-->",
            &format!(
                "<style>{}{}</style>",
                include_str!("../ui/src/fonts.css"),
                include_str!("../ui/src/style.css")
            ),
        )
        .replace(
            "<!--SCRIPTS-->",
            &format!("<script>{}</script>", include_str!("../ui/src/main.js")),
        )
}
#[cfg(test)]
mod tests {
    #[test]
    fn embedded_view_has_only_native_scan_controls() {
        let html = super::html();
        assert!(!html.contains("<!--STYLES-->"));
        assert!(html.contains("messageHandlers"));
        assert!(!html.contains("new Worker"));
        assert!(!html.contains("WebAssembly"));
        assert!(!html.contains("urlForm"));
        assert!(html.contains("connect-src 'none'"));
    }
}
