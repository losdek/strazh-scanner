pub const T_DATA: u32 = 0;
pub const T_WINDOWS_PROGRAM: u32 = 1;
pub const T_LINUX_PROGRAM: u32 = 2;
pub const T_MAC_PROGRAM: u32 = 3;
pub const T_PDF: u32 = 4;
pub const T_ZIP: u32 = 5;
pub const T_PNG: u32 = 6;
pub const T_JPEG: u32 = 7;
pub const T_GIF: u32 = 8;
pub const T_SCRIPT: u32 = 9;
pub const T_TEXT: u32 = 10;
pub const T_RAR: u32 = 11;
pub const T_7Z: u32 = 12;
pub const T_GZIP: u32 = 13;
pub const T_OFFICE_LEGACY: u32 = 14;
pub const T_WASM: u32 = 15;
pub const T_EMPTY: u32 = 16;
pub const T_JAVA_OR_MAC: u32 = 17;

pub fn sniff_bytes(b: &[u8]) -> u32 {
    let starts = |p: &[u8]| b.len() >= p.len() && &b[..p.len()] == p;
    if b.is_empty() {
        return T_EMPTY;
    }
    if starts(b"MZ") {
        return T_WINDOWS_PROGRAM;
    }
    if starts(b"\x7fELF") {
        return T_LINUX_PROGRAM;
    }
    if starts(&[0xCF, 0xFA, 0xED, 0xFE])
        || starts(&[0xCE, 0xFA, 0xED, 0xFE])
        || starts(&[0xFE, 0xED, 0xFA, 0xCF])
    {
        return T_MAC_PROGRAM;
    }
    if starts(&[0xCA, 0xFE, 0xBA, 0xBE]) {
        return T_JAVA_OR_MAC;
    }
    if starts(b"%PDF") {
        return T_PDF;
    }
    if starts(b"PK\x03\x04") || starts(b"PK\x05\x06") {
        return T_ZIP;
    }
    if starts(b"\x89PNG") {
        return T_PNG;
    }
    if starts(&[0xFF, 0xD8, 0xFF]) {
        return T_JPEG;
    }
    if starts(b"GIF8") {
        return T_GIF;
    }
    if starts(b"Rar!") {
        return T_RAR;
    }
    if starts(&[b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C]) {
        return T_7Z;
    }
    if starts(&[0x1F, 0x8B]) {
        return T_GZIP;
    }
    if starts(&[0xD0, 0xCF, 0x11, 0xE0]) {
        return T_OFFICE_LEGACY;
    }
    if starts(b"\0asm") {
        return T_WASM;
    }
    if starts(b"#!") {
        return T_SCRIPT;
    }
    // Text if the sample is valid UTF-8 (allowing a cut-off last character)
    // and has no control bytes other than tabs and line breaks.
    let sample = &b[..b.len().min(4096)];
    let text_ok = match std::str::from_utf8(sample) {
        Ok(_) => true,
        Err(e) => e.error_len().is_none() && e.valid_up_to() + 4 > sample.len(),
    };
    if text_ok
        && !sample
            .iter()
            .any(|&c| c < 0x20 && c != b'\t' && c != b'\n' && c != b'\r' && c != 0x0C)
    {
        return T_TEXT;
    }
    T_DATA
}
