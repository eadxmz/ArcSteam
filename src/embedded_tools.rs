use std::fs;
use std::path::PathBuf;

include!(concat!(env!("OUT_DIR"), "/embedded_tools_gen.rs"));

/// Directory where ArcSteam auto-extracts its built-in helper engines.
pub fn bin_dir() -> PathBuf {
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        let dir = PathBuf::from(local).join("ArcSteam").join("bin");
        let _ = fs::create_dir_all(&dir);
        return dir;
    }
    let dir = std::env::temp_dir().join("ArcSteamBin");
    let _ = fs::create_dir_all(&dir);
    dir
}

/// Optional user-override tools/ folder next to arcsteam.exe.
pub fn user_tools_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("tools")))
        .unwrap_or_else(|| PathBuf::from("tools"))
}

/// Extracts all helper binaries baked into arcsteam.exe into %LOCALAPPDATA%\ArcSteam\bin\.
/// Uses exact byte comparison (not just file length, since MSVC PE padding can keep lengths identical!).
pub fn ensure_extracted() -> usize {
    let dir = bin_dir();
    let mut ready = 0usize;
    for &(name, bytes) in EMBEDDED_TOOLS {
        if bytes.is_empty() {
            continue;
        }
        let target = dir.join(name);
        let up_to_date = fs::read(&target)
            .map(|existing| existing.as_slice() == bytes)
            .unwrap_or(false);
        if up_to_date || fs::write(&target, bytes).is_ok() {
            ready += 1;
        }
    }
    ready
}

/// Resolves a helper binary: prefers user override in tools/ next to arcsteam.exe,
/// otherwise uses the built-in binary extracted from arcsteam.exe.
pub fn resolve_tool(name: &str) -> PathBuf {
    let override_path = user_tools_dir().join(name);
    if override_path.exists() {
        return override_path;
    }
    bin_dir().join(name)
}

pub fn embedded_count() -> usize {
    EMBEDDED_TOOLS.len()
}
