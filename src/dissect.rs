use anyhow::{Context, Result};
use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use walkdir::WalkDir;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Debug, Default, Clone)]
pub struct DissectedSetup {
    pub archive_password: Option<String>,
    pub registry_entries: Vec<RegistryEntry>,
    pub dir_entries: Vec<String>,
    pub icon_entries: Vec<IconEntry>,
    pub safe_post_run: Vec<PostRunCommand>,
    pub has_unarc_payload: bool,
}

#[derive(Debug, Clone)]
pub struct RegistryEntry {
    pub root: String,
    pub subkey: String,
    pub value_name: String,
    pub value_type: String,
    pub value_data: String,
}

#[derive(Debug, Clone)]
pub struct IconEntry {
    pub name: String,
    pub filename: String,
    pub working_dir: String,
}

#[derive(Debug, Clone)]
pub struct PostRunCommand {
    pub filename: String,
    pub parameters: String,
}

fn env_dir(var: &str, fallback: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| fallback.to_string())
}

fn user_docs_dir() -> PathBuf {
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        return PathBuf::from(profile).join("Documents");
    }
    PathBuf::from(r"C:\Users\Public\Documents")
}

fn common_docs_dir() -> PathBuf {
    if let Some(public) = std::env::var_os("PUBLIC") {
        return PathBuf::from(public).join("Documents");
    }
    PathBuf::from(r"C:\Users\Public\Documents")
}

/// Expands Inno Setup directory constants (`{app}`, `{userdocs}`, `{localappdata}`, etc.).
pub fn expand_inno_tokens(raw: &str, target_app_dir: &Path, work_dir: &Path) -> String {
    let app_str = target_app_dir.display().to_string();
    let tmp_str = work_dir.display().to_string();
    let docs_str = user_docs_dir().display().to_string();
    let cdocs_str = common_docs_dir().display().to_string();
    let appdata = env_dir("APPDATA", r"C:\Users\Default\AppData\Roaming");
    let localappdata = env_dir("LOCALAPPDATA", r"C:\Users\Default\AppData\Local");
    let progdata = env_dir("PROGRAMDATA", r"C:\ProgramData");
    let windir = env_dir("WINDIR", r"C:\Windows");
    let sysdir = format!(r"{windir}\System32");

    let mut out = raw.to_string();
    let pairs = [
        ("{app}", app_str.as_str()),
        ("{APP}", app_str.as_str()),
        ("{tmp}", tmp_str.as_str()),
        ("{TMP}", tmp_str.as_str()),
        ("{userdocs}", docs_str.as_str()),
        ("{commondocs}", cdocs_str.as_str()),
        ("{userappdata}", appdata.as_str()),
        ("{localappdata}", localappdata.as_str()),
        ("{commonappdata}", progdata.as_str()),
        ("{win}", windir.as_str()),
        ("{sys}", sysdir.as_str()),
    ];
    for (tok, val) in pairs {
        if out.contains(tok) {
            out = out.replace(tok, val);
        }
    }
    out
}

/// Unpacks setup.exe's embedded files (`{tmp}`, `{app}`, `{userdocs}`, etc.)
/// and parses `install_script.iss` for passwords, `[Dirs]`, `[Registry]`, `[Icons]`, and safe `[Run]` tasks.
pub fn dissect_inno_setup(
    innounp_exe: &Path,
    setup_exe: &Path,
    work_dir: &Path,
) -> Result<DissectedSetup> {
    fs::create_dir_all(work_dir)?;

    let out = Command::new(innounp_exe)
        .args([
            "-x",
            "-y",
            &format!("-d{}", work_dir.display()),
            &setup_exe.display().to_string(),
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .with_context(|| format!("Failed to invoke innounp at {}", innounp_exe.display()))?;

    let mut result = DissectedSetup::default();

    if !out.status.success() {
        return Ok(result);
    }

    // Flatten FreeArc/CLS plugins from `{tmp}` (or nested subdirs) into `work_dir`
    for entry in WalkDir::new(work_dir).max_depth(4).into_iter().flatten() {
        if !entry.file_type().is_file() {
            continue;
        }
        let src = entry.path();
        if src.parent() == Some(work_dir) {
            continue;
        }
        let Some(name_os) = src.file_name() else {
            continue;
        };
        let lower = name_os.to_string_lossy().to_ascii_lowercase();
        let in_tmp = src
            .to_string_lossy()
            .to_ascii_lowercase()
            .contains("{tmp}");
        let is_plugin = lower == "unarc.dll"
            || lower == "arc.ini"
            || lower == "cls.ini"
            || lower.starts_with("cls-")
            || lower.starts_with("srep")
            || lower.starts_with("lolz")
            || lower.starts_with("xtool")
            || lower.starts_with("oo2core")
            || lower.starts_with("facompress")
            || lower.starts_with("zlib")
            || lower.starts_with("rz");
        if in_tmp || is_plugin {
            let dst_name = if lower == "unarc.dll" {
                std::ffi::OsStr::new("unarc.dll")
            } else {
                name_os
            };
            let _ = fs::copy(src, work_dir.join(dst_name));
        }
    }

    result.has_unarc_payload = work_dir.join("unarc.dll").exists()
        || work_dir.join("arc.ini").exists()
        || work_dir.join("cls-srep.dll").exists()
        || work_dir.join("cls-lolz.dll").exists();

    let iss_path = work_dir.join("install_script.iss");
    if iss_path.exists() {
        if let Ok(bytes) = fs::read(&iss_path) {
            let script = if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
                let u16s: Vec<u16> = bytes[2..]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                String::from_utf16_lossy(&u16s)
            } else {
                String::from_utf8_lossy(&bytes).into_owned()
            };
            parse_install_script(&script, &mut result);
        }
    }

    Ok(result)
}

fn copy_tree_filtered(src_root: &Path, dst_root: &Path) -> usize {
    if !src_root.is_dir() {
        return 0;
    }
    let mut copied = 0usize;
    for entry in WalkDir::new(src_root).into_iter().flatten() {
        if !entry.file_type().is_file() {
            continue;
        }
        let src = entry.path();
        let Ok(rel) = src.strip_prefix(src_root) else {
            continue;
        };
        let lower_name = src
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        if lower_name.starts_with("unins")
            || lower_name.ends_with(".url")
            || lower_name == "quicksfv.exe"
            || lower_name == "quicksfv.ini"
        {
            continue;
        }
        let dst = dst_root.join(rel);
        if let Some(parent) = dst.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if fs::copy(src, &dst).is_ok() {
            copied += 1;
        }
    }
    copied
}

/// Copies embedded game/profile files extracted from `setup.exe` (`{app}`, `{userdocs}`,
/// `{userappdata}`, `{localappdata}`, `{commonappdata}`) to their real Windows destinations.
pub fn deploy_embedded_setup_files(work_dir: &Path, target_app_dir: &Path) -> usize {
    let mut total = 0usize;
    let mappings: [(&str, PathBuf); 6] = [
        ("{app}", target_app_dir.to_path_buf()),
        ("{userdocs}", user_docs_dir()),
        ("{commondocs}", common_docs_dir()),
        ("{userappdata}", PathBuf::from(env_dir("APPDATA", ""))),
        ("{localappdata}", PathBuf::from(env_dir("LOCALAPPDATA", ""))),
        ("{commonappdata}", PathBuf::from(env_dir("PROGRAMDATA", ""))),
    ];

    if let Ok(rd) = fs::read_dir(work_dir) {
        for entry in rd.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let dir_name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            for (token, dst) in &mappings {
                if dir_name == *token && !dst.as_os_str().is_empty() {
                    total += copy_tree_filtered(&path, dst);
                }
            }
        }
    }
    total
}

/// Creates all directories declared in `install_script.iss` `[Dirs]` (e.g., `Documents\My Games\...`).
pub fn create_script_dirs(dirs: &[String], target_app_dir: &Path, work_dir: &Path) -> usize {
    let mut created = 0usize;
    for raw in dirs {
        let expanded = expand_inno_tokens(raw, target_app_dir, work_dir);
        let p = PathBuf::from(expanded.trim());
        if !p.as_os_str().is_empty() && !p.to_string_lossy().contains('{') {
            if fs::create_dir_all(&p).is_ok() {
                created += 1;
            }
        }
    }
    created
}

fn parse_install_script(script: &str, out: &mut DissectedSetup) {
    let re_pwd = Regex::new(r#"(?i)ISArcExtract\([^;]*?'([^']{2,64})'\s*,\s*false"#).ok();
    if let Some(re) = re_pwd {
        if let Some(cap) = re.captures(script) {
            if let Some(m) = cap.get(1) {
                let candidate = m.as_str().trim();
                if !candidate.is_empty() && !candidate.contains('{') {
                    out.archive_password = Some(candidate.to_string());
                }
            }
        }
    }

    let mut section = "";
    let re_kv = Regex::new(
        r#"(?i)(Root|Subkey|ValueType|ValueName|ValueData|Filename|Parameters|Name|WorkingDir)\s*:\s*("([^"]*)"|([^;\r\n]+))"#,
    )
    .unwrap();

    for raw_line in script.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line;
            continue;
        }

        if section.eq_ignore_ascii_case("[Dirs]") {
            for cap in re_kv.captures_iter(line) {
                if cap[1].eq_ignore_ascii_case("name") {
                    let v = cap
                        .get(3)
                        .or_else(|| cap.get(4))
                        .map(|m| m.as_str().trim().to_string())
                        .unwrap_or_default();
                    if !v.is_empty() {
                        out.dir_entries.push(v);
                    }
                }
            }
        } else if section.eq_ignore_ascii_case("[Registry]") {
            let mut root = String::new();
            let mut subkey = String::new();
            let mut value_type = String::from("string");
            let mut value_name = String::new();
            let mut value_data = String::new();

            for cap in re_kv.captures_iter(line) {
                let k = cap[1].to_ascii_lowercase();
                let v = cap
                    .get(3)
                    .or_else(|| cap.get(4))
                    .map(|m| m.as_str().trim().to_string())
                    .unwrap_or_default();
                match k.as_str() {
                    "root" => root = v,
                    "subkey" => subkey = v,
                    "valuetype" => value_type = v,
                    "valuename" => value_name = v,
                    "valuedata" => value_data = v,
                    _ => {}
                }
            }
            if !root.is_empty() && !subkey.is_empty() {
                out.registry_entries.push(RegistryEntry {
                    root,
                    subkey,
                    value_name,
                    value_type,
                    value_data,
                });
            }
        } else if section.eq_ignore_ascii_case("[Icons]") {
            let mut name = String::new();
            let mut filename = String::new();
            let mut working_dir = String::new();
            for cap in re_kv.captures_iter(line) {
                let k = cap[1].to_ascii_lowercase();
                let v = cap
                    .get(3)
                    .or_else(|| cap.get(4))
                    .map(|m| m.as_str().trim().to_string())
                    .unwrap_or_default();
                match k.as_str() {
                    "name" => name = v,
                    "filename" => filename = v,
                    "workingdir" => working_dir = v,
                    _ => {}
                }
            }
            let lower_fn = filename.to_ascii_lowercase();
            if lower_fn.ends_with(".exe")
                && !lower_fn.contains("unins")
                && !name.is_empty()
                && (name.to_ascii_lowercase().contains("desktop")
                    || out.icon_entries.is_empty())
            {
                out.icon_entries.push(IconEntry {
                    name,
                    filename,
                    working_dir,
                });
            }
        } else if section.eq_ignore_ascii_case("[Run]") {
            let mut filename = String::new();
            let mut parameters = String::new();
            for cap in re_kv.captures_iter(line) {
                let k = cap[1].to_ascii_lowercase();
                let v = cap
                    .get(3)
                    .or_else(|| cap.get(4))
                    .map(|m| m.as_str().trim().to_string())
                    .unwrap_or_default();
                match k.as_str() {
                    "filename" => filename = v,
                    "parameters" => parameters = v,
                    _ => {}
                }
            }
            let lower = filename.to_ascii_lowercase();
            let is_blocked = lower.starts_with("http")
                || lower.contains("vcredist")
                || lower.contains("dxwebsetup")
                || lower.contains("dxsetup")
                || lower.contains("directx")
                || lower.contains("dotnet")
                || lower.contains("openal")
                || lower.contains("physx")
                || lower.contains("quicksfv")
                || lower.contains("unins");
            let is_safe_patcher = lower.contains("xdelta")
                || lower.contains("hdiff")
                || lower.contains("hpatch")
                || lower.contains("vpatch")
                || lower.contains("bsdiff")
                || lower.contains("bink")
                || lower.contains("radvideo")
                || lower.contains("quickbms")
                || lower.contains("oggdec")
                || lower.contains("flac")
                || lower.contains("unpack")
                || lower.contains("repack");

            if is_safe_patcher && !is_blocked {
                out.safe_post_run.push(PostRunCommand { filename, parameters });
            }
        }
    }
}

/// Applies `[Registry]` keys with proper 32-bit `WOW6432Node` (`/reg:32`) + 64-bit (`/reg:64`) routing
/// so 32-bit games (e.g. Far Cry 3, Blood Dragon, older Ubisoft/EA titles) always see their keys.
pub fn apply_registry_entries(
    entries: &[RegistryEntry],
    target_app_dir: &Path,
    work_dir: &Path,
) -> usize {
    let mut applied = 0usize;

    for e in entries {
        let upper_root = e.root.to_ascii_uppercase();
        let (hive, reg_views): (&str, &[&str]) = match upper_root.as_str() {
            "HKLM32" => ("HKLM", &["/reg:32"]),
            "HKLM64" => ("HKLM", &["/reg:64"]),
            "HKLM" => ("HKLM", &["/reg:32", "/reg:64"]),
            "HKCU32" => ("HKCU", &["/reg:32"]),
            "HKCU64" => ("HKCU", &["/reg:64"]),
            "HKCU" => ("HKCU", &["/reg:32", "/reg:64"]),
            _ => continue,
        };
        let reg_type = match e.value_type.to_ascii_lowercase().as_str() {
            "dword" => "REG_DWORD",
            "expandsz" => "REG_EXPAND_SZ",
            "none" => continue,
            _ => "REG_SZ",
        };
        let subkey = expand_inno_tokens(&e.subkey, target_app_dir, work_dir);
        let key_path = format!(r"{hive}\{subkey}");
        let mut data = expand_inno_tokens(&e.value_data, target_app_dir, work_dir);
        if reg_type == "REG_DWORD" && data.starts_with('$') {
            data = format!("0x{}", &data[1..]);
        }

        let mut wrote_any = false;
        for &view in reg_views {
            let mut cmd = Command::new("reg");
            cmd.args(["add", &key_path, "/t", reg_type, "/d", &data, "/f", view]);
            if e.value_name.is_empty() {
                cmd.arg("/ve");
            } else {
                cmd.args(["/v", &e.value_name]);
            }
            if cmd
                .creation_flags(CREATE_NO_WINDOW)
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                wrote_any = true;
            }
        }
        if wrote_any {
            applied += 1;
        }
    }
    applied
}

/// Creates Desktop `.lnk` shortcuts for parsed Inno `[Icons]` game executables.
pub fn create_desktop_shortcuts(icons: &[IconEntry], target_app_dir: &Path) -> usize {
    let app_str = target_app_dir.display().to_string();
    let mut created = 0usize;
    let mut seen_targets = HashSet::new();

    for icon in icons {
        let exe_path = PathBuf::from(icon.filename.replace("{app}", &app_str));
        if !exe_path.exists() || !seen_targets.insert(exe_path.clone()) {
            continue;
        }
        let clean_name = icon
            .name
            .rsplit('\\')
            .next()
            .unwrap_or("Game")
            .replace([':', '*', '?', '"', '<', '>', '|'], "")
            .trim()
            .to_string();
        if clean_name.is_empty() {
            continue;
        }
        let work_dir = if icon.working_dir.is_empty() {
            exe_path
                .parent()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| app_str.clone())
        } else {
            icon.working_dir.replace("{app}", &app_str)
        };

        let esc_name = clean_name.replace('\'', "''");
        let esc_target = exe_path.display().to_string().replace('\'', "''");
        let esc_work = work_dir.replace('\'', "''");

        let ps = format!(
            "$ws = New-Object -ComObject WScript.Shell; \
             $lnk = $ws.CreateShortcut([Environment]::GetFolderPath('Desktop') + '\\{esc_name}.lnk'); \
             $lnk.TargetPath = '{esc_target}'; \
             $lnk.WorkingDirectory = '{esc_work}'; \
             $lnk.Save()"
        );
        if Command::new("powershell")
            .args(["-NoProfile", "-Command", &ps])
            .creation_flags(CREATE_NO_WINDOW)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            created += 1;
        }
    }
    created
}
