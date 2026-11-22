use anyhow::{Context, Result};
use regex::Regex;
use std::fs;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Debug, Default, Clone)]
pub struct DissectedSetup {
    pub work_dir: PathBuf,
    pub archive_password: Option<String>,
    pub registry_entries: Vec<RegistryEntry>,
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
pub struct PostRunCommand {
    pub filename: String,
    pub parameters: String,
}

/// Unpacks setup.exe's embedded {tmp} plugins (unarc.dll, cls-srep, cls-lolz, xtool, arc.ini)
/// and parses install_script.iss for passwords, [Registry], and safe [Run] post-install steps.
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

    let mut result = DissectedSetup {
        work_dir: work_dir.to_path_buf(),
        ..Default::default()
    };

    if !out.status.success() {
        return Ok(result);
    }

    // Flatten {tmp} binaries into work_dir so unarc.exe finds cls-*.dll, xtool.exe, arc.ini immediately.
    let tmp_sub = work_dir.join("{tmp}");
    if tmp_sub.is_dir() {
        if let Ok(read_dir) = fs::read_dir(&tmp_sub) {
            for entry in read_dir.flatten() {
                let src = entry.path();
                if src.is_file() {
                    if let Some(name) = src.file_name() {
                        let _ = fs::copy(&src, work_dir.join(name));
                    }
                }
            }
        }
    }

    result.has_unarc_payload = work_dir.join("unarc.dll").exists()
        || work_dir.join("arc.ini").exists()
        || work_dir.join("cls-srep.dll").exists()
        || work_dir.join("cls-lolz.dll").exists();

    let iss_path = work_dir.join("install_script.iss");
    if iss_path.exists() {
        if let Ok(script) = fs::read_to_string(&iss_path) {
            parse_install_script(&script, &mut result);
        }
    }

    Ok(result)
}

fn parse_install_script(script: &str, out: &mut DissectedSetup) {
    // 1. Extract FreeArc password if present in ISArcExtract / ArcExtract calls
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

    // 2. Parse [Registry] and safe [Run] sections
    let mut section = "";
    let re_kv = Regex::new(r#"(?i)(Root|Subkey|ValueType|ValueName|ValueData|Filename|Parameters)\s*:\s*("([^"]*)"|([^;\r\n]+))"#).unwrap();

    for raw_line in script.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line;
            continue;
        }

        if section.eq_ignore_ascii_case("[Registry]") {
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
            let is_safe_patcher = (lower.contains("xdelta")
                || lower.contains("bink")
                || lower.contains("hpatch")
                || lower.contains("quickbms")
                || lower.contains("unpack"))
                && !lower.starts_with("http")
                && !lower.contains("vcredist")
                && !lower.contains("dxwebsetup");

            if is_safe_patcher {
                out.safe_post_run.push(PostRunCommand { filename, parameters });
            }
        }
    }
}

/// Replays parsed Inno [Registry] keys into Windows so legacy games (Ubisoft/WB/EA) launch cleanly.
pub fn apply_registry_entries(entries: &[RegistryEntry], target_app_dir: &Path) -> usize {
    let app_str = target_app_dir.display().to_string();
    let mut applied = 0;

    for e in entries {
        let hive = match e.root.to_ascii_uppercase().as_str() {
            "HKLM" | "HKLM32" | "HKLM64" => "HKLM",
            "HKCU" | "HKCU32" | "HKCU64" => "HKCU",
            _ => continue,
        };
        let reg_type = match e.value_type.to_ascii_lowercase().as_str() {
            "dword" => "REG_DWORD",
            "expandsz" => "REG_EXPAND_SZ",
            _ => "REG_SZ",
        };
        let key_path = format!(r"{hive}\{}", e.subkey.replace("{app}", &app_str));
        let data = e.value_data.replace("{app}", &app_str);

        let mut cmd = Command::new("reg");
        cmd.args(["add", &key_path, "/t", reg_type, "/d", &data, "/f"]);
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
            applied += 1;
        }
    }
    applied
}
