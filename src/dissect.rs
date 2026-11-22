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

/// Unpacks setup.exe's embedded {tmp} plugins (unarc.dll, cls-srep, cls-lolz, xtool, arc.ini)
/// and parses install_script.iss for passwords, [Registry], [Icons], and safe [Run] tasks.
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

    let tmp_sub = work_dir.join("{tmp}");
    if tmp_sub.is_dir() {
        for entry in walkdir::WalkDir::new(&tmp_sub).into_iter().flatten() {
            if entry.file_type().is_file() {
                let src = entry.path();
                if let Some(name) = src.file_name() {
                    let _ = fs::copy(src, work_dir.join(name));
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

/// Creates Desktop `.lnk` shortcuts for parsed Inno `[Icons]` game executables.
pub fn create_desktop_shortcuts(icons: &[IconEntry], target_app_dir: &Path) -> usize {
    let app_str = target_app_dir.display().to_string();
    let mut created = 0usize;
    let mut seen_targets = std::collections::HashSet::new();

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
